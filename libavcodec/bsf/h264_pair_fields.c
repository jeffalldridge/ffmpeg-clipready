/* ClipReady complementary-field sample repair. LGPL-2.1-or-later. */
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "bsf.h"
#include "bsf_internal.h"
#include "cbs.h"
#include "cbs_h264.h"
#include "h264.h"
#include "libavutil/refstruct.h"

typedef struct Picture {
    H264RawSliceHeader slice;
    H264RawSPS sps;
} Picture;

typedef struct PairContext {
    const AVClass *class;
    int verify_only;
    int report;
    int drop_incomplete_tail;
    CodedBitstreamContext *cbs;
    CodedBitstreamFragment fragment;
    AVPacket *pending;
    Picture first;
    H264RawSPS *sps[H264_MAX_SPS_COUNT];
    H264RawPPS *pps[H264_MAX_PPS_COUNT];
} PairContext;

/* Keep parameter-set state in NAL order. CBS has already read the whole
 * packet when our filter sees its units, so its final table cannot describe
 * an earlier slice when parameter sets occur between complementary fields. */
static void remember_parameter(PairContext *s, const CodedBitstreamUnit *unit)
{
    if (unit->type == H264_NAL_SPS) {
        const H264RawSPS *value = unit->content;
        av_refstruct_replace(&s->sps[value->seq_parameter_set_id], unit->content_ref);
    } else if (unit->type == H264_NAL_PPS) {
        const H264RawPPS *value = unit->content;
        av_refstruct_replace(&s->pps[value->pic_parameter_set_id], unit->content_ref);
    }
}

static int pair_init(AVBSFContext *ctx)
{
    PairContext *s = ctx->priv_data;
    int ret = ff_cbs_init(&s->cbs, AV_CODEC_ID_H264, ctx);
    if (s->report)
        av_log(ctx, AV_LOG_INFO, "CLIPREADY_H264_RATE=%d/%d\n", ctx->par_in->framerate.num, ctx->par_in->framerate.den);
    if (ret < 0) return ret;
    s->pending = av_packet_alloc();
    if (!s->pending) return AVERROR(ENOMEM);
    if (ctx->par_in->extradata_size) {
        ret = ff_cbs_read_extradata(s->cbs, &s->fragment, ctx->par_in);
        if (ret >= 0)
            for (int i = 0; i < s->fragment.nb_units; ++i) remember_parameter(s, &s->fragment.units[i]);
        ff_cbs_fragment_reset(&s->fragment);
    }
    return ret;
}

static int picture(PairContext *s, Picture *p, const H264RawSliceHeader *slice)
{
    const H264RawPPS *pps = s->pps[slice->pic_parameter_set_id];
    if (!pps || !s->sps[pps->seq_parameter_set_id]) return AVERROR_INVALIDDATA;
    p->slice = *slice;
    /* CBS allocates zero-initialized, pointer-free raw SPS structs. Snapshot
     * the value now: looking up the first PPS again after the next packet
     * would silently accept an intervening redefinition. PPS IDs may differ. */
    p->sps = *s->sps[pps->seq_parameter_set_id];
    return 0;
}

static int same_picture(const Picture *a, const Picture *b)
{
    const H264RawSliceHeader *x = &a->slice, *y = &b->slice;
    return x->frame_num == y->frame_num &&
           x->field_pic_flag == y->field_pic_flag &&
           x->bottom_field_flag == y->bottom_field_flag &&
           x->pic_parameter_set_id == y->pic_parameter_set_id &&
           x->nal_unit_header.nal_unit_type == y->nal_unit_header.nal_unit_type &&
           !!x->nal_unit_header.nal_ref_idc == !!y->nal_unit_header.nal_ref_idc &&
           x->idr_pic_id == y->idr_pic_id &&
           x->pic_order_cnt_lsb == y->pic_order_cnt_lsb &&
           x->delta_pic_order_cnt_bottom == y->delta_pic_order_cnt_bottom &&
           x->delta_pic_order_cnt[0] == y->delta_pic_order_cnt[0] &&
           x->delta_pic_order_cnt[1] == y->delta_pic_order_cnt[1] &&
           !memcmp(&a->sps, &b->sps, sizeof(a->sps));
}

static int complementary(const Picture *a, const Picture *b)
{
    const H264RawSliceHeader *x = &a->slice, *y = &b->slice;
    if (!x->field_pic_flag || !y->field_pic_flag ||
        x->frame_num != y->frame_num || x->bottom_field_flag == y->bottom_field_flag ||
        !!x->nal_unit_header.nal_ref_idc != !!y->nal_unit_header.nal_ref_idc ||
        memcmp(&a->sps, &b->sps, sizeof(a->sps))) return 0;
    /* An IDR first field may have a non-IDR complementary second field.
     * A new IDR after a non-IDR field cannot finish the pending picture. */
    if (y->nal_unit_header.nal_unit_type == H264_NAL_IDR_SLICE &&
        (x->nal_unit_header.nal_unit_type != H264_NAL_IDR_SLICE || x->idr_pic_id != y->idr_pic_id)) return 0;
    if (a->sps.pic_order_cnt_type == 0) {
        unsigned mask = (1U << (a->sps.log2_max_pic_order_cnt_lsb_minus4 + 4)) - 1;
        unsigned delta = (y->pic_order_cnt_lsb - x->pic_order_cnt_lsb) & mask;
        if (delta != 1 && delta != mask) return 0;
    } else if (a->sps.pic_order_cnt_type == 1) {
        /* No verified type-1 PAFF control yet. Refuse to infer a pairing. */
        return 0;
    }
    return 1;
}

static int compatible_side_data(const AVPacket *first, const AVPacket *second)
{
    for (int i = 0; i < second->side_data_elems; ++i) {
        size_t size = 0;
        const AVPacketSideData *side = &second->side_data[i];
        /* PES stream IDs describe the source transport, not the MOV picture.
         * They may occur only on the second field at a PES boundary. */
        if (side->type == AV_PKT_DATA_MPEGTS_STREAM_ID) continue;
        const uint8_t *data = av_packet_get_side_data(first, side->type, &size);
        if (!data || size != side->size || memcmp(data, side->data, size)) return 0;
    }
    return 1;
}

static int pair_filter(AVBSFContext *ctx, AVPacket *pkt)
{
    PairContext *s = ctx->priv_data;
    int ret;
    for (;;) {
        Picture first = {0}, last = {0}, next = {0};
        int pictures = 0;
        ret = ff_bsf_get_packet_ref(ctx, pkt);
        if (ret < 0) {
            if (ret == AVERROR_EOF && s->pending->size) {
                if (s->drop_incomplete_tail && !s->verify_only) {
                    av_log(ctx, AV_LOG_VERBOSE, "Trim ended between H.264 fields; omitted the incomplete final frame\n");
                    av_packet_unref(s->pending);
                    return AVERROR_EOF;
                }
                av_log(ctx, AV_LOG_ERROR, "Unpaired H.264 field at EOF\n");
                ret = AVERROR_INVALIDDATA;
                goto fail;
            }
            return ret;
        }
        if (pkt->flags & AV_PKT_FLAG_CORRUPT) { ret = AVERROR_INVALIDDATA; goto fail; }
        ret = ff_cbs_read_packet(s->cbs, &s->fragment, pkt);
        if (ret < 0) goto fail;
        for (int i = 0; i < s->fragment.nb_units; ++i) {
            CodedBitstreamUnit *unit = &s->fragment.units[i];
            remember_parameter(s, unit);
            if (unit->type != H264_NAL_SLICE && unit->type != H264_NAL_IDR_SLICE) continue;
            ret = picture(s, &next, &((H264RawSlice *)unit->content)->header);
            if (ret < 0) goto fail;
            if (!pictures) { first = last = next; pictures = 1; }
            else if (same_picture(&last, &next)) continue;
            else if (pictures == 1 && complementary(&first, &next)) { last = next; pictures = 2; }
            else { ret = AVERROR_INVALIDDATA; goto fail; }
        }
        ff_cbs_fragment_reset(&s->fragment);
        if (!pictures || !first.slice.field_pic_flag || pictures == 2) {
            if (s->pending->size || (!pictures && s->verify_only)) { ret = AVERROR_INVALIDDATA; goto fail; }
            return 0;
        }
        if (s->verify_only) {
            av_log(ctx, AV_LOG_ERROR, "Incomplete H.264 frame sample: one encoded field\n");
            ret = AVERROR_INVALIDDATA; goto fail;
        }
        if (!s->pending->size) {
            s->first = first;
            av_packet_move_ref(s->pending, pkt);
            continue;
        }
        if (!complementary(&s->first, &first) || !compatible_side_data(s->pending, pkt)) {
            ret = AVERROR_INVALIDDATA; goto fail;
        }
        if (pkt->dts == AV_NOPTS_VALUE || s->pending->dts == AV_NOPTS_VALUE || pkt->dts <= s->pending->dts ||
            (s->pending->dts < 0 && pkt->dts > INT64_MAX + s->pending->dts)) {
            ret = AVERROR_INVALIDDATA; goto fail;
        }
        int64_t delta = pkt->dts - s->pending->dts;
        if (delta > INT64_MAX / 2) { ret = AVERROR_INVALIDDATA; goto fail; }
        int old_size = s->pending->size;
        ret = av_grow_packet(s->pending, pkt->size);
        if (ret < 0) goto fail;
        memcpy(s->pending->data + old_size, pkt->data, pkt->size);
        s->pending->duration = 2 * delta;
        av_packet_unref(pkt);
        av_packet_move_ref(pkt, s->pending);
        return 0;
    }
fail:
    av_log(ctx, AV_LOG_ERROR, "Cannot form a verified complete H.264 frame sample\n");
    av_packet_unref(s->pending);
    av_packet_unref(pkt);
    ff_cbs_fragment_reset(&s->fragment);
    return ret;
}
static void pair_close(AVBSFContext *ctx) {
    PairContext *s = ctx->priv_data;
    av_packet_free(&s->pending);
    for (int i = 0; i < H264_MAX_SPS_COUNT; ++i) av_refstruct_unref(&s->sps[i]);
    for (int i = 0; i < H264_MAX_PPS_COUNT; ++i) av_refstruct_unref(&s->pps[i]);
    ff_cbs_fragment_free(&s->fragment);
    ff_cbs_close(&s->cbs);
}
static void pair_flush(AVBSFContext *ctx) {
    PairContext *s = ctx->priv_data;
    av_packet_unref(s->pending);
    ff_cbs_fragment_reset(&s->fragment);
}
static const AVOption options[] = {
    { "drop_incomplete_tail", "For explicit trims only, omit a final incomplete field pair", offsetof(PairContext, drop_incomplete_tail),
      AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, AV_OPT_FLAG_VIDEO_PARAM | AV_OPT_FLAG_BSF_PARAM },
    { "report", "Report the parsed coded-picture rate for preflight", offsetof(PairContext, report),
      AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, AV_OPT_FLAG_VIDEO_PARAM | AV_OPT_FLAG_BSF_PARAM },
    { "verify_only", "Reject unpaired field samples instead of combining packets", offsetof(PairContext, verify_only),
      AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, AV_OPT_FLAG_VIDEO_PARAM | AV_OPT_FLAG_BSF_PARAM },
    { NULL }
};
static const AVClass pair_class = {
    .class_name = "h264_pair_fields", .item_name = av_default_item_name,
    .option = options, .version = LIBAVUTIL_VERSION_INT,
};
static const enum AVCodecID codecs[] = { AV_CODEC_ID_H264, AV_CODEC_ID_NONE };
const FFBitStreamFilter ff_h264_pair_fields_bsf = {
    .p.name = "h264_pair_fields", .p.codec_ids = codecs, .p.priv_class = &pair_class,
    .priv_data_size = sizeof(PairContext), .init = pair_init,
    .filter = pair_filter, .close = pair_close, .flush = pair_flush,
};
