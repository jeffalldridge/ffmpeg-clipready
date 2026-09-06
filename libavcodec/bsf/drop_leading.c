/*
 * drop_leading bitstream filter — ClipReady patch (LGPL v2.1+, same terms
 * as FFmpeg).
 *
 * After an input seek with stream copy, the first keyframe of an open-GOP
 * stream (HEVC CRA, MPEG-2/H.264 open GOP) is followed in decode order by
 * leading pictures that are displayed before it and reference the previous
 * GOP, which is not in the output. Apple's decoders refuse the whole first
 * GOP over them. Those packets are exactly the ones whose PTS is earlier
 * than the first keyframe's PTS, so this filter drops them and passes
 * everything else untouched. It is codec-agnostic and touches no bytes.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "libavutil/opt.h"
#include "bsf.h"
#include "bsf_internal.h"

typedef struct DropLeadingContext {
    const AVClass *class;
    int seen_key;
    int64_t key_pts;
    int64_t dropped;
} DropLeadingContext;

static int drop_leading_filter(AVBSFContext *ctx, AVPacket *pkt)
{
    DropLeadingContext *s = ctx->priv_data;
    int ret;

    for (;;) {
        ret = ff_bsf_get_packet_ref(ctx, pkt);
        if (ret < 0)
            return ret;

        if (!s->seen_key) {
            if (pkt->flags & AV_PKT_FLAG_KEY) {
                s->seen_key = 1;
                s->key_pts  = pkt->pts;
            }
            return 0;
        }

        if (s->key_pts != AV_NOPTS_VALUE && pkt->pts != AV_NOPTS_VALUE &&
            pkt->pts < s->key_pts) {
            s->dropped++;
            av_log(ctx, AV_LOG_VERBOSE,
                   "dropping leading picture pts %" PRId64 " before first keyframe pts %" PRId64 "\n",
                   pkt->pts, s->key_pts);
            av_packet_unref(pkt);
            continue;
        }
        return 0;
    }
}

static void drop_leading_close(AVBSFContext *ctx)
{
    DropLeadingContext *s = ctx->priv_data;
    if (s->dropped)
        av_log(ctx, AV_LOG_INFO, "dropped %" PRId64 " leading picture(s) of the first keyframe\n",
               s->dropped);
}

static const AVClass drop_leading_class = {
    .class_name = "drop_leading",
    .item_name  = av_default_item_name,
    .version    = LIBAVUTIL_VERSION_INT,
};

const FFBitStreamFilter ff_drop_leading_bsf = {
    .p.name         = "drop_leading",
    .p.priv_class   = &drop_leading_class,
    .priv_data_size = sizeof(DropLeadingContext),
    .filter         = drop_leading_filter,
    .close          = drop_leading_close,
};
