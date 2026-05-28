/* Copyright 2026. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * RTP (Real-time Transport Protocol) parser
 * RFC 3550 - RTP: A Transport Protocol for Real-Time Applications
 * RFC 3984 - RTP Payload Format for H.264 Video
 * RFC 3551 - RTP Profile for Audio and Video Conferences
 *
 * Features:
 * - RTP packet header parsing and validation
 * - Multi-SSRC stream reassembly per session
 * - H.264 depacketization (FU-A, STAP-A, Single NAL)
 * - Audio codec frame extraction (PCMU, PCMA, G722, Opus)
 * - FFmpeg-based decoding and container muxing (H264→MP4, PCMU→WAV, etc.)
 * - SDP-RTP bridge table for codec info propagation from SIP
 */
#include "arkime.h"
#include "rtp.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

extern ArkimeConfig_t config;

/******************************************************************************/
/* FFmpeg 头文件                                                               */
/******************************************************************************/
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libavutil/channel_layout.h>
#include <libswresample/swresample.h>

/******************************************************************************/
/* 本地字段 ID                                                                */
/******************************************************************************/
LOCAL int rtpSsrcField;
LOCAL int rtpPayloadTypeField;
LOCAL int rtpCodecField;
LOCAL int rtpMediaField;
LOCAL int rtpPacketsField;
LOCAL int rtpLostField;
LOCAL int rtpStreamsField;
LOCAL int rtpFilesField;

/******************************************************************************/
/* 桥接表 (rtp_bridge_add/lookup/init/exit) 已移到 capture/rtp_bridge.c        */
/* 编译入主 capture 二进制文件，所有 .so 解析器共享同一份数据。                  */
/******************************************************************************/

/* FFmpeg 辅助函数 — 编解码映射                                                */
/******************************************************************************/
int rtp_codec_to_avcodec_id(const char *codec)
{
    if (!codec) return AV_CODEC_ID_NONE;
    if (g_ascii_strcasecmp(codec, "PCMU") == 0)  return AV_CODEC_ID_PCM_MULAW;
    if (g_ascii_strcasecmp(codec, "PCMA") == 0)  return AV_CODEC_ID_PCM_ALAW;
    if (g_ascii_strcasecmp(codec, "G722") == 0)  return AV_CODEC_ID_ADPCM_G722;
    if (g_ascii_strcasecmp(codec, "G729") == 0)  return AV_CODEC_ID_G729;
    if (g_ascii_strcasecmp(codec, "OPUS") == 0)  return AV_CODEC_ID_OPUS;
    if (g_ascii_strcasecmp(codec, "H264") == 0)  return AV_CODEC_ID_H264;
    if (g_ascii_strcasecmp(codec, "VP8")  == 0)  return AV_CODEC_ID_VP8;
    if (g_ascii_strcasecmp(codec, "MP4A-LATM") == 0 ||
        g_ascii_strcasecmp(codec, "MPEG4-GENERIC") == 0) return AV_CODEC_ID_AAC;
    if (g_ascii_strcasecmp(codec, "TELEPHONE-EVENT") == 0) return AV_CODEC_ID_NONE;
    return AV_CODEC_ID_NONE;
}

int rtp_codec_clock_rate(const char *codec)
{
    if (!codec) return 8000;
    if (g_ascii_strcasecmp(codec, "H264") == 0 ||
        g_ascii_strcasecmp(codec, "H263") == 0 ||
        g_ascii_strcasecmp(codec, "MP4V-ES") == 0) return 90000;
    if (g_ascii_strcasecmp(codec, "OPUS") == 0) return 48000;
    if (g_ascii_strcasecmp(codec, "G722") == 0) return 8000;  /* G722 internally 16kHz but RTP clock is 8kHz */
    if (g_ascii_strcasecmp(codec, "PCMU") == 0 ||
        g_ascii_strcasecmp(codec, "PCMA") == 0) return 8000;
    return 8000; /* Default audio clock */
}

const char *rtp_codec_container_ext(const char *codec)
{
    if (!codec) return "raw";
    if (g_ascii_strcasecmp(codec, "H264") == 0)  return "mp4";
    if (g_ascii_strcasecmp(codec, "PCMU") == 0)  return "wav";
    if (g_ascii_strcasecmp(codec, "PCMA") == 0)  return "wav";
    if (g_ascii_strcasecmp(codec, "G722") == 0)  return "wav";
    if (g_ascii_strcasecmp(codec, "G729") == 0)  return "wav";
    if (g_ascii_strcasecmp(codec, "OPUS") == 0)  return "mp4";
    if (g_ascii_strcasecmp(codec, "VP8")  == 0)  return "ivf";
    return "raw";
}

/* 根据 RTP 静态载荷类型 (PT) 回退检测编解码器名称
 * 当 SIP SDP 桥接表查询失败时作为备用
 * 参见 RFC 3551 Section 6 */
LOCAL const char *rtp_static_codec_from_pt(int pt)
{
    switch (pt) {
    case 0:  return "PCMU";
    case 3:  return "GSM";
    case 4:  return "G723";
    case 5:  return "DVI4";
    case 6:  return "DVI4";
    case 7:  return "LPC";
    case 8:  return "PCMA";
    case 9:  return "G722";
    case 10: return "L16";
    case 11: return "L16";
    case 12: return "QCELP";
    case 13: return "CN";
    case 14: return "MPA";
    case 15: return "G728";
    case 16: return "DVI4";
    case 17: return "DVI4";
    case 18: return "G729";
    case 25: return "CELB";
    case 26: return "JPEG";
    case 28: return "BV16";
    case 31: return "H261";
    case 32: return "MPV";
    case 33: return "MP2T";
    case 34: return "H263";
    default: return NULL; /* 动态 PT (96-127) 需要 SDP rtpmap */
    }
}

const char *rtp_codec_media_type(const char *codec)
{
    if (!codec) return "unknown";
    if (g_ascii_strcasecmp(codec, "H264") == 0 ||
        g_ascii_strcasecmp(codec, "H263") == 0 ||
        g_ascii_strcasecmp(codec, "VP8")  == 0 ||
        g_ascii_strcasecmp(codec, "JPEG") == 0 ||
        g_ascii_strcasecmp(codec, "MP4V-ES") == 0) return "video";
    return "audio";
}

/******************************************************************************/
/* H.264 解包函数                                                              */
/* 输入: RTP 载荷 (不含 RTP 头部)                                              */
/* 输出: 追加 Annex B H.264 比特流到流缓冲区                                    */
/******************************************************************************/
LOCAL void rtp_depacket_h264(RtpStreamState_t *stream, const uint8_t *payload, int payloadLen)
{
    if (payloadLen <= 0)
        return;

    uint8_t nal_type = H264_NAL_TYPE(payload[0]);

    switch (nal_type) {
    case H264_NAL_FU_A: {
        /* FU-A 分片单元 (RFC 3984 Section 5.8) */
        if (payloadLen < 2)
            return;

        uint8_t fu_indicator = payload[0];
        uint8_t fu_header    = payload[1];
        uint8_t fu_start     = H264_FU_START(&fu_header);
        uint8_t fu_type      = H264_FU_TYPE(&fu_header);

        if (fu_start) {
            /* 第一个分片：重建 NAL 头部 (FU indicator 的 NRI + FU header 的 Type) */
            uint8_t nal_header = (fu_indicator & 0xE0) | fu_type;

            /* 提取 SPS/PPS 用于 MP4 头 */
            if (fu_type == H264_NAL_SPS && payloadLen > 2) {
                int sps_data_len = payloadLen - 2;
                if (sps_data_len > (int)sizeof(stream->sps))
                    sps_data_len = sizeof(stream->sps);
                memcpy(stream->sps, payload + 2, sps_data_len);
                stream->spsLen = sps_data_len;
            }
            if (fu_type == H264_NAL_PPS && payloadLen > 2) {
                int pps_data_len = payloadLen - 2;
                if (pps_data_len > (int)sizeof(stream->pps))
                    pps_data_len = sizeof(stream->pps);
                memcpy(stream->pps, payload + 2, pps_data_len);
                stream->ppsLen = pps_data_len;
            }

            /* 写入起始码 + NAL 头部 */
            int needed = stream->bufLen + ANNEXB_STARTCODE_LEN + 1 + (payloadLen - 2);
            if (needed > MAX_STREAM_BUFFER_SIZE) {
                stream->bufOverflow = 1;
                return;
            }
            if (needed > stream->bufAlloc) {
                stream->bufAlloc = needed + 65536;
                stream->buf = g_realloc(stream->buf, stream->bufAlloc);
            }
            memcpy(stream->buf + stream->bufLen, annexb_startcode, ANNEXB_STARTCODE_LEN);
            stream->bufLen += ANNEXB_STARTCODE_LEN;
            stream->buf[stream->bufLen++] = nal_header;
            memcpy(stream->buf + stream->bufLen, payload + 2, payloadLen - 2);
            stream->bufLen += (payloadLen - 2);
        } else {
            /* 后续分片：直接追加数据 (不含起始码和 NAL 头) */
            int data_len = payloadLen - 2;
            if (data_len <= 0) return;
            int needed = stream->bufLen + data_len;
            if (needed > MAX_STREAM_BUFFER_SIZE) {
                stream->bufOverflow = 1;
                return;
            }
            if (needed > stream->bufAlloc) {
                stream->bufAlloc = needed + 65536;
                stream->buf = g_realloc(stream->buf, stream->bufAlloc);
            }
            memcpy(stream->buf + stream->bufLen, payload + 2, data_len);
            stream->bufLen += data_len;
        }
        break;
    }

    case H264_NAL_STAP_A: {
        /* STAP-A 聚合单元 (RFC 3984 Section 5.7) */
        int offset = 1; /* 跳过 STAP-A NAL 头 */
        while (offset + 2 < payloadLen) {
            uint16_t nalu_size = ((uint16_t)payload[offset] << 8) | payload[offset + 1];
            offset += 2;

            if (offset + nalu_size > payloadLen)
                break;

            const uint8_t *nalu = payload + offset;

            /* 提取 SPS/PPS */
            uint8_t nalu_type = H264_NAL_TYPE(nalu[0]);
            if (nalu_type == H264_NAL_SPS && nalu_size > 0) {
                int sps_data_len = nalu_size;
                if (sps_data_len > (int)sizeof(stream->sps))
                    sps_data_len = sizeof(stream->sps);
                memcpy(stream->sps, nalu, sps_data_len);
                stream->spsLen = sps_data_len;
            }
            if (nalu_type == H264_NAL_PPS && nalu_size > 0) {
                int pps_data_len = nalu_size;
                if (pps_data_len > (int)sizeof(stream->pps))
                    pps_data_len = sizeof(stream->pps);
                memcpy(stream->pps, nalu, pps_data_len);
                stream->ppsLen = pps_data_len;
            }

            /* 写入起始码 + NAL 单元 */
            int needed = stream->bufLen + ANNEXB_STARTCODE_LEN + nalu_size;
            if (needed > MAX_STREAM_BUFFER_SIZE) {
                stream->bufOverflow = 1;
                return;
            }
            if (needed > stream->bufAlloc) {
                stream->bufAlloc = needed + 65536;
                stream->buf = g_realloc(stream->buf, stream->bufAlloc);
            }
            memcpy(stream->buf + stream->bufLen, annexb_startcode, ANNEXB_STARTCODE_LEN);
            stream->bufLen += ANNEXB_STARTCODE_LEN;
            memcpy(stream->buf + stream->bufLen, nalu, nalu_size);
            stream->bufLen += nalu_size;

            offset += nalu_size;
        }
        break;
    }

    default: {
        /* Single NAL Unit (类型 1-23) */
        /* 提取 SPS/PPS */
        if (nal_type == H264_NAL_SPS && payloadLen > 0) {
            int sps_data_len = payloadLen;
            if (sps_data_len > (int)sizeof(stream->sps))
                sps_data_len = sizeof(stream->sps);
            memcpy(stream->sps, payload, sps_data_len);
            stream->spsLen = sps_data_len;
        }
        if (nal_type == H264_NAL_PPS && payloadLen > 0) {
            int pps_data_len = payloadLen;
            if (pps_data_len > (int)sizeof(stream->pps))
                pps_data_len = sizeof(stream->pps);
            memcpy(stream->pps, payload, pps_data_len);
            stream->ppsLen = pps_data_len;
        }

        /* 写入起始码 + NAL 单元 */
        int needed = stream->bufLen + ANNEXB_STARTCODE_LEN + payloadLen;
        if (needed > MAX_STREAM_BUFFER_SIZE) {
            stream->bufOverflow = 1;
            return;
        }
        if (needed > stream->bufAlloc) {
            stream->bufAlloc = needed + 65536;
            stream->buf = g_realloc(stream->buf, stream->bufAlloc);
        }
        memcpy(stream->buf + stream->bufLen, annexb_startcode, ANNEXB_STARTCODE_LEN);
        stream->bufLen += ANNEXB_STARTCODE_LEN;
        memcpy(stream->buf + stream->bufLen, payload, payloadLen);
        stream->bufLen += payloadLen;
        break;
    }
    }
}

/******************************************************************************/
/* 音频帧直接追加                                                              */
/******************************************************************************/
LOCAL void rtp_append_audio_frame(RtpStreamState_t *stream, const uint8_t *payload, int payloadLen)
{
    if (payloadLen <= 0)
        return;

    int needed = stream->bufLen + payloadLen;
    if (needed > MAX_STREAM_BUFFER_SIZE) {
        stream->bufOverflow = 1;
        return;
    }
    if (needed > stream->bufAlloc) {
        stream->bufAlloc = needed + 65536;
        stream->buf = g_realloc(stream->buf, stream->bufAlloc);
    }
    memcpy(stream->buf + stream->bufLen, payload, payloadLen);
    stream->bufLen += payloadLen;

    /* 记录本包大小，用于后续按帧边界分割（Opus 等变长帧） */
    if (stream->packetSizesCount >= stream->packetSizesAlloc) {
        int newAlloc = stream->packetSizesAlloc ? stream->packetSizesAlloc * 2 : 64;
        stream->packetSizes = g_realloc(stream->packetSizes, newAlloc * sizeof(int));
        stream->packetSizesAlloc = newAlloc;
    }
    stream->packetSizes[stream->packetSizesCount] = payloadLen;
    stream->packetSizesCount++;
}

/******************************************************************************/
/* 全局 FFmpeg 初始化 (调用一次)                                                */
/******************************************************************************/
LOCAL int rtp_ffmpeg_initialized = 0;

LOCAL void rtp_ffmpeg_init(void)
{
    if (!rtp_ffmpeg_initialized) {
        /* 注册所有编解码器和格式 */
        avformat_network_init();
        rtp_ffmpeg_initialized = 1;
    }
}

/******************************************************************************/
/* FFmpeg: H.264 → MP4 容器封装 (codec copy / passthrough)                    */
/******************************************************************************/
LOCAL int rtp_mux_h264_to_mp4(const char *output_path,
                               const uint8_t *annex_b_data, int annex_b_len,
                               uint32_t UNUSED(first_ts), uint32_t UNUSED(last_ts), int clock_rate,
                               const uint8_t *sps, int sps_len,
                               const uint8_t *pps, int pps_len)
{
    AVFormatContext *fmt_ctx = NULL;
    AVStream *stream = NULL;
    int ret = -1;

    /* 分配输出上下文 — 使用 .mp4 扩展名自动选择 muxer */
    ret = avformat_alloc_output_context2(&fmt_ctx, NULL, NULL, output_path);
    if (ret < 0 || !fmt_ctx) {
        LOG("rtp: avformat_alloc_output_context2 failed for %s", output_path);
        return -1;
    }

    /* 创建视频流 */
    stream = avformat_new_stream(fmt_ctx, NULL);
    if (!stream) {
        LOG("rtp: avformat_new_stream failed");
        goto cleanup;
    }

    stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codecpar->codec_id   = AV_CODEC_ID_H264;
    stream->codecpar->codec_tag  = 0;
    stream->time_base = (AVRational){1, clock_rate > 0 ? clock_rate : 90000};

    /* 构建 extradata (AVCDecoderConfigurationRecord) */
    if (sps_len > 0 && pps_len > 0) {
        uint8_t extradata[256];
        int extradata_size = 0;

        extradata[extradata_size++] = 0x01;                                 /* version */
        extradata[extradata_size++] = sps[1];                               /* profile */
        extradata[extradata_size++] = sps[2];                               /* compatibility */
        extradata[extradata_size++] = sps[3];                               /* level */
        extradata[extradata_size++] = 0xFF;                                 /* 6+2 bits: NAL size = 4 bytes */
        extradata[extradata_size++] = 0xE1;                                 /* 3+5 bits: 1 SPS */

        /* SPS NAL unit */
        extradata[extradata_size++] = (sps_len >> 8) & 0xFF;
        extradata[extradata_size++] = sps_len & 0xFF;
        if (extradata_size + sps_len <= (int)sizeof(extradata)) {
            memcpy(extradata + extradata_size, sps, sps_len);
            extradata_size += sps_len;
        }

        /* PPS */
        extradata[extradata_size++] = 0x01;                                 /* 1 PPS */
        extradata[extradata_size++] = (pps_len >> 8) & 0xFF;
        extradata[extradata_size++] = pps_len & 0xFF;
        if (extradata_size + pps_len <= (int)sizeof(extradata)) {
            memcpy(extradata + extradata_size, pps, pps_len);
            extradata_size += pps_len;
        }

        stream->codecpar->extradata = av_mallocz(extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
        if (stream->codecpar->extradata) {
            memcpy(stream->codecpar->extradata, extradata, extradata_size);
            stream->codecpar->extradata_size = extradata_size;
        }
    }

    /* 打开输出文件 */
    ret = avio_open(&fmt_ctx->pb, output_path, AVIO_FLAG_WRITE);
    if (ret < 0) {
        LOG("rtp: avio_open failed for %s: %s", output_path, av_err2str(ret));
        goto cleanup;
    }

    /* 写头部 */
    ret = avformat_write_header(fmt_ctx, NULL);
    if (ret < 0) {
        LOG("rtp: avformat_write_header failed: %s", av_err2str(ret));
        goto cleanup_file;
    }

    /* 解析 Annex B 比特流，提取 NAL 单元作为 AVPacket 写入 */
    int offset = 0;
    uint32_t ts = first_ts;
    int frame_count = 0;

    while (offset < annex_b_len) {
        /* 查找下一个起始码 */
        int start_pos = -1;
        for (int i = offset; i < annex_b_len - 3; i++) {
            if (annex_b_data[i]   == 0x00 &&
                annex_b_data[i+1] == 0x00 &&
                annex_b_data[i+2] == 0x00 &&
                annex_b_data[i+3] == 0x01) {
                start_pos = i;
                break;
            }
            /* 3字节起始码 */
            if (annex_b_data[i]   == 0x00 &&
                annex_b_data[i+1] == 0x00 &&
                annex_b_data[i+2] == 0x01) {
                start_pos = i;
                break;
            }
        }

        if (start_pos < 0) {
            /* 没有更多起始码，写入剩余数据作为一个包 */
            if (offset < annex_b_len) {
                AVPacket *pkt = av_packet_alloc();
                if (pkt) {
                    pkt->data = (uint8_t *)annex_b_data + offset;
                    pkt->size = annex_b_len - offset;
                    pkt->stream_index = stream->index;
                    pkt->pts = pkt->dts = ts;
                    pkt->duration = 1;
                    av_interleaved_write_frame(fmt_ctx, pkt);
                    av_packet_free(&pkt);
                }
            }
            break;
        }

        /* 找到起始码之间的一个 NAL 单元 */
        if (frame_count > 0) {
            /* 从 previous offset 到 start_pos */
            int nal_len = start_pos - offset;
            if (nal_len > 0) {
                AVPacket *pkt = av_packet_alloc();
                if (pkt) {
                    pkt->data = (uint8_t *)annex_b_data + offset;
                    pkt->size = nal_len;
                    pkt->stream_index = stream->index;
                    pkt->pts = pkt->dts = ts;
                    pkt->duration = 0; /* will be fixed at end */

                    /* 检测是否为关键帧 (IDR) */
                    for (int i = 0; i < nal_len; i++) {
                        if (i + ANNEXB_STARTCODE_LEN <= nal_len &&
                            memcmp(annex_b_data + offset + i, annexb_startcode, ANNEXB_STARTCODE_LEN) == 0) {
                            int nal_offset = i + ANNEXB_STARTCODE_LEN;
                            if (nal_offset < nal_len) {
                                uint8_t nalu_type = H264_NAL_TYPE(annex_b_data[offset + nal_offset]);
                                if (nalu_type == H264_NAL_IDR) {
                                    pkt->flags |= AV_PKT_FLAG_KEY;
                                }
                            }
                            break;
                        }
                    }

                    av_interleaved_write_frame(fmt_ctx, pkt);
                    av_packet_free(&pkt);
                }

                /* 简单的时间戳推进 (每帧固定时长) */
                ts += (clock_rate > 0) ? (clock_rate / 30) : 3000;  /* ~30fps */
                frame_count++;
            }
        }

        offset = start_pos + ANNEXB_STARTCODE_LEN;
        frame_count++;
    }

    /* 修复最后一帧的时长 */
    /* (av_write_trailer 会处理) */

    /* 写尾部 */
    av_write_trailer(fmt_ctx);

    LOG("rtp: H.264→MP4 muxed %s: %d frames, %d bytes input", output_path, frame_count, annex_b_len);
    ret = 0;

cleanup_file:
    avio_closep(&fmt_ctx->pb);
cleanup:
    avformat_free_context(fmt_ctx);
    return ret;
}

/******************************************************************************/
/* FFmpeg: PCMU/PCMA → WAV 解码 + 封装                                        */
/******************************************************************************/
LOCAL int rtp_mux_audio_to_wav(const char *output_path,
                                 const char *codec_name,
                                 const uint8_t *audio_data, int audio_len,
                                 uint32_t UNUSED(first_ts), uint32_t UNUSED(last_ts), int clock_rate)
{
    int ret = -1;
    enum AVCodecID codec_id = AV_CODEC_ID_NONE;
    int sample_rate = clock_rate > 0 ? clock_rate : 8000;

    if (g_ascii_strcasecmp(codec_name, "PCMU") == 0) {
        codec_id = AV_CODEC_ID_PCM_MULAW;
    } else if (g_ascii_strcasecmp(codec_name, "PCMA") == 0) {
        codec_id = AV_CODEC_ID_PCM_ALAW;
    } else if (g_ascii_strcasecmp(codec_name, "G722") == 0) {
        codec_id = AV_CODEC_ID_ADPCM_G722;
        sample_rate = 16000; /* G722 内部为 16kHz */
    } else if (g_ascii_strcasecmp(codec_name, "G729") == 0) {
        codec_id = AV_CODEC_ID_G729;
        sample_rate = 8000;
    } else {
        LOG("rtp: unsupported audio codec for WAV: %s", codec_name);
        return -1;
    }

    const AVCodec *decoder = avcodec_find_decoder(codec_id);
    if (!decoder) {
        LOG("rtp: decoder not found for codec %s", codec_name);
        return -1;
    }

    AVCodecContext *dec_ctx = avcodec_alloc_context3(decoder);
    if (!dec_ctx) {
        LOG("rtp: avcodec_alloc_context3 failed");
        return -1;
    }

    dec_ctx->sample_rate = sample_rate;
    dec_ctx->ch_layout   = (AVChannelLayout)AV_CHANNEL_LAYOUT_MONO;

    if (codec_id == AV_CODEC_ID_PCM_MULAW || codec_id == AV_CODEC_ID_PCM_ALAW) {
        dec_ctx->sample_fmt = AV_SAMPLE_FMT_S16;
    }

    ret = avcodec_open2(dec_ctx, decoder, NULL);
    if (ret < 0) {
        LOG("rtp: avcodec_open2 failed for %s: %s", codec_name, av_err2str(ret));
        goto cleanup_decoder;
    }

    /* 分配输出格式上下文 — WAV muxer */
    AVFormatContext *fmt_ctx = NULL;
    ret = avformat_alloc_output_context2(&fmt_ctx, NULL, "wav", output_path);
    if (ret < 0 || !fmt_ctx) {
        LOG("rtp: avformat_alloc_output_context2 (wav) failed for %s", codec_name);
        goto cleanup_decoder;
    }

    /* 创建音频流 (PCM S16LE) */
    AVStream *out_stream = avformat_new_stream(fmt_ctx, NULL);
    if (!out_stream) {
        LOG("rtp: avformat_new_stream failed for WAV output");
        goto cleanup_format;
    }

    out_stream->codecpar->codec_type  = AVMEDIA_TYPE_AUDIO;
    out_stream->codecpar->codec_id    = AV_CODEC_ID_PCM_S16LE;
    out_stream->codecpar->sample_rate = sample_rate;
    out_stream->codecpar->ch_layout   = (AVChannelLayout)AV_CHANNEL_LAYOUT_MONO;
    out_stream->codecpar->bits_per_coded_sample = 16;
    out_stream->time_base = (AVRational){1, sample_rate};

    /* 打开输出文件 */
    ret = avio_open(&fmt_ctx->pb, output_path, AVIO_FLAG_WRITE);
    if (ret < 0) {
        LOG("rtp: avio_open failed for %s: %s", output_path, av_err2str(ret));
        goto cleanup_format;
    }

    /* 写 WAV 头 */
    ret = avformat_write_header(fmt_ctx, NULL);
    if (ret < 0) {
        LOG("rtp: avformat_write_header (wav) failed: %s", av_err2str(ret));
        goto cleanup_file;
    }

    /* 逐帧解码音频并写入 WAV */
    AVPacket *in_pkt = av_packet_alloc();
    AVFrame  *frame  = av_frame_alloc();

    if (!in_pkt || !frame) {
        LOG("rtp: av_packet_alloc or av_frame_alloc failed");
        av_packet_free(&in_pkt);
        av_frame_free(&frame);
        goto cleanup_file;
    }

    int offset = 0;
    int frame_size;
    if (codec_id == AV_CODEC_ID_PCM_MULAW || codec_id == AV_CODEC_ID_PCM_ALAW) {
        frame_size = 160; /* 20ms @ 8kHz */
    } else if (codec_id == AV_CODEC_ID_G729) {
        frame_size = 10;  /* 10ms @ 8kbps — 每帧 10 字节 */
    } else {
        frame_size = 320; /* G722: 20ms @ 16kHz */
    }
    int pts_samples = 0;

    while (offset + frame_size <= audio_len) {
        /* 准备输入包 */
        in_pkt->data = (uint8_t *)audio_data + offset;
        in_pkt->size = frame_size;
        in_pkt->pts  = pts_samples;
        in_pkt->dts  = pts_samples;
        in_pkt->duration = frame_size;
        in_pkt->stream_index = out_stream->index;

        /* 发送给解码器 */
        ret = avcodec_send_packet(dec_ctx, in_pkt);
        if (ret < 0) {
            /* 解码错误 — 跳过本帧 */
            offset += frame_size;
            pts_samples += frame_size;
            continue;
        }

        /* 接收解码帧 */
        ret = avcodec_receive_frame(dec_ctx, frame);
        if (ret == 0) {
            /* 创建 PCM 输出包 */
            AVPacket *out_pkt = av_packet_alloc();
            if (out_pkt) {
                int pcm_size = frame->nb_samples * 2; /* S16LE mono = 2 bytes/sample */
                out_pkt->data = frame->data[0];
                out_pkt->size = pcm_size;
                out_pkt->stream_index = out_stream->index;
                out_pkt->pts = pts_samples;
                out_pkt->dts = pts_samples;
                out_pkt->duration = frame->nb_samples;

                av_interleaved_write_frame(fmt_ctx, out_pkt);
                av_packet_free(&out_pkt);
            }
        }

        offset += frame_size;
        pts_samples += (frame_size / (2)) * 1; /* Approximate */
        /* Actually for PCMU/PCMA: each byte = 1 sample, so frame_size = samples */
        pts_samples = offset; /* For 8kHz mono: 1 byte = 1 sample */
        av_frame_unref(frame);
    }

    /* 冲刷解码器 */
    avcodec_send_packet(dec_ctx, NULL);
    while (avcodec_receive_frame(dec_ctx, frame) == 0) {
        AVPacket *out_pkt = av_packet_alloc();
        if (out_pkt) {
            out_pkt->data = frame->data[0];
            out_pkt->size = frame->nb_samples * 2;
            out_pkt->stream_index = out_stream->index;
            out_pkt->pts = pts_samples;
            out_pkt->dts = pts_samples;
            out_pkt->duration = frame->nb_samples;
            av_interleaved_write_frame(fmt_ctx, out_pkt);
            av_packet_free(&out_pkt);
        }
        av_frame_unref(frame);
    }

    av_packet_free(&in_pkt);
    av_frame_free(&frame);

    /* 写 WAV 尾部 */
    av_write_trailer(fmt_ctx);

    LOG("rtp: audio→WAV decoded %s: %d bytes input", output_path, audio_len);
    ret = 0;

cleanup_file:
    avio_closep(&fmt_ctx->pb);
cleanup_format:
    avformat_free_context(fmt_ctx);
cleanup_decoder:
    avcodec_free_context(&dec_ctx);
    return ret;
}

/******************************************************************************/
/* FFmpeg: Opus → MP4 容器封装 (codec copy)                                    */
/******************************************************************************/
LOCAL int rtp_mux_opus_to_mp4(const char *output_path,
                               const uint8_t *opus_data, int opus_len,
                               uint32_t UNUSED(first_ts), uint32_t UNUSED(last_ts), int clock_rate,
                               const int *packetSizes, int packetCount)
{
    AVFormatContext *fmt_ctx = NULL;
    int ret = -1;

    ret = avformat_alloc_output_context2(&fmt_ctx, NULL, "mp4", output_path);
    if (ret < 0 || !fmt_ctx) {
        LOG("rtp: avformat_alloc_output_context2 (mp4) failed");
        return -1;
    }

    AVStream *stream = avformat_new_stream(fmt_ctx, NULL);
    if (!stream) {
        LOG("rtp: avformat_new_stream failed for OGG output");
        goto cleanup;
    }

    stream->codecpar->codec_type  = AVMEDIA_TYPE_AUDIO;
    stream->codecpar->codec_id    = AV_CODEC_ID_OPUS;
    stream->codecpar->sample_rate = 48000; /* Opus 固定 48kHz */
    stream->codecpar->ch_layout   = (AVChannelLayout)AV_CHANNEL_LAYOUT_MONO;
    stream->codecpar->codec_tag   = 0;
    stream->time_base = (AVRational){1, 48000};

    /* 设置 Opus 头部 extradata */
    uint8_t opus_head[19] = {
        'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',                         /* 魔数 */
        0x01,                                                             /* 版本 */
        0x01,                                                             /* 声道数 */
        0x00, 0x0F,                                                       /* 预跳过 (3840 samples) */
        0x00, 0x00, 0x00, 0x00,                                           /* 输入采样率 (48000) */
        0x00, 0x00,                                                       /* 输出增益 (0) */
        0x00                                                              /* 声道映射家族 (0=mono) */
    };
    /* 设置输入采样率 */
    int sr = clock_rate > 0 ? clock_rate : 48000;
    opus_head[12] = (sr >> 8) & 0xFF;
    opus_head[13] = sr & 0xFF;
    /* 修正预跳过 */
    int preskip = 3840; /* 48kHz * 80ms */
    opus_head[10] = (preskip >> 8) & 0xFF;
    opus_head[11] = preskip & 0xFF;

    stream->codecpar->extradata = av_mallocz(sizeof(opus_head) + AV_INPUT_BUFFER_PADDING_SIZE);
    if (stream->codecpar->extradata) {
        memcpy(stream->codecpar->extradata, opus_head, sizeof(opus_head));
        stream->codecpar->extradata_size = sizeof(opus_head);
    }

    ret = avio_open(&fmt_ctx->pb, output_path, AVIO_FLAG_WRITE);
    if (ret < 0) {
        LOG("rtp: avio_open failed for %s: %s", output_path, av_err2str(ret));
        goto cleanup;
    }

    ret = avformat_write_header(fmt_ctx, NULL);
    if (ret < 0) {
        LOG("rtp: avformat_write_header (ogg/opus) failed: %s", av_err2str(ret));
        goto cleanup_file;
    }

    /* 写入 Opus 包 — 使用存储的 RTP 包边界而非固定分块 */
    int offset = 0;
    int pkt_count = 0;
    int pkt_idx = 0;

    while (offset < opus_len && pkt_idx < packetCount) {
        int pkt_size = packetSizes[pkt_idx];
        /* 安全检查：不应超出缓冲区 */
        if (offset + pkt_size > opus_len) {
            LOG("rtp: Opus packet[%d] size %d exceeds remaining data %d, truncating",
                pkt_idx, pkt_size, opus_len - offset);
            pkt_size = opus_len - offset;
        }

        AVPacket *pkt = av_packet_alloc();
        if (!pkt) break;

        /* 必须分配引用计数的 buffer，否则 av_interleaved_write_frame 内部
         * 缓存非 refcounted 数据指针会导致后续 use-after-free */
        if (av_new_packet(pkt, pkt_size) < 0) {
            av_packet_free(&pkt);
            break;
        }
        memcpy(pkt->data, opus_data + offset, pkt_size);
        pkt->stream_index = stream->index;
        /* 每个 RTP 包 = 20ms Opus 帧 @ 48kHz = 960 samples */
        pkt->pts = pkt->dts = pkt_count * 960;
        pkt->duration = 960;
        pkt->flags = AV_PKT_FLAG_KEY;

        av_interleaved_write_frame(fmt_ctx, pkt);
        av_packet_free(&pkt);

        offset += pkt_size;
        pkt_count++;
        pkt_idx++;
    }

    av_write_trailer(fmt_ctx);
    LOG("rtp: Opus→MP4 muxed %s: %d packets, %d bytes", output_path, pkt_count, opus_len);
    ret = 0;

cleanup_file:
    avio_closep(&fmt_ctx->pb);
cleanup:
    avformat_free_context(fmt_ctx);
    return ret;
}

/******************************************************************************/
/* 通用 FFmpeg 保存入口                                                        */
/******************************************************************************/
LOCAL int rtp_save_stream_to_file(const char *output_path,
                                    RtpStreamState_t *stream,
                                    const char *codec)
{
    int clock_rate = stream->clockRate > 0 ? stream->clockRate : rtp_codec_clock_rate(codec);

    LOG("rtp: saving stream ssrc=0x%08x codec=%s to %s "
        "(bufLen=%d clockRate=%d)",
        stream->ssrc, codec ? codec : "(null)", output_path,
        stream->bufLen, clock_rate);

    if (!codec || codec[0] == '\0') {
        LOG("rtp: unknown codec for stream ssrc=0x%08x, skipping", stream->ssrc);
        return -1;
    }

    if (stream->bufLen <= 0) {
        LOG("rtp: no data in stream");
        return -1;
    }

    if (g_ascii_strcasecmp(codec, "H264") == 0) {
        return rtp_mux_h264_to_mp4(output_path,
                                    stream->buf, stream->bufLen,
                                    stream->firstTimestamp,
                                    stream->lastTimestamp,
                                    stream->clockRate,
                                    stream->sps, stream->spsLen,
                                    stream->pps, stream->ppsLen);
    } else if (g_ascii_strcasecmp(codec, "PCMU") == 0 ||
               g_ascii_strcasecmp(codec, "PCMA") == 0 ||
               g_ascii_strcasecmp(codec, "G722") == 0 ||
               g_ascii_strcasecmp(codec, "G729") == 0) {
        return rtp_mux_audio_to_wav(output_path, codec,
                                     stream->buf, stream->bufLen,
                                     stream->firstTimestamp,
                                     stream->lastTimestamp,
                                     stream->clockRate);
    } else if (g_ascii_strcasecmp(codec, "OPUS") == 0) {
        return rtp_mux_opus_to_mp4(output_path,
                                    stream->buf, stream->bufLen,
                                    stream->firstTimestamp,
                                    stream->lastTimestamp,
                                    stream->clockRate,
                                    stream->packetSizes, stream->packetSizesCount);
    } else {
        /* 未支持的编码：写原始数据文件 */
        LOG("rtp: unknown codec %s, writing raw data", codec);
        FILE *f = fopen(output_path, "wb");
        if (!f) {
            LOG("rtp: could not open %s: %s", output_path, strerror(errno));
            return -1;
        }
        int written = fwrite(stream->buf, 1, stream->bufLen, f);
        fclose(f);
        return (written == stream->bufLen) ? 0 : -1;
    }
}

/******************************************************************************/
/* 获取 SSRC 流的文件名                                                        */
/******************************************************************************/
LOCAL char *rtp_stream_filename(uint32_t ssrc, const char *codec, const char *ext)
{
    char ssrc_str[16];
    snprintf(ssrc_str, sizeof(ssrc_str), "ssrc_%08x", ssrc);
    return g_strdup_printf("%s_%s.%s", ssrc_str, codec, ext);
}

/******************************************************************************/
/* rtp_save — parserSaveFunc 回调                                             */
/* 在会话关闭时调用，对所有 SSRC 流执行 FFmpeg 处理并保存文件                      */
/******************************************************************************/
LOCAL void rtp_save(ArkimeSession_t *session, void *uw, int final)
{
    RtpSessionData_t *rtpData = (RtpSessionData_t *)uw;
    if (!rtpData)
        return;

    /* 只在最终保存时写文件，mid-save (final==FALSE) 时跳过 */
    if (!final)
        return;

    LOG("rtp: rtp_save called for session %s, streamCount=%d",
        rtpData->sessionId, rtpData->streamCount);

    /* 确保 FFmpeg 已初始化 */
    rtp_ffmpeg_init();

    int saved_count = 0;
    /* 使用堆分配的 file_paths 缓冲区，避免栈数组被 hash 表 g_free 的危险 */
    char *file_paths = g_malloc0(256);
    int file_paths_size = 256;
    int path_offset = 0;

    for (int i = 0; i < rtpData->streamCount; i++) {
        RtpStreamState_t *stream = &rtpData->streams[i];

        if (stream->bufLen <= 0 || stream->bufOverflow)
            continue;

        /* 确定输出容器格式 */
        const char *codec = stream->codec[0] ? stream->codec : rtpData->codecInfo.codec;
        const char *ext   = rtp_codec_container_ext(codec);

        /* 如果编解码器未知，跳过保存（防止生成 ssrc_XXXX_.raw 文件名导致 segfault） */
        if (codec[0] == '\0') {
            LOG("rtp: stream[%d] ssrc=0x%08x has unknown codec, skipping",
                i, stream->ssrc);
            continue;
        }

        LOG("rtp: stream[%d] ssrc=0x%08x codec='%s' bufLen=%d ext='%s'",
            i, stream->ssrc, codec, stream->bufLen, ext);

        /* 生成文件名 */
        char *filename = rtp_stream_filename(stream->ssrc, codec, ext);
        LOG("rtp: generated filename='%s'", filename ? filename : "(null)");

        if (!filename) {
            continue;
        }

        /* 构造完整文件系统路径 */
        const char *save_dir = config.contentSavePath ? config.contentSavePath : "/tmp";
        char full_path[1024];
        int path_len = snprintf(full_path, sizeof(full_path), "%s/%s",
                                save_dir, filename);
        if (path_len >= (int)sizeof(full_path)) {
            LOG("rtp: path too long for %s/%s", save_dir, filename);
            g_free(filename);
            continue;
        }

        char *es_name = NULL;
        if (!config.dryRun) {
            /* 注册文件到 Elasticsearch（Arkime 文件管理系统） */
            uint32_t file_id = 0;
            struct timeval tv = {0, 0};
            LOG("rtp: calling arkime_db_create_file_full with filename='%s'", filename);
            es_name = arkime_db_create_file_full(&tv, filename, 0, 0, &file_id, NULL);
            LOG("rtp: es_name=%s file_id=%u", es_name ? es_name : "null", file_id);

            if (!es_name) {
                LOG("rtp: arkime_db_create_file_full failed for %s", filename);
                g_free(filename);
                continue;
            }
        } else {
            /* dryrun 模式下跳过 ES 注册，直接保存到磁盘 */
            LOG("rtp: dryrun mode, skipping ES registration, saving directly to %s", full_path);
            es_name = filename; /* 在 dryrun 模式下，直接用原始文件名 */
        }

        LOG("rtp: saving to full_path=%s", full_path);

        /* 执行 FFmpeg 解码/封装 */
        int ret = rtp_save_stream_to_file(full_path, stream, codec);
        LOG("rtp: rtp_save_stream_to_file returned %d", ret);
        if (ret == 0) {
            saved_count++;
            /* 记录文件路径到会话字段 */
            if (path_offset < file_paths_size - 64) {
                if (path_offset > 0) {
                    file_paths[path_offset++] = ',';
                }
                int name_len = strlen(filename);
                if (path_offset + name_len < file_paths_size) {
                    memcpy(file_paths + path_offset, filename, name_len);
                    path_offset += name_len;
                    file_paths[path_offset] = '\0';
                }
            }
        } else {
            LOG("rtp: failed to save stream to %s", full_path);
        }

        /* 在非 dryrun 模式下，es_name 是 arkime_db_create_file_full 内部
         * g_regex_replace_literal 的新分配，需单独释放。
         * 在 dryrun 模式下，es_name == filename，只需释放 filename。
         * full_path 是栈数组，无需释放。 */
        if (!config.dryRun && es_name) {
            g_free(es_name);
        }
        g_free(filename);
    }

    /* 添加 RTP 文件路径字段 */
    if (saved_count > 0) {
        arkime_field_string_add(rtpFilesField, session, file_paths, strlen(file_paths), TRUE);
        arkime_session_add_tag(session, "rtp:has-media");
    }

    g_free(file_paths);

    LOG("rtp: saved %d/%d streams for session %s",
        saved_count, rtpData->streamCount, rtpData->sessionId);
}

/******************************************************************************/
/* rtp_free — parserFreeFunc 回调                                             */
/******************************************************************************/
LOCAL void rtp_free(ArkimeSession_t *UNUSED(session), void *uw)
{
    RtpSessionData_t *rtpData = uw;
    if (!rtpData)
        return;

    /* 从 RTP 会话查找表中注销 */
    if (rtpData->sessionId[0]) {
        char ip[INET6_ADDRSTRLEN];
        unsigned int port;
        if (sscanf(rtpData->sessionId, "%63[^:]:%u", ip, &port) == 2) {
            rtp_session_unregister(ip, (uint16_t)port);
        }
    }

    for (int i = 0; i < rtpData->streamCount; i++) {
        if (rtpData->streams[i].buf) {
            g_free(rtpData->streams[i].buf);
            rtpData->streams[i].buf = NULL;
        }
        if (rtpData->streams[i].packetSizes) {
            g_free(rtpData->streams[i].packetSizes);
            rtpData->streams[i].packetSizes = NULL;
        }
    }

    g_free(rtpData);
}

/******************************************************************************/
/* 查找或创建 SSRC 流                                                         */
/******************************************************************************/
LOCAL RtpStreamState_t *rtp_find_or_create_stream(RtpSessionData_t *rtpData, uint32_t ssrc)
{
    /* 查找已有流 */
    for (int i = 0; i < rtpData->streamCount; i++) {
        if (rtpData->streams[i].ssrc == ssrc)
            return &rtpData->streams[i];
    }

    /* 创建新流 */
    if (rtpData->streamCount >= MAX_SSRC_PER_SESSION)
        return NULL;

    RtpStreamState_t *stream = &rtpData->streams[rtpData->streamCount];
    memset(stream, 0, sizeof(RtpStreamState_t));
    stream->ssrc = ssrc;

    /* 继承会话级编解码信息 */
    if (rtpData->hasCodecInfo) {
        memcpy(stream->mediaType, rtpData->codecInfo.mediaType, sizeof(stream->mediaType));
        memcpy(stream->codec, rtpData->codecInfo.codec, sizeof(stream->codec));
        stream->clockRate = rtp_codec_clock_rate(rtpData->codecInfo.codec);
    }

    rtpData->streamCount++;
    return stream;
}

/******************************************************************************/
/* rtp_parser — 每个 UDP RTP 包调用                                            */
/******************************************************************************/
LOCAL int rtp_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int len, int UNUSED(which))
{
    RtpSessionData_t *rtpData = uw;
    if (!rtpData)
        return 0;

    /* 1. 基本校验 */
    if (len < 12)
        return 0;
    if (RTP_VER(data) != 2)
        return 0;

    /* 2. 解析 RTP 头部 */
    int cc             = RTP_CC(data);
    int extension      = RTP_EXTENSION(data);
    int padding        = RTP_PADDING(data);
    int payload_type   = RTP_PT(data);
    uint16_t seq       = RTP_SEQ(data);
    uint32_t timestamp = RTP_TS(data);
    uint32_t ssrc      = RTP_SSRC(data);

    /* 3. 计算头部长度 */
    int header_len = 12 + cc * 4;
    if (extension) {
        if (len < header_len + 4)
            return 0;
        uint16_t ext_len = ntohs(*(uint16_t *)(data + header_len + 2));
        header_len += 4 + ext_len * 4;
    }

    /* 4. 跳过 padding */
    int payload_len = len - header_len;
    if (padding && payload_len > 0) {
        uint8_t pad_count = data[len - 1];
        if (pad_count > 0 && pad_count <= payload_len) {
            payload_len -= pad_count;
        }
    }

    if (payload_len <= 0)
        return 0;

    const uint8_t *payload = data + header_len;

    /* 5. 查找/创建 SSRC 流 */
    RtpStreamState_t *stream = rtp_find_or_create_stream(rtpData, ssrc);
    if (!stream)
        return 0;

    /* 6. 更新流信息 */
    stream->payloadType = payload_type;
    if (!stream->gotFirst) {
        stream->gotFirst = 1;
        stream->lastSeq = seq;
        stream->firstTimestamp = timestamp;
        stream->lastTimestamp = timestamp;
        stream->hasTimestamps = 1;

        /* 首次收到包时查询桥接表 */
        if (!rtpData->hasCodecInfo) {
            /* 从 session 获取 IP:port 构造 key */
            char ip_str[64];
            /* Session 中 port1=src, port2=dst, addr1=src, addr2=dst (主机字节序!) */
            /* 注意：session->port1/port2 已在 udp.c 中经过 ntohs() 转换为主机字节序 */
            /* 此处不能再调用 ntohs()，否则端口值会被破坏 */
            /* addr2 是 struct in6_addr，IPv4 地址需要通过 ARKIME_V6_TO_V4 宏提取 */
            /* 使用 arkime_ip4tostr() 将 uint32_t IP 转换为点分十进制字符串 */
            /* 尝试用目标地址+端口查询（最常见的情况：RTP 发往 SIP 协商的目标） */
            uint16_t dst_port = session->port2;

            if (!session->v6) {
                arkime_ip4tostr(ARKIME_V6_TO_V4(session->addr2), ip_str, sizeof(ip_str));
            } else {
                inet_ntop(AF_INET6, &session->addr2, ip_str, sizeof(ip_str));
            }

            if (rtp_bridge_lookup(ip_str, dst_port, &rtpData->codecInfo)) {
                rtpData->hasCodecInfo = 1;
                memcpy(stream->mediaType, rtpData->codecInfo.mediaType, sizeof(stream->mediaType));
                memcpy(stream->codec, rtpData->codecInfo.codec, sizeof(stream->codec));
                stream->clockRate = rtp_codec_clock_rate(rtpData->codecInfo.codec);
                LOG("rtp: SDP bridge lookup OK: %s:%u codec=%s media=%s",
                    ip_str, dst_port, stream->codec, stream->mediaType);
            } else {
                /* 尝试源地址+端口 */
                uint16_t src_port = session->port1;
                if (!session->v6) {
                    arkime_ip4tostr(ARKIME_V6_TO_V4(session->addr1), ip_str, sizeof(ip_str));
                } else {
                    inet_ntop(AF_INET6, &session->addr1, ip_str, sizeof(ip_str));
                }
                if (rtp_bridge_lookup(ip_str, src_port, &rtpData->codecInfo)) {
                    rtpData->hasCodecInfo = 1;
                    memcpy(stream->mediaType, rtpData->codecInfo.mediaType, sizeof(stream->mediaType));
                    memcpy(stream->codec, rtpData->codecInfo.codec, sizeof(stream->codec));
                    stream->clockRate = rtp_codec_clock_rate(rtpData->codecInfo.codec);
                    LOG("rtp: SDP bridge lookup OK (src): %s:%u codec=%s media=%s",
                        ip_str, src_port, stream->codec, stream->mediaType);
                }
            }

            /* 桥接表查询失败时，尝试用 RTP 载荷类型 (PT) 静态回退 */
            if (!rtpData->hasCodecInfo) {
                const char *pt_codec = rtp_static_codec_from_pt(payload_type);
                if (pt_codec) {
                    g_strlcpy(stream->codec, pt_codec, sizeof(stream->codec));
                    stream->clockRate = rtp_codec_clock_rate(pt_codec);
                    LOG("rtp: PT static fallback: PT=%d codec=%s clockRate=%d",
                        payload_type, pt_codec, stream->clockRate);
                    LOG("rtp: SDP bridge lookup MISSED for %s:%u, "
                        "using PT=%d fallback codec=%s",
                        ip_str, dst_port, payload_type, pt_codec);
                }
            }
        }
    } else {
        stream->lastTimestamp = timestamp;
    }

    /* 7. 丢包检测 */
    stream->packetCount++;
    if (stream->gotFirst) {
        int16_t diff = (int16_t)(seq - stream->lastSeq);
        if (diff > 1) {
            stream->lostCount += (diff - 1);
        }
        stream->lastSeq = seq;
    }

    /* 8. 根据编解码类型处理载荷 */
    const char *codec = stream->codec[0] ? stream->codec : rtpData->codecInfo.codec;

    if (g_ascii_strcasecmp(codec, "H264") == 0) {
        rtp_depacket_h264(stream, payload, payload_len);
    } else {
        /* 默认：直接追加为原始帧 (音频等) */
        rtp_append_audio_frame(stream, payload, payload_len);
    }

    /* 9. 添加会话字段（仅首次）*/
    if (stream->packetCount == 1) {
        /* 这些字段只添加一次 */
        char ssrc_str[16];
        snprintf(ssrc_str, sizeof(ssrc_str), "%u", ssrc);
        arkime_field_string_add(rtpSsrcField, session, ssrc_str, strlen(ssrc_str), TRUE);

        char pt_str[8];
        snprintf(pt_str, sizeof(pt_str), "%d", payload_type);
        arkime_field_string_add(rtpPayloadTypeField, session, pt_str, strlen(pt_str), TRUE);

        if (codec[0]) {
            arkime_field_string_add(rtpCodecField, session, codec, strlen(codec), TRUE);
        }

        if (stream->mediaType[0]) {
            arkime_field_string_add(rtpMediaField, session, stream->mediaType,
                                     strlen(stream->mediaType), TRUE);
            /* 添加标签 */
            char tag[32];
            snprintf(tag, sizeof(tag), "rtp:%s", stream->mediaType);
            arkime_session_add_tag(session, tag);
        }

        /* 添加编解码标签 */
        if (codec[0]) {
            char tag[32];
            snprintf(tag, sizeof(tag), "rtp:%s", codec);
            arkime_session_add_tag(session, tag);
        }
    }

    return 0;
}

/******************************************************************************/
/* rtp_classify — 分类函数，检测 RTP 包头并注册解析器                           */
/******************************************************************************/
LOCAL void rtp_classify(ArkimeSession_t *session, const uint8_t *data, int len, int UNUSED(which), void *UNUSED(uw))
{
    if (arkime_session_has_protocol(session, "rtp"))
        return;

    /* 基本 RTP 验证 */
    if (len < 12)
        return;

    /* RTP version must be 2 */
    if ((data[0] >> 6) != 2)
        return;

    /* PT must not be in RTCP range 64-95 */
    int pt = data[1] & 0x7F;
    if (pt >= 64 && pt <= 95)
        return;

    /* 拒绝全零数据包 (RTP 版本 0) */
    if (data[0] == 0 && data[1] == 0)
        return;

    /* 简单的随机性检查：载荷类型应该在常见范围内 */
    if (pt > 127)
        return;

    arkime_session_add_protocol(session, "rtp");
    arkime_session_add_tag(session, "rtp:stream");

    /* 分配会话数据 */
    RtpSessionData_t *rtpData = ARKIME_TYPE_ALLOC0(RtpSessionData_t);
    rtpData->streamCount = 0;
    rtpData->hasCodecInfo = 0;

    /* 生成会话 ID */
    char ip_str[INET6_ADDRSTRLEN];
    if (!session->v6) {
        arkime_ip4tostr(ARKIME_V6_TO_V4(session->addr2), ip_str, sizeof(ip_str));
    } else {
        inet_ntop(AF_INET6, &session->addr2, ip_str, sizeof(ip_str));
    }
    snprintf(rtpData->sessionId, sizeof(rtpData->sessionId), "%s:%u",
             ip_str, session->port2);

    /* 注册到 RTP 会话查找表，供 SIP BYE 关闭用 */
    rtp_session_register(ip_str, session->port2, session);

    arkime_parsers_register2(session, rtp_parser, rtpData, rtp_free, rtp_save);
}

/******************************************************************************/
/* arkime_parser_init — 插件入口                                               */
/******************************************************************************/
void arkime_parser_init()
{
    /* 初始化桥接表 */
    rtp_bridge_init();

    /* 注册字段 */
    rtpSsrcField = arkime_field_define("rtp", "termfield",
                                        "rtp.ssrc", "RTP SSRC", "rtp.ssrc",
                                        "RTP synchronization source identifier",
                                        ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                        (char *)NULL);

    rtpPayloadTypeField = arkime_field_define("rtp", "termfield",
                                               "rtp.payload_type", "RTP Payload Type", "rtp.payload_type",
                                               "RTP payload type number",
                                               ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                               (char *)NULL);

    rtpCodecField = arkime_field_define("rtp", "termfield",
                                         "rtp.codec", "RTP Codec", "rtp.codec",
                                         "RTP codec name (H264, PCMU, OPUS, etc.)",
                                         ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                         (char *)NULL);

    rtpMediaField = arkime_field_define("rtp", "termfield",
                                         "rtp.media", "RTP Media", "rtp.media",
                                         "RTP media type (audio, video)",
                                         ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                         (char *)NULL);

    rtpPacketsField = arkime_field_define("rtp", "integer",
                                           "rtp.packets", "RTP Packets", "rtp.packets",
                                           "Number of RTP packets received",
                                           ARKIME_FIELD_TYPE_INT_GHASH, ARKIME_FIELD_FLAG_CNT,
                                           (char *)NULL);

    rtpLostField = arkime_field_define("rtp", "integer",
                                        "rtp.lost", "RTP Lost", "rtp.lost",
                                        "Estimated number of lost RTP packets",
                                        ARKIME_FIELD_TYPE_INT_GHASH, ARKIME_FIELD_FLAG_CNT,
                                        (char *)NULL);

    rtpStreamsField = arkime_field_define("rtp", "integer",
                                           "rtp.streams", "RTP Streams", "rtp.streams",
                                           "Number of SSRC streams in this session",
                                           ARKIME_FIELD_TYPE_INT_GHASH, ARKIME_FIELD_FLAG_CNT,
                                           (char *)NULL);

    rtpFilesField = arkime_field_define("rtp", "termfield",
                                         "rtp.files", "RTP Files", "rtp.files",
                                         "List of saved media files",
                                         ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                         (char *)NULL);

    /* 注册 RTP 分类器 */
    /* 使用端口范围方式 — 匹配所有 UDP 包，由 classify 函数过滤 */
    arkime_parsers_classifier_register_udp("rtp", NULL, 0, NULL, 0, rtp_classify);
}
