#ifndef RTP_H
#define RTP_H

#include <glib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* RTP 头部解析宏 (RFC 3550)                                                   */
/******************************************************************************/
#define RTP_VER(data)         (((data)[0] >> 6) & 0x03)
#define RTP_PADDING(data)     (((data)[0] >> 5) & 0x01)
#define RTP_EXTENSION(data)   (((data)[0] >> 4) & 0x01)
#define RTP_CC(data)          ((data)[0] & 0x0F)
#define RTP_MARKER(data)      (((data)[1] >> 7) & 0x01)
#define RTP_PT(data)          ((data)[1] & 0x7F)
#define RTP_SEQ(data)         (((uint16_t)(data)[2] << 8) | (uint16_t)(data)[3])
#define RTP_TS(data)          ((uint32_t)(data)[4] << 24 | (uint32_t)(data)[5] << 16 | \
                               (uint32_t)(data)[6] << 8  | (uint32_t)(data)[7])
#define RTP_SSRC(data)        ((uint32_t)(data)[8] << 24 | (uint32_t)(data)[9] << 16 | \
                               (uint32_t)(data)[10] << 8 | (uint32_t)(data)[11])

/* RTP 头部长度：12 字节固定头 + CSRC 列表 + 扩展头 */
#define RTP_HEADER_LEN(cc, ext_len) (12 + (cc) * 4 + (ext_len) * 4)

/******************************************************************************/
/* 限制常量                                                                    */
/******************************************************************************/
#define MAX_SSRC_PER_SESSION    4
#define MAX_RTP_PAYLOAD_SIZE    65536
#define MAX_STREAM_BUFFER_SIZE  (50 * 1024 * 1024)  /* 每流最大 50MB */
#define RTP_PTIME_MS            20                   /* 默认音频帧时长 20ms */
#define RTP_AUDIO_CLOCK_RATE    8000

/******************************************************************************/
/* H.264 NAL 单元类型 (RFC 3984)                                               */
/******************************************************************************/
#define H264_NAL_TYPE(nal_hdr)  ((nal_hdr) & 0x1F)
#define H264_NAL_FU_A           28
#define H264_NAL_STAP_A         24
#define H264_NAL_SPS            7
#define H264_NAL_PPS            8
#define H264_NAL_IDR            5
#define H264_NAL_NON_IDR        1
#define H264_NAL_AUD            9

/* FU-A 分片头 */
#define H264_FU_HEADER(data)    ((data)[0])
#define H264_FU_START(data)     (((data)[0] >> 7) & 0x01)
#define H264_FU_END(data)       (((data)[0] >> 6) & 0x01)
#define H264_FU_TYPE(data)      ((data)[0] & 0x1F)

/* Annex B 起始码 */
static const uint8_t annexb_startcode[] = {0x00, 0x00, 0x00, 0x01};
#define ANNEXB_STARTCODE_LEN    4

/******************************************************************************/
/* SDP-RTP 桥接表 — 线程安全全局哈希表                                          */
/******************************************************************************/

/* RTP 流信息，由 SIP 解析器填充，RTP 解析器查询 */
typedef struct {
    char     mediaType[16];     /* "audio" "video" */
    char     codec[32];         /* "PCMU" "H264" "OPUS" */
    int      payloadType;       /* 动态 PT 编号 */
    uint32_t ssrc;              /* 0=未知，RTP 解析后填充 */
    char     sipSessionId[64];  /* 关联的 SIP 会话 ID */
} RtpBridgeInfo_t;

/* 桥接表操作（线程安全） */
void rtp_bridge_add(const char *ip, uint16_t port, RtpBridgeInfo_t *info);
int  rtp_bridge_lookup(const char *ip, uint16_t port, RtpBridgeInfo_t *info);
void rtp_bridge_remove(const char *ip, uint16_t port);
void rtp_bridge_init(void);
void rtp_bridge_exit(void);

/******************************************************************************/
/* RTP 会话注册表 — SIP BYE → RTP 会话关闭                                      */
/*                                                                             */
/* RTP 解析器在 rtp_classify() 中注册会话，rtp_free() 中注销。                   */
/* SIP 解析器在收到 BYE 时查找并关闭 RTP 会话，从而提前写入媒体文件。              */
/*                                                                             */
/* 超时回退 (udpTimeout 默认 60s) 仍在 udp.c 中生效，BYE 丢失时依然能自动关闭。    */
/******************************************************************************/

/* 注册 RTP 会话供反向查找 */
void rtp_session_register(const char *ip, uint16_t port, ArkimeSession_t *session);

/* 通过 IP:port 查找已注册的 RTP 会话 */
ArkimeSession_t *rtp_session_lookup(const char *ip, uint16_t port);

/* 注销 RTP 会话 */
void rtp_session_unregister(const char *ip, uint16_t port);

/* 关闭与指定 SIP Call-ID 关联的所有 RTP 会话 */
void rtp_bridge_close_by_callid(const char *callId);

/******************************************************************************/
/* 单 SSRC 流状态                                                              */
/******************************************************************************/
typedef struct {
    uint32_t ssrc;               /* SSRC 标识 */
    int      payloadType;        /* RTP 载荷类型 */
    uint16_t lastSeq;            /* 上次序列号，用于检测丢包 */
    int      packetCount;        /* 收到的包数 */
    int      lostCount;          /* 检测到的丢包数 */
    int      gotFirst;           /* 是否收到第一个包 */

    /* 累积的已解包载荷缓冲区 (Annex B for H.264, raw frames for audio) */
    uint8_t *buf;                /* 累积数据 */
    int      bufLen;             /* 当前数据长度 */
    int      bufAlloc;           /* 分配大小 */
    int      bufOverflow;        /* 超过最大限制标志 */

    /* H.263 帧边界 (由 RTP marker bit 确定，替代 PSC 扫描) */
#define MAX_H263_FRAMES 4096
    int      frameEnds[MAX_H263_FRAMES]; /* 每帧在 buf 中的结束偏移 */
    int      frameCount;                  /* 帧数 */

    /* 每个 RTP 包的载荷大小，用于正确分割 Opus 等变长帧 */
    int     *packetSizes;        /* 每个 RTP 包的 payload 长度数组 */
    int      packetSizesCount;   /* packetSizes 数组中的元素数 */
    int      packetSizesAlloc;   /* packetSizes 数组分配容量 */

    /* H.264 SPS/PPS (用于 MP4 容器 extradata) */
    uint8_t  sps[64];
    int      spsLen;
    uint8_t  pps[64];
    int      ppsLen;

    /* 时间信息 (RTP 时间戳) */
    uint32_t firstTimestamp;
    uint32_t lastTimestamp;
    int      hasTimestamps;
    int      clockRate;          /* RTP 时钟频率 (H.264=90000, 音频=8000) */

    /* 媒体信息 */
    char     mediaType[16];
    char     codec[32];
} RtpStreamState_t;

/******************************************************************************/
/* 每个 RTP 会话的数据                                                         */
/******************************************************************************/
typedef struct {
    RtpStreamState_t streams[MAX_SSRC_PER_SESSION];
    int         streamCount;
    RtpBridgeInfo_t codecInfo;
    int         hasCodecInfo;    /* 是否已从桥接表查询到信息 */
    int         isAudio;
    int         isVideo;
    char        sessionId[64];   /* 格式 "ip:port" */
} RtpSessionData_t;

/******************************************************************************/
/* FFmpeg 辅助函数                                                             */
/******************************************************************************/

/* 将 RTP 编码名映射为 AVCodecID */
int rtp_codec_to_avcodec_id(const char *codec);

/* 获取 RTP 时钟频率 */
int rtp_codec_clock_rate(const char *codec);

/* 获取文件扩展名 */
const char *rtp_codec_container_ext(const char *codec);

/* 获取媒体类型标签 */
const char *rtp_codec_media_type(const char *codec);

#ifdef __cplusplus
}
#endif

#endif /* RTP_H */
