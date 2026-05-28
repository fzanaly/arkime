/* rtp_bridge.c  -- Cross-session RTP-SIP bridge table
 *
 * This table allows the SIP parser to share codec/SSRC information
 * with the RTP parser across different Arkime sessions.
 *
 * Also provides RTP session registration for SIP BYE → RTP session close.
 *
 * IMPORTANT: This file is compiled into the main capture binary
 * (not as a .so plugin), so its static variables are shared by all
 * parser .so files that reference these functions.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "arkime.h"
#include "parsers/rtp.h"

extern ArkimeConfig_t config;

/******************************************************************************/
/* Bridge Table — 跨会话共享编解码信息                                          */
/*                                                                             */
/* SIP 解析器在处理 SDP 时，将 c=IP + m=port → codec 的映射存入此表。            */
/* RTP 解析器在收到首个 RTP 包时，用 session 目标 IP:port 查询此表，              */
/* 从而获知该 RTP 流使用的编解码器，即使 SIP 和 RTP 属于不同的 Arkime session。    */
/*                                                                             */
/* 本文件编译入主 capture 二进制文件（而非 .so 插件），                            */
/* 因此所有加载的 .so 解析器共享同一份静态变量和互斥锁。                          */
/******************************************************************************/

LOCAL GHashTable *rtpBridgeTable = NULL;
LOCAL GMutex      rtpBridgeMutex;

/******************************************************************************/
/* RTP 会话注册表 — 供 SIP BYE → RTP 关闭使用                                   */
/* 声明提前到 init/exit 之前，确保 init 函数可以访问。                            */
/******************************************************************************/
LOCAL GHashTable *rtpSessionTable = NULL;
LOCAL GMutex      rtpSessionMutex;

/* Key format: "ip:port" */
LOCAL char *rtp_bridge_key(const char *ip, uint16_t port)
{
    return g_strdup_printf("%s:%u", ip, port);
}

void rtp_bridge_add(const char *ip, uint16_t port, RtpBridgeInfo_t *info)
{
    char *key = rtp_bridge_key(ip, port);
    RtpBridgeInfo_t *existing;

    g_mutex_lock(&rtpBridgeMutex);

    existing = g_hash_table_lookup(rtpBridgeTable, key);
    if (existing) {
        memcpy(existing, info, sizeof(RtpBridgeInfo_t));
        g_free(key);
    } else {
        RtpBridgeInfo_t *copy = g_memdup2(info, sizeof(RtpBridgeInfo_t));
        g_hash_table_insert(rtpBridgeTable, key, copy);
    }

    g_mutex_unlock(&rtpBridgeMutex);
}

int rtp_bridge_lookup(const char *ip, uint16_t port, RtpBridgeInfo_t *info)
{
    char *key = rtp_bridge_key(ip, port);
    int found = 0;

    g_mutex_lock(&rtpBridgeMutex);

    RtpBridgeInfo_t *entry = g_hash_table_lookup(rtpBridgeTable, key);
    if (entry) {
        memcpy(info, entry, sizeof(RtpBridgeInfo_t));
        found = 1;
    }

    g_mutex_unlock(&rtpBridgeMutex);
    g_free(key);
    return found;
}

void rtp_bridge_remove(const char *ip, uint16_t port)
{
    char *key = rtp_bridge_key(ip, port);

    g_mutex_lock(&rtpBridgeMutex);
    g_hash_table_remove(rtpBridgeTable, key);
    g_mutex_unlock(&rtpBridgeMutex);

    g_free(key);
}

LOCAL void rtp_bridge_free_value(gpointer data)
{
    g_free(data);
}

void rtp_bridge_init(void)
{
    if (rtpBridgeTable == NULL) {
        rtpBridgeTable = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                g_free, rtp_bridge_free_value);
        g_mutex_init(&rtpBridgeMutex);
    }

    /* 初始化 RTP 会话查找表（值不释放 — 仅作指针查找，不拥有 session 生命周期） */
    if (rtpSessionTable == NULL) {
        rtpSessionTable = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                 g_free, NULL);
        g_mutex_init(&rtpSessionMutex);
    }
}

void rtp_bridge_exit(void)
{
    if (rtpBridgeTable) {
        g_hash_table_destroy(rtpBridgeTable);
        rtpBridgeTable = NULL;
        g_mutex_clear(&rtpBridgeMutex);
    }

    if (rtpSessionTable) {
        g_hash_table_destroy(rtpSessionTable);
        rtpSessionTable = NULL;
        g_mutex_clear(&rtpSessionMutex);
    }
}

/******************************************************************************/
/* RTP 会话注册表 — 供 SIP BYE → RTP 关闭使用                                   */
/*                                                                             */
/* 此表维护 "ip:port" → ArkimeSession_t* 映射，                                  */
/* 允许 SIP 解析器（收到 BYE 时）通过桥接表条目的 IP:port 找到 RTP 会话并关闭。    */
/*                                                                             */
/* 线程安全说明：                                                                */
/*   arkime_session_mark_for_close() 访问 sessionThreadData[session->thread]，   */
/*   在多线程（非 dryrun）模式下，SIP 和 RTP 可能在不同线程，直接关闭不安全。      */
/*   当前实现适用于 --dryrun（单线程）和测试场景。                                  */
/*   多线程场景仍依赖 udpTimeout（60s）超时回退。                                  */
/******************************************************************************/

void rtp_session_register(const char *ip, uint16_t port, ArkimeSession_t *session)
{
    if (!ip || !session) return;

    char *key = rtp_bridge_key(ip, port);

    g_mutex_lock(&rtpSessionMutex);

    /* 如果已存在同 key 条目，先删除旧值（不释放 session） */
    g_hash_table_remove(rtpSessionTable, key);
    /* 插入 — 注意不引用 session 生命周期，session 释放时需手动 unregister */
    g_hash_table_insert(rtpSessionTable, key, session);

    g_mutex_unlock(&rtpSessionMutex);

    LOG("rtp_bridge: session registered: %s:%u -> %p", ip, port, (void *)session);
}

ArkimeSession_t *rtp_session_lookup(const char *ip, uint16_t port)
{
    if (!ip) return NULL;

    char *key = rtp_bridge_key(ip, port);
    ArkimeSession_t *session = NULL;

    g_mutex_lock(&rtpSessionMutex);
    session = g_hash_table_lookup(rtpSessionTable, key);
    g_mutex_unlock(&rtpSessionMutex);

    g_free(key);
    return session;
}

void rtp_session_unregister(const char *ip, uint16_t port)
{
    if (!ip) return;

    char *key = rtp_bridge_key(ip, port);

    g_mutex_lock(&rtpSessionMutex);
    g_hash_table_remove(rtpSessionTable, key);
    g_mutex_unlock(&rtpSessionMutex);

    g_free(key);

    LOG("rtp_bridge: session unregistered: %s:%u", ip, port);
}

/******************************************************************************/
/* rtp_bridge_close_by_callid — 关闭与 SIP Call-ID 关联的所有 RTP 会话          */
/*                                                                             */
/* 在 SIP BYE 解析后调用：遍历桥接表找到匹配 sipSessionId 的条目，                 */
/* 通过 IP:port 查询 RTP 会话注册表，对每个会话调用 arkime_session_mark_for_close()  */
/*                                                                             */
/* 线程安全：                                                                    */
/*   从桥接表收集 key 列表时加锁，释放锁后再逐个关闭，避免在持有锁时调用            */
/*   arkime_session_mark_for_close() 可能导致的死锁或锁顺序问题。                  */
/******************************************************************************/
void rtp_bridge_close_by_callid(const char *callId)
{
    if (!callId || callId[0] == '\0')
        return;

    LOG("rtp_bridge: close_by_callid called for '%s'", callId);

    /* 第 1 步：加锁遍历桥接表，收集匹配的 key 列表 */
    GList *keys_to_close = NULL;

    g_mutex_lock(&rtpBridgeMutex);

    GHashTableIter iter;
    gpointer key_ptr, value_ptr;
    g_hash_table_iter_init(&iter, rtpBridgeTable);
    while (g_hash_table_iter_next(&iter, &key_ptr, &value_ptr)) {
        RtpBridgeInfo_t *info = (RtpBridgeInfo_t *)value_ptr;
        LOG("rtp_bridge:   checking entry key='%s' sipSessionId='%s' (len=%zu) callId='%s' (len=%zu)",
            (char *)key_ptr, info->sipSessionId, strlen(info->sipSessionId),
            callId, strlen(callId));
        if (g_strcmp0(info->sipSessionId, callId) == 0) {
            /* 复制 key 字符串，传入列表 */
            keys_to_close = g_list_prepend(keys_to_close, g_strdup((char *)key_ptr));
            LOG("rtp_bridge:   matched bridge entry key='%s' codec=%s media=%s",
                (char *)key_ptr, info->codec, info->mediaType);
        }
    }

    g_mutex_unlock(&rtpBridgeMutex);

    if (!keys_to_close) {
        LOG("rtp_bridge:   no bridge entries matched callId '%s'", callId);
        return;
    }

    /* 第 2 步：对每个 key，查找 RTP 会话并关闭 */
    int closed_count = 0;
    for (GList *l = keys_to_close; l != NULL; l = l->next) {
        char *key = (char *)l->data;
        /* key 格式 "ip:port"，解析出 ip 和 port */
        char *colon = strchr(key, ':');
        if (!colon) {
            g_free(key);
            continue;
        }

        *colon = '\0';
        const char *ip = key;
        uint16_t port = (uint16_t)atoi(colon + 1);

        ArkimeSession_t *rtpSession = rtp_session_lookup(ip, port);
        if (rtpSession) {
            LOG("rtp_bridge:   closing RTP session %p (key=%s:%u)",
                (void *)rtpSession, ip, port);
            arkime_session_mark_for_close(rtpSession);
            closed_count++;
        } else {
            LOG("rtp_bridge:   no RTP session registered for key=%s:%u", ip, port);
        }

        *colon = ':'; /* restore */
        g_free(key);
    }

    g_list_free(keys_to_close);

    LOG("rtp_bridge: close_by_callid done, closed %d RTP sessions", closed_count);
}
