/* Copyright 2026 Andy Wick. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Basic FTP parser - extracts user, password, commands, filenames, response codes, banner
 * Also reassembles FTP data-channel transfers (RETR/STOR) to disk.
 */
#include "arkime.h"
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>

extern ArkimeConfig_t   config;

LOCAL  int userField;
LOCAL  int commandField;
LOCAL  int filenameField;
LOCAL  int responseCodeField;
LOCAL  int bannerField;
LOCAL  int savedFileField;   // ftp.savedFile - path to reassembled file on disk

#define FTP_LINE_MAX 4096

/* ------- FTP data-connection tracking ------- */

typedef struct {
    ArkimeSession_t *controlSession;  /* back-pointer to control channel session */
    char            *filename;        /* last RETR/STOR filename seen on control channel */
    uint32_t         dataFileCount;   /* how many files saved so far for this session */
} FTPDataCtx_t;

/*
 * Global table: key = "ip4:port" string (data-side server/client port)
 *               value = FTPDataCtx_t*
 * Protected by a simple spinlock – data connections are rare so contention is low.
 */
LOCAL GHashTable       *ftpDataPending;   /* char* -> FTPDataCtx_t* */
LOCAL ARKIME_LOCK_DEFINE(ftpDataLock);

/* Build hash-table key from a network-byte-order IP and HOST-byte-order port */
LOCAL void ftp_data_pending_key(char *buf, int bufsz, uint32_t ip_net, uint16_t port_host)
{
    struct in_addr a;
    a.s_addr = ip_net;  /* inet_ntoa expects network byte order */
    snprintf(buf, bufsz, "%s:%u", inet_ntoa(a), port_host);
}

/* ------- FTP data parser (registered on the data TCP connection) ------- */

typedef struct {
    FILE  *outFile;
    char   savedPath[512];
} FTPDataInfo_t;

LOCAL int ftp_data_parser(ArkimeSession_t UNUSED(*session), void *uw, const uint8_t *data, int remaining, int UNUSED(which))
{
    FTPDataInfo_t *di = uw;
    if (di->outFile && remaining > 0) {
        fwrite(data, 1, remaining, di->outFile);
    }
    return 0;
}

LOCAL void ftp_data_free(ArkimeSession_t UNUSED(*session), void *uw)
{
    FTPDataInfo_t *di = uw;
    if (di->outFile) {
        fclose(di->outFile);
        di->outFile = NULL;
    }
    ARKIME_TYPE_FREE(FTPDataInfo_t, di);
}

LOCAL void ftp_data_classify(ArkimeSession_t *session, const uint8_t *UNUSED(data),
                              int UNUSED(len), int UNUSED(which), void *UNUSED(uw))
{
    char key[64];
    uint32_t sip;
    uint16_t sport;
    FTPDataCtx_t *ctx = NULL;

    if (arkime_session_has_protocol(session, "ftp-data"))
        return;
    arkime_session_add_protocol(session, "ftp-data");

    /* Try both endpoints; the data port might be on either side */
    sip   = ARKIME_V6_TO_V4(session->addr1);
    sport = session->port1;
    ftp_data_pending_key(key, sizeof(key), sip, htons(sport));
    ARKIME_LOCK(ftpDataLock);
    ctx = g_hash_table_lookup(ftpDataPending, key);
    if (ctx) g_hash_table_remove(ftpDataPending, key);
    ARKIME_UNLOCK(ftpDataLock);

    if (!ctx) {
        sip   = ARKIME_V6_TO_V4(session->addr2);
        sport = session->port2;
        ftp_data_pending_key(key, sizeof(key), sip, htons(sport));
        ARKIME_LOCK(ftpDataLock);
        ctx = g_hash_table_lookup(ftpDataPending, key);
        if (ctx) g_hash_table_remove(ftpDataPending, key);
        ARKIME_UNLOCK(ftpDataLock);
    }

    if (!ctx) {
        return;
    }

    /* Open the output file */
    char idBuf[256];
    char path[512];
    arkime_session_id_string(ctx->controlSession->sessionId, idBuf);
    const char *basename = ctx->filename ?  ctx->filename : "unknown";
    /* strip leading path from filename to avoid directory traversal */
    const char *slash = strrchr(basename, '/');
    if (slash) basename = slash + 1;
    if (*basename == '\0') basename = "unknown";

    snprintf(path, sizeof(path), "%s/ftp_%s_%u_%s",
             "/data/file", idBuf, ctx->dataFileCount, basename);

    FTPDataInfo_t *di = ARKIME_TYPE_ALLOC0(FTPDataInfo_t);
    di->outFile = fopen(path, "wb");
    g_strlcpy(di->savedPath, path, sizeof(di->savedPath));

    /* Record path in the control session SPI */
    if (di->outFile) {
        arkime_field_string_add(savedFileField, ctx->controlSession, path, -1, TRUE);
    }

    arkime_parsers_register(session, ftp_data_parser, di, ftp_data_free);

    if (ctx->filename) g_free(ctx->filename);
    ARKIME_TYPE_FREE(FTPDataCtx_t, ctx);
}

/* Register ftp_data_classify for a specific port dynamically */
LOCAL void ftp_register_data_port(uint16_t port_network_order)
{
    /* port arg to register_port must be in host byte order */
    uint16_t port_host = ntohs(port_network_order);
    arkime_parsers_classifier_register_port("ftp-data", NULL, port_host,
                                            ARKIME_PARSERS_PORT_TCP,
                                            ftp_data_classify);
}


typedef struct {
    GString  *line[2];
    uint8_t   serverWhich;
    uint8_t   sawBanner;
    uint32_t  dataFileCount;
    FTPDataCtx_t *data_ctx;
} FTPInfo_t;

/******************************************************************************/
LOCAL int ftp_process_client_line(ArkimeSession_t *session, FTPInfo_t *ftp, const char *line, int len)
{
    while (len > 0 && (*line == ' ' || *line == '\t')) {
        line++;
        len--;
    }
    if (len < 3)
        return 0;

    const char *space = memchr(line, ' ', len);
    int cmdLen = space ? (int)(space - line) : len;
    if (cmdLen < 3 || cmdLen > 8)
        return 0;

    char cmd[16];
    int i;
    for (i = 0; i < cmdLen; i++) {
        if (!isalpha((uint8_t)line[i]))
            return 0;
        cmd[i] = toupper((uint8_t)line[i]);
    }
    cmd[cmdLen] = 0;

    if (strcmp(cmd, "HELO") == 0 || strcmp(cmd, "EHLO") == 0 || strcmp(cmd, "LHLO") == 0)
        return 1;

    const char *arg = space ? space + 1 : NULL;
    int argLen = space ? (len - cmdLen - 1) : 0;
    while (argLen > 0 && (*arg == ' ' || *arg == '\t')) {
        arg++;
        argLen--;
    }
    while (argLen > 0 && (arg[argLen - 1] == '\r' || arg[argLen - 1] == ' ' || arg[argLen - 1] == '\t')) {
        argLen--;
    }

    arkime_field_string_add(commandField, session, cmd, cmdLen, TRUE);

    if (argLen <= 0)
        return 0;

    if (strcmp(cmd, "USER") == 0) {
        arkime_field_string_add_lower(userField, session, arg, argLen);
    } else if (strcmp(cmd, "PASS") == 0) {
        arkime_session_add_tag(session, "ftp:password");
    } else if (strcmp(cmd, "RETR") == 0 || strcmp(cmd, "STOR") == 0 ||
               strcmp(cmd, "STOU") == 0 || strcmp(cmd, "APPE") == 0 ||
               strcmp(cmd, "DELE") == 0 || strcmp(cmd, "RNFR") == 0 ||
               strcmp(cmd, "RNTO") == 0 || strcmp(cmd, "MKD")  == 0 ||
               strcmp(cmd, "RMD")  == 0 || strcmp(cmd, "SIZE") == 0 ||
               strcmp(cmd, "MDTM") == 0) {
        arkime_field_string_add(filenameField, session, arg, argLen, TRUE);
        /* Track the filename for data-connection reassembly */
        if (strcmp(cmd, "RETR") == 0 || strcmp(cmd, "STOR") == 0 ||
            strcmp(cmd, "STOU") == 0 || strcmp(cmd, "APPE") == 0) {
            if (ftp->data_ctx->filename) {
                g_free(ftp->data_ctx->filename);
            }
            ftp->data_ctx->filename = g_strndup(arg, argLen);
        }
    } else if (strcmp(cmd, "PORT") == 0 && argLen > 0) {
        /* Active mode: PORT h1,h2,h3,h4,p1,p2 */
        unsigned int h1, h2, h3, h4, p1, p2;
        if (sscanf(arg, "%u,%u,%u,%u,%u,%u", &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
            uint32_t ip = htonl((h1 << 24) | (h2 << 16) | (h3 << 8) | h4);
            uint16_t port = htons((uint16_t)((p1 << 8) | p2));
            char key[64];
            ftp_data_pending_key(key, sizeof(key), ip, port);
            FTPDataCtx_t *ctx = ARKIME_TYPE_ALLOC0(FTPDataCtx_t);
            ctx->controlSession = session;
            ctx->filename       = NULL;
            ctx->dataFileCount  = ftp->dataFileCount++;
            ftp->data_ctx = ctx;
            ARKIME_LOCK(ftpDataLock);
            g_hash_table_insert(ftpDataPending, g_strdup(key), ctx);
            ARKIME_UNLOCK(ftpDataLock);
            ftp_register_data_port(port);
        }
    }
    return 0;
}
/******************************************************************************/
LOCAL void ftp_process_server_line(FTPInfo_t *ftp, ArkimeSession_t *session, const char *line, int len)
{
    if (len < 4)
        return;
    if (!isdigit((uint8_t)line[0]) || !isdigit((uint8_t)line[1]) || !isdigit((uint8_t)line[2]))
        return;

    int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    arkime_field_int_add(responseCodeField, session, code);

    if (!ftp->sawBanner && code == 220) {
        const char *msg = line + 4;
        int msgLen = len - 4;
        while (msgLen > 0 && (*msg == '-' || *msg == ' ' || *msg == '\t')) {
            msg++;
            msgLen--;
        }
        while (msgLen > 0 && (msg[msgLen - 1] == '\r' || msg[msgLen - 1] == ' ' || msg[msgLen - 1] == '\t' || msg[msgLen - 1] == '-')) {
            msgLen--;
        }
        if (msgLen > 0) {
            arkime_field_string_add(bannerField, session, msg, msgLen, TRUE);
            ftp->sawBanner = 1;
        }
    }

    /* PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2) */
    if (code == 227) {
        const char *paren = memchr(line, '(', len);
        if (paren) {
            unsigned int h1, h2, h3, h4, p1, p2;
            if (sscanf(paren + 1, "%u,%u,%u,%u,%u,%u", &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
                uint32_t ip = htonl((h1 << 24) | (h2 << 16) | (h3 << 8) | h4);
                uint16_t port = htons((uint16_t)((p1 << 8) | p2));
                LOG("%u %u %u %u %u %u", h1, h2, h3, h4, p1, p2);
                char key[64];
                ftp_data_pending_key(key, sizeof(key), ip, port);
                FTPDataCtx_t *ctx = ARKIME_TYPE_ALLOC0(FTPDataCtx_t);
                ctx->controlSession = session;
                ctx->filename       = NULL;
                ctx->dataFileCount  = ftp->dataFileCount++;
                ftp->data_ctx = ctx;
                ARKIME_LOCK(ftpDataLock);
                g_hash_table_insert(ftpDataPending, g_strdup(key), ctx);
                ARKIME_UNLOCK(ftpDataLock);
                ftp_register_data_port(port);
            }
        }
    }
}
/******************************************************************************/
LOCAL int ftp_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int remaining, int which)
{
    FTPInfo_t *ftp = uw;
    GString *buf = ftp->line[which];
    int isServer = (which == ftp->serverWhich);

    while (remaining > 0) {
        const uint8_t *lineEnd = memchr(data, '\n', remaining);
        int chunkLen;

        if (!lineEnd) {
            if (buf->len + remaining > FTP_LINE_MAX) {
                g_string_truncate(buf, 0);
                return ARKIME_PARSER_UNREGISTER;
            }
            g_string_append_len(buf, (const char *)data, remaining);
            return 0;
        }

        chunkLen = lineEnd - data;
        if (buf->len + chunkLen > FTP_LINE_MAX) {
            g_string_truncate(buf, 0);
            return ARKIME_PARSER_UNREGISTER;
        }
        g_string_append_len(buf, (const char *)data, chunkLen);

        int lineLen = buf->len;
        if (lineLen > 0 && buf->str[lineLen - 1] == '\r')
            lineLen--;

        if (lineLen > 0) {
            if (isServer) {
                ftp_process_server_line(ftp, session, buf->str, lineLen);
            } else if (ftp_process_client_line(session, ftp, buf->str, lineLen)) {
                arkime_field_free_one(session, bannerField);
                arkime_field_free_one(session, commandField);
                arkime_field_free_one(session, filenameField);
                arkime_field_free_one(session, responseCodeField);
                arkime_session_rm_protocol(session, "ftp");
                g_string_truncate(buf, 0);
                return ARKIME_PARSER_UNREGISTER;
            }
        }

        g_string_truncate(buf, 0);

        remaining -= chunkLen + 1;
        data = lineEnd + 1;
    }

    return 0;
}
/******************************************************************************/
LOCAL void ftp_free(ArkimeSession_t UNUSED(*session), void *uw)
{
    FTPInfo_t *ftp = uw;
    g_string_free(ftp->line[0], TRUE);
    g_string_free(ftp->line[1], TRUE);
    ARKIME_TYPE_FREE(FTPInfo_t, ftp);
}
/******************************************************************************/
LOCAL void ftp_classify(ArkimeSession_t *session, const uint8_t *data, int len, int which, void *UNUSED(uw))
{
    if (arkime_session_has_protocol(session, "ftp"))
        return;

    if (g_strstr_len((const char *)data, len, "LMTP") != NULL)
        return;
    if (g_strstr_len((const char *)data, len, "SMTP") != NULL)
        return;
    if (g_strstr_len((const char *)data, len, " TLS") != NULL)
        return;

    arkime_session_add_protocol(session, "ftp");

    FTPInfo_t *ftp = ARKIME_TYPE_ALLOC0(FTPInfo_t);
    ftp->line[0] = g_string_sized_new(128);
    ftp->line[1] = g_string_sized_new(128);
    ftp->serverWhich = which;

    arkime_parsers_register(session, ftp_parser, ftp, ftp_free);
}
/******************************************************************************/
void arkime_parser_init()
{
    userField = arkime_field_by_db("user");

    commandField = arkime_field_define("ftp", "uptermfield",
                                       "ftp.command", "Command", "ftp.command",
                                       "FTP command",
                                       ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                       (char *)NULL);

    filenameField = arkime_field_define("ftp", "termfield",
                                        "ftp.filename", "Filename", "ftp.filename",
                                        "FTP filename argument (RETR/STOR/DELE/RNFR/RNTO/MKD/RMD/SIZE/MDTM)",
                                        ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                        (char *)NULL);

    responseCodeField = arkime_field_define("ftp", "integer",
                                            "ftp.responseCode", "Response Code", "ftp.responseCode",
                                            "FTP response code",
                                            ARKIME_FIELD_TYPE_INT_GHASH, ARKIME_FIELD_FLAG_CNT,
                                            (char *)NULL);

    bannerField = arkime_field_define("ftp", "termfield",
                                      "ftp.banner", "Banner", "ftp.banner",
                                      "FTP server welcome banner",
                                      ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    savedFileField = arkime_field_define("ftp", "termfield",
                                          "ftp.savedFile", "Saved File", "ftp.savedFile",
                                          "Path of the reassembled FTP data-channel file saved to disk",
                                          ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                          (char *)NULL);

    /* Global table for pending FTP data connections */
    ARKIME_LOCK_INIT(ftpDataLock);
    ftpDataPending = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    /* NOTE: ftp-data port classifiers are registered dynamically when PASV/PORT is seen */

    arkime_parsers_classifier_register_tcp("ftp", NULL, 0, (const uint8_t *)"220 ", 4, ftp_classify);
    arkime_parsers_classifier_register_tcp("ftp", NULL, 0, (const uint8_t *)"220-", 4, ftp_classify);
}
