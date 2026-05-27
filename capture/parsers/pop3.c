/* SPDX-License-Identifier: Apache-2.0
 *
 * POP3 parser - captures the USER name, decodes NTLMSSP blobs
 * sent via SASL AUTH NTLM (RFC 1734 / RFC 5034), and captures
 * email body content from RETR responses.
 */
#include "arkime.h"

extern ArkimeConfig_t   config;

LOCAL  int userField;
LOCAL  int bodyFileField;
LOCAL  int magicField;
LOCAL  int md5Field;
LOCAL  int sha256Field;

typedef struct {
    GString  *line[2];
    uint8_t   serverWhich;
    uint8_t   inNtlmAuth;
    uint8_t   ntlmCount;
    uint8_t   done;

    uint8_t   inRetr;           /* Currently inside a RETR response body */
    uint8_t   seenRetrCmd;      /* Client issued RETR command */
    FILE     *bodyFile;         /* File handle for writing body content */
    GChecksum *checksum[2];     /* [0]=MD5, [1]=SHA256 */
    uint32_t  bodyCount;        /* Counter for multiple RETRs */
    gboolean  firstBodyChunk;   /* Track first chunk for magic detection */
} POP3Info_t;

/******************************************************************************/
LOCAL void pop3_process_line(POP3Info_t *pop3, ArkimeSession_t *session, const char *line, int len, int which)
{
    /* Client: "AUTH NTLM [<base64>]" */
    if (which != pop3->serverWhich && len >= 9 &&
        strncasecmp(line, "AUTH NTLM", 9) == 0) {
        arkime_session_add_tag(session, "pop3:authntlm");
        pop3->inNtlmAuth = 1;
        if (len > 10 && line[9] == ' ') {
            if (arkime_parsers_ntlm_decode_base64(session, line + 10, len - 10))
                pop3->ntlmCount++;
        }
        return;
    }

    if (pop3->inNtlmAuth) {
        const char *b = line;
        int blen = len;
        /* Server continuation: "+ TlRMTVN..." */
        if (which == pop3->serverWhich && blen > 2 && b[0] == '+' && b[1] == ' ') {
            b += 2;
            blen -= 2;
        }
        if (arkime_parsers_ntlm_decode_base64(session, b, blen)) {
            pop3->ntlmCount++;
            /* After Type 3 (third message from client) we're done. */
            if (pop3->ntlmCount >= 3)
                pop3->done = 1;
            return;
        }
    }

    /* Client: "USER <name>" */
    if (which != pop3->serverWhich && len > 5 &&
        strncasecmp(line, "USER ", 5) == 0) {
        const char *u = line + 5;
        int ulen = len - 5;
        while (ulen > 0 && isspace((unsigned char) * u)) {
            u++;
            ulen--;
        }
        while (ulen > 0 && isspace((unsigned char)u[ulen - 1])) ulen--;
        if (ulen > 0)
            arkime_field_string_add_lower(userField, session, u, ulen);
        pop3->done = 1;
        return;
    }

    /* Client: "RETR <msg>" - marks the start of a message retrieval */
    if (which != pop3->serverWhich && len > 5 &&
        strncasecmp(line, "RETR ", 5) == 0) {
        pop3->seenRetrCmd = 1;
        return;
    }

    /* Server: "+OK" response to RETR - start of message body */
    if (which == pop3->serverWhich && pop3->seenRetrCmd && !pop3->inRetr) {
        if (len >= 3 && strncasecmp(line, "+OK", 3) == 0) {
            pop3->inRetr = 1;
            pop3->seenRetrCmd = 0;
            pop3->firstBodyChunk = TRUE;
            return;
        }
        /* If server didn't respond with +OK, reset */
        pop3->seenRetrCmd = 0;
        return;
    }

    /* Server: body content lines during RETR response */
    if (which == pop3->serverWhich && pop3->inRetr) {
        /* "." on a line by itself - end of message (RFC 1939 section 3) */
        if (len == 1 && line[0] == '.') {
            /* Close file if open */
            if (pop3->bodyFile) {
                fclose(pop3->bodyFile);
                pop3->bodyFile = NULL;
            }
            pop3->inRetr = 0;
            return;
        }

        /* Handle dot-stuffing: lines starting with ".." become "." */
        const char *bodyData = line;
        int bodyLen = len;
        if (len > 0 && line[0] == '.') {
            bodyData = line + 1;
            bodyLen = len - 1;
        }

        /* Write body content to file */
        if (bodyLen > 0 && config.httpBodySave) {
            if (!pop3->bodyFile) {
                char idBuf[256];
                char path[512];
                arkime_session_id_string(session->sessionId, idBuf);
                snprintf(path, sizeof(path), "%s/%s_pop3_%u.eml",
                        "/data/file", idBuf, pop3->bodyCount++);
                pop3->bodyFile = fopen(path, "wb");
                if (pop3->bodyFile) {
                    arkime_field_string_add(bodyFileField, session, path, -1, TRUE);
                }
            }
            if (pop3->bodyFile) {
                fwrite(bodyData, 1, bodyLen, pop3->bodyFile);
                /* Restore the newline that was stripped by line parsing */
                fwrite("\n", 1, 1, pop3->bodyFile);
            }
        }

        /* Update checksums */
        if (bodyLen > 0) {
            g_checksum_update(pop3->checksum[0], (guchar *)bodyData, bodyLen);
            if (config.supportSha256) {
                g_checksum_update(pop3->checksum[1], (guchar *)bodyData, bodyLen);
            }
            if (pop3->firstBodyChunk) {
                pop3->firstBodyChunk = FALSE;
                arkime_parsers_magic(session, magicField, bodyData, bodyLen);
            }
        }
        return;
    }
}
/******************************************************************************/
LOCAL int pop3_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int remaining, int which)
{
    POP3Info_t *pop3 = uw;
    GString *line = pop3->line[which];

    while (remaining > 0) {
        const uint8_t *lineEnd = memchr(data, '\n', remaining);
        int lineLen;

        if (lineEnd) {
            lineLen = lineEnd - data;
            if (lineLen > 0 && data[lineLen - 1] == '\r')
                lineLen--;
        } else {
            if (line->len + remaining > 16384) {
                arkime_session_add_tag(session, "pop3:line-too-long");
                return ARKIME_PARSER_UNREGISTER;
            }
            g_string_append_len(line, (const char *)data, remaining);
            return 0;
        }

        if (line->len > 0) {
            if (line->len + lineLen > 16384) {
                arkime_session_add_tag(session, "pop3:line-too-long");
                return ARKIME_PARSER_UNREGISTER;
            }
            g_string_append_len(line, (const char *)data, lineLen);
            pop3_process_line(pop3, session, line->str, line->len, which);
            g_string_truncate(line, 0);
        } else {
            pop3_process_line(pop3, session, (const char *)data, lineLen, which);
        }

        remaining -= (lineEnd - data) + 1;
        data = lineEnd + 1;

        if (pop3->done)
            return ARKIME_PARSER_UNREGISTER;
    }

    return 0;
}
/******************************************************************************/
LOCAL void pop3_save(ArkimeSession_t *session, void *uw, int final)
{
    POP3Info_t *pop3 = uw;
    if (!final)
        return;

    /* Store MD5 hash if we captured any body content */
    if (pop3->bodyCount > 0) {
        const char *md5 = g_checksum_get_string(pop3->checksum[0]);
        arkime_field_string_add(md5Field, session, (char *)md5, 32, TRUE);

        if (config.supportSha256) {
            const char *sha256 = g_checksum_get_string(pop3->checksum[1]);
            arkime_field_string_add(sha256Field, session, (char *)sha256, 64, TRUE);
        }
    }
}
/******************************************************************************/
LOCAL void pop3_free(ArkimeSession_t UNUSED(*session), void *uw)
{
    POP3Info_t *pop3 = uw;
    g_string_free(pop3->line[0], TRUE);
    g_string_free(pop3->line[1], TRUE);

    if (pop3->bodyFile)
        fclose(pop3->bodyFile);

    g_checksum_free(pop3->checksum[0]);
    if (config.supportSha256)
        g_checksum_free(pop3->checksum[1]);

    ARKIME_TYPE_FREE(POP3Info_t, pop3);
}
/******************************************************************************/
LOCAL void pop3_classify(ArkimeSession_t *session, const uint8_t *data, int len, int which, void *UNUSED(uw))
{
    if (arkime_session_has_protocol(session, "pop3"))
        return;

    if (len < 8)
        return;

    /* Greeting "+OK ..." with "POP" somewhere in it */
    if (memcmp(data, "+OK ", 4) != 0)
        return;

    if (!arkime_memcasestr((const char *)data + 4, len - 4, "pop", 3))
        return;

    arkime_session_add_protocol(session, "pop3");

    POP3Info_t *pop3 = ARKIME_TYPE_ALLOC0(POP3Info_t);
    pop3->line[0] = g_string_sized_new(256);
    pop3->line[1] = g_string_sized_new(256);
    pop3->serverWhich = which;

    pop3->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
    if (config.supportSha256)
        pop3->checksum[1] = g_checksum_new(G_CHECKSUM_SHA256);

    arkime_parsers_register2(session, pop3_parser, pop3, pop3_free, pop3_save);
}
/******************************************************************************/
void arkime_parser_init()
{
    userField = arkime_field_define("pop3", "lotermfield",
                                    "pop3.user", "User", "pop3.user",
                                    "POP3 username",
                                    ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    bodyFileField = arkime_field_define("pop3", "termfield",
                                        "pop3.bodyfile", "POP3 Body File", "pop3.bodyFile",
                                        "POP3 email body saved file path",
                                        ARKIME_FIELD_TYPE_STR_HASH, 0,
                                        (char *)NULL);

    magicField = arkime_field_define("pop3", "termfield",
                                     "pop3.bodymagic", "POP3 Body Magic", "pop3.bodyMagic",
                                     "The content type of POP3 body determined by libfile/magic",
                                     ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                     (char *)NULL);

    md5Field = arkime_field_define("pop3", "termfield",
                                   "pop3.body.md5", "POP3 Body MD5", "pop3.bodyMd5",
                                   "POP3 email body MD5",
                                   ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                   "category", "md5",
                                   (char *)NULL);

    if (config.supportSha256) {
        sha256Field = arkime_field_define("pop3", "termfield",
                                          "pop3.body.sha256", "POP3 Body SHA256", "pop3.bodySha256",
                                          "POP3 email body SHA256",
                                          ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                          "category", "sha256",
                                          "disabled", "true",
                                          (char *)NULL);
    }

    arkime_parsers_classifier_register_tcp("pop3", NULL, 0, (const uint8_t *)"+OK ", 4, pop3_classify);
}
