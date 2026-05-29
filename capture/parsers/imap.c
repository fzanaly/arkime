/* Copyright 2012-2017 AOL Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Basic IMAP parser - parses email addresses from FETCH responses
 * and saves email body content from FETCH BODY[] literals.
 */
#include "arkime.h"

extern ArkimeConfig_t   config;

LOCAL  int srcField;
LOCAL  int dstField;
LOCAL  int subjectField;
LOCAL  int folderField;
LOCAL  int bodyFileField;
LOCAL  int magicField;
LOCAL  int md5Field;
LOCAL  int sha256Field;

typedef struct {
    GString  *line;
    uint8_t   serverWhich;
    uint8_t   inFetch;
    uint8_t   inHeaders;
    uint8_t   inNtlmAuth;

    /* Body file saving fields */
    uint8_t   inLiteral;         /* Currently inside a literal (BODY[]) */
    uint32_t  literalRemaining;  /* Bytes remaining in current literal */
    FILE     *bodyFile;          /* File handle for writing body content */
    GChecksum *checksum[2];      /* [0]=MD5, [1]=SHA256 */
    uint32_t  bodyCount;         /* Counter for multiple FETCH responses */
    gboolean  firstBodyChunk;    /* Track first chunk for magic detection */
} IMAPInfo_t;

/******************************************************************************/
LOCAL void imap_parse_email_address(int field, ArkimeSession_t *session, const char *data, int len)
{
    const char *end = data + len;

    while (data < end) {
        while (data < end && isspace(*data)) data++;
        const char *start = data;

        /* Handle quoted strings */
        if (data < end && *data == '"') {
            data++;
            while (data < end && *data != '"') data++;
            data++;
            while (data < end && isspace(*data)) data++;
            start = data;
        }

        /* Find angle bracket or comma */
        while (data < end && *data != '<' && *data != ',' && *data != '\r' && *data != '\n') data++;

        if (data < end && *data == '<') {
            data++;
            start = data;
            while (data < end && *data != '>') data++;
        }

        if (data > start) {
            arkime_field_string_add_lower(field, session, start, data - start);
        }

        while (data < end && *data != ',' && *data != '\r' && *data != '\n') data++;
        if (data < end) data++;
    }
}
/******************************************************************************/
LOCAL void imap_parse_header_line(IMAPInfo_t UNUSED(*imap), ArkimeSession_t *session, const char *line, int len)
{
    if (len < 3) return;

    /* From: header */
    if (len > 5 && strncasecmp(line, "From:", 5) == 0) {
        imap_parse_email_address(srcField, session, line + 5, len - 5);
    }
    /* To: header */
    else if (len > 3 && strncasecmp(line, "To:", 3) == 0) {
        imap_parse_email_address(dstField, session, line + 3, len - 3);
    }
    /* Cc: header */
    else if (len > 3 && strncasecmp(line, "Cc:", 3) == 0) {
        imap_parse_email_address(dstField, session, line + 3, len - 3);
    }
    /* Subject: header */
    else if (len > 8 && strncasecmp(line, "Subject:", 8) == 0) {
        const char *s = line + 8;
        const char *end = line + len;
        while (s < end && isspace(*s)) s++;
        arkime_field_string_add(subjectField, session, s, len - (s - line), TRUE);
    }
}
/******************************************************************************/
LOCAL void imap_process_line(IMAPInfo_t *imap, ArkimeSession_t *session, const char *line, int len, int which)
{
    /* NTLM detection / decoding */
    if (which != imap->serverWhich && len > 16) {
        /* Client: "<tag> AUTHENTICATE NTLM [<base64>]" */
        const char *cmd = line;
        while (cmd < line + len && !isspace(*cmd)) cmd++;
        while (cmd < line + len && isspace(*cmd)) cmd++;
        if (line + len - cmd >= 17 && strncasecmp(cmd, "AUTHENTICATE NTLM", 17) == 0) {
            imap->inNtlmAuth = 1;
            const char *rest = cmd + 17;
            if (rest < line + len && *rest == ' ')
                arkime_parsers_ntlm_decode_base64(session, rest + 1, (line + len) - (rest + 1));
            return;
        }
    }
    if (imap->inNtlmAuth) {
        const char *b = line;
        int blen = len;
        /* Server continuation: "+ TlRMTVN..." */
        if (which == imap->serverWhich && blen > 2 && b[0] == '+' && b[1] == ' ') {
            b += 2;
            blen -= 2;
        }
        if (arkime_parsers_ntlm_decode_base64(session, b, blen))
            return;
    }

    /* Server responses */
    if (which == imap->serverWhich) {
        if (len > 6 && line[0] == '*' && line[1] == ' ') {
            if (arkime_memcasestr(line, len, "fetch", 5)) {
                imap->inFetch = TRUE;
                imap->inHeaders = TRUE;

                /* Check for literal size in FETCH response: "* N FETCH (BODY[] {size}" */
                const char *brace = memchr(line, '{', len);
                if (brace) {
                    const char *endBrace = memchr(brace, '}', line + len - brace);
                    if (endBrace && endBrace > brace + 1) {
                        int size = atoi(brace + 1);
                        if (size > 0) {
                            imap->inLiteral = TRUE;
                            imap->literalRemaining = size;

                            /* Open body file */
                            if (config.httpBodySave) {
                                char idBuf[256];
                                char path[512];
                                arkime_session_id_string(session->sessionId, idBuf);
                                snprintf(path, sizeof(path), "%s/%s_imap_%u.eml",
                                        config.contentSavePath, idBuf, imap->bodyCount++);
                                imap->bodyFile = fopen(path, "wb");
                                if (imap->bodyFile) {
                                    arkime_field_string_add(bodyFileField, session, path, -1, TRUE);
                                }
                                imap->firstBodyChunk = TRUE;
                            }
                        }
                    }
                }
            }
        } else if (imap->inFetch && len > 0 && line[0] == ')') {
            imap->inFetch = FALSE;
            imap->inHeaders = FALSE;
        } else if (imap->inFetch && imap->inHeaders) {
            if (len == 0) {
                imap->inHeaders = FALSE;
            } else {
                imap_parse_header_line(imap, session, line, len);
            }
        }
    }
    /* Client commands */
    else {
        if (len > 7) {
            const char *cmd = line;
            while (cmd < line + len && !isspace(*cmd)) cmd++;
            while (cmd < line + len && isspace(*cmd)) cmd++;

            if (strncasecmp(cmd, "SELECT ", 7) == 0 || strncasecmp(cmd, "EXAMINE ", 8) == 0) {
                const char *folder = cmd + (strncasecmp(cmd, "SELECT", 6) == 0 ? 7 : 8);
                while (folder < line + len && isspace(*folder)) folder++;

                const char *folderEnd = line + len;
                if (folder < line + len && *folder == '"') {
                    folder++;
                    folderEnd = memchr(folder, '"', folderEnd - folder);
                    if (!folderEnd) folderEnd = line + len;
                } else {
                    while (folderEnd > folder && isspace(folderEnd[-1])) folderEnd--;
                }

                if (folderEnd > folder) {
                    arkime_field_string_add(folderField, session, folder, folderEnd - folder, TRUE);
                }
            }
        }
    }
}
/******************************************************************************/
LOCAL int imap_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int remaining, int which)
{
    IMAPInfo_t *imap = uw;

    while (remaining > 0) {
        /* If we are inside a literal (BODY[] data), write raw bytes to body file */
        if (imap->inLiteral) {
            uint32_t writeLen = (uint32_t)remaining;
            if (writeLen > imap->literalRemaining)
                writeLen = imap->literalRemaining;

            if (writeLen > 0 && config.httpBodySave && imap->bodyFile) {
                fwrite(data, 1, writeLen, imap->bodyFile);
                g_checksum_update(imap->checksum[0], data, writeLen);
                if (config.supportSha256) {
                    g_checksum_update(imap->checksum[1], data, writeLen);
                }
                if (imap->firstBodyChunk) {
                    imap->firstBodyChunk = FALSE;
                    arkime_parsers_magic(session, magicField, (const char *)data, writeLen);
                }
            }

            imap->literalRemaining -= writeLen;
            remaining -= writeLen;
            data += writeLen;

            if (imap->literalRemaining == 0) {
                imap->inLiteral = FALSE;
                /* Close body file - literal data is complete */
                if (imap->bodyFile) {
                    fclose(imap->bodyFile);
                    imap->bodyFile = NULL;
                }
            }
            continue;
        }

        /* Normal line-by-line parsing */
        /* Find end of line */
        const uint8_t *lineEnd = memchr(data, '\n', remaining);
        int lineLen;

        if (lineEnd) {
            lineLen = lineEnd - data;
            /* Strip CR if present */
            if (lineLen > 0 && data[lineLen - 1] == '\r') {
                lineLen--;
            }
        } else {
            /* Incomplete line, buffer it (cap to prevent unbounded growth) */
            if (imap->line->len + remaining > 16384) {
                arkime_session_add_tag(session, "imap:line-too-long");
                return ARKIME_PARSER_UNREGISTER;
            }
            g_string_append_len(imap->line, (const char *)data, remaining);
            return 0;
        }

        /* Combine with any buffered data */
        if (imap->line->len > 0) {
            if (imap->line->len + lineLen > 16384) {
                arkime_session_add_tag(session, "imap:line-too-long");
                return ARKIME_PARSER_UNREGISTER;
            }
            g_string_append_len(imap->line, (const char *)data, lineLen);
            imap_process_line(imap, session, imap->line->str, imap->line->len, which);
            g_string_truncate(imap->line, 0);
        } else {
            imap_process_line(imap, session, (const char *)data, lineLen, which);
        }

        /* Move past this line */
        remaining -= (lineEnd - data) + 1;
        data = lineEnd + 1;
    }

    return 0;
}
/******************************************************************************/
LOCAL void imap_save(ArkimeSession_t *session, void *uw, int final)
{
    IMAPInfo_t *imap = uw;
    if (!final)
        return;

    /* Store MD5 hash if we captured any body content */
    if (imap->bodyCount > 0) {
        const char *md5 = g_checksum_get_string(imap->checksum[0]);
        arkime_field_string_add(md5Field, session, (char *)md5, 32, TRUE);

        if (config.supportSha256) {
            const char *sha256 = g_checksum_get_string(imap->checksum[1]);
            arkime_field_string_add(sha256Field, session, (char *)sha256, 64, TRUE);
        }
    }
}
/******************************************************************************/
LOCAL void imap_free(ArkimeSession_t UNUSED(*session), void *uw)
{
    IMAPInfo_t *imap = uw;

    g_string_free(imap->line, TRUE);

    if (imap->bodyFile)
        fclose(imap->bodyFile);

    g_checksum_free(imap->checksum[0]);
    if (config.supportSha256)
        g_checksum_free(imap->checksum[1]);

    ARKIME_TYPE_FREE(IMAPInfo_t, imap);
}
/******************************************************************************/
LOCAL void imap_classify(ArkimeSession_t *session, const uint8_t *data, int len, int which, void *UNUSED(uw))
{
    if (arkime_session_has_protocol(session, "imap"))
        return;

    if (len < 10)
        return;

    /* Check for "* OK " followed by IMAP somewhere */
    if (memcmp(data, "* OK ", 5) != 0)
        return;

    if (!arkime_memcasestr((const char *)data + 5, len - 5, "imap", 4))
        return;

    arkime_session_add_protocol(session, "imap");

    IMAPInfo_t *imap = ARKIME_TYPE_ALLOC0(IMAPInfo_t);
    imap->line = g_string_sized_new(256);
    imap->serverWhich = which;

    imap->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
    if (config.supportSha256)
        imap->checksum[1] = g_checksum_new(G_CHECKSUM_SHA256);

    arkime_parsers_register2(session, imap_parser, imap, imap_free, imap_save);
}
/******************************************************************************/
void arkime_parser_init()
{
    srcField = arkime_field_define("email", "lotermfield",
                                   "email.src", "Sender", "email.src",
                                   "Email from address",
                                   ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                   "requiredRight", "emailSearch",
                                   "category", "user",
                                   (char *)NULL);

    dstField = arkime_field_define("email", "lotermfield",
                                   "email.dst", "Receiver", "email.dst",
                                   "Email to address",
                                   ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                   "requiredRight", "emailSearch",
                                   "category", "user",
                                   (char *)NULL);

    subjectField = arkime_field_define("email", "termfield",
                                       "email.subject", "Subject", "email.subject",
                                       "Email subject header",
                                       ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT | ARKIME_FIELD_FLAG_FORCE_UTF8,
                                       "requiredRight", "emailSearch",
                                       (char *)NULL);

    folderField = arkime_field_define("email", "termfield",
                                      "email.folder", "Folder", "email.folder",
                                      "Email folder/mailbox name",
                                      ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    bodyFileField = arkime_field_define("imap", "termfield",
                                        "imap.files", "IMAP Body File", "imap.files",
                                        "IMAP email body saved file path",
                                        ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                        (char *)NULL);

    magicField = arkime_field_define("imap", "termfield",
                                     "imap.bodymagic", "IMAP Body Magic", "imap.bodyMagic",
                                     "The content type of IMAP body determined by libfile/magic",
                                     ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                     (char *)NULL);

    md5Field = arkime_field_define("imap", "termfield",
                                   "imap.body.md5", "IMAP Body MD5", "imap.bodyMd5",
                                   "IMAP email body MD5",
                                   ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                   "category", "md5",
                                   (char *)NULL);

    if (config.supportSha256) {
        sha256Field = arkime_field_define("imap", "termfield",
                                          "imap.body.sha256", "IMAP Body SHA256", "imap.bodySha256",
                                          "IMAP email body SHA256",
                                          ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                          "category", "sha256",
                                          "disabled", "true",
                                          (char *)NULL);
    }

    arkime_parsers_classifier_register_tcp("imap", NULL, 0, (const uint8_t *)"* OK ", 5, imap_classify);
}
