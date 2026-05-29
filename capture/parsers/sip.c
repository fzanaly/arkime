/* Copyright 2026 Andy Wick. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SIP (Session Initiation Protocol) parser
 * RFC 3261
 */
#include "arkime.h"
#include "rtp.h"

extern ArkimeConfig_t config;

LOCAL int methodField;
LOCAL int statusCodeField;
LOCAL int callIdField;
LOCAL int fromField;
LOCAL int toField;
LOCAL int userAgentField;
LOCAL int viaField;
LOCAL int contactField;
LOCAL int userField;

// RTP/SDP fields
LOCAL int rtpMediaField;
LOCAL int rtpPortField;
LOCAL int rtpCodecField;
LOCAL int rtpTransportField;
LOCAL int rtpIpField;

// Forward declarations
LOCAL int sip_find_line(const uint8_t *data, int len, int *lineLen);
LOCAL void sip_extract_callid_from_data(const uint8_t *data, int len, char *callid, int callid_size);

/******************************************************************************/
// Static RTP payload type -> codec mapping per RFC 3551
LOCAL const char *sdp_static_codec(int pt)
{
    switch (pt) {
    case 0:  return "PCMU";
    case 2:  return "G721";
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
    default: return NULL;
    }
}

// Structure for dynamic payload type mapping from rtpmap
#define SDP_MAX_DYNAMIC_PTS 32
typedef struct {
    int   pt;
    char  codec[32];
} SdpPtMap;

/******************************************************************************/
// Lookup codec name for a payload type, checking dynamic mappings first
LOCAL const char *sdp_pt_to_codec(int pt, SdpPtMap *dynMap, int dynCount)
{
    for (int i = 0; i < dynCount; i++) {
        if (dynMap[i].pt == pt)
            return dynMap[i].codec;
    }
    return sdp_static_codec(pt);
}

/******************************************************************************/
// Parse a=rtpmap: line, e.g.: a=rtpmap:0 PCMU/8000
// Returns the payload type and stores the codec name in dynMap
LOCAL void sdp_parse_rtpmap(const uint8_t *line, int lineLen, SdpPtMap *dynMap, int *dynCount)
{
    if (lineLen < 10 || strncasecmp((char *)line, "a=rtpmap:", 9) != 0)
        return;

    int pos = 9;
    // Skip whitespace
    while (pos < lineLen && line[pos] == ' ') pos++;

    // Parse payload type number
    int pt = 0;
    while (pos < lineLen && isdigit(line[pos])) {
        pt = pt * 10 + (line[pos] - '0');
        pos++;
    }

    if (pos >= lineLen || line[pos] != ' ' || pt > 127 || *dynCount >= SDP_MAX_DYNAMIC_PTS)
        return;

    // Skip space before codec name
    pos++;

    // Extract codec name (up to '/' or end of line)
    int codecStart = pos;
    int codecLen = 0;
    while (pos < lineLen && line[pos] != '/' && line[pos] != '\r' && line[pos] != '\n') {
        codecLen++;
        pos++;
    }

    if (codecLen <= 0 || codecLen >= (int)sizeof(dynMap[0].codec))
        return;

    // Store in dynamic mapping (uppercased)
    dynMap[*dynCount].pt = pt;
    for (int i = 0; i < codecLen; i++) {
        dynMap[*dynCount].codec[i] = toupper(line[codecStart + i]);
    }
    dynMap[*dynCount].codec[codecLen] = '\0';
    (*dynCount)++;
}

/******************************************************************************/
// Parse c= line, e.g.: c=IN IP4 192.168.1.100 or c=IN IP6 ::1
// Returns pointer to IP string in the line, or NULL
LOCAL const char *sdp_parse_connection(const uint8_t *line, int lineLen)
{
    if (lineLen < 10 || line[0] != 'c' || line[1] != '=')
        return NULL;

    // Skip "c=IN IP4 " or "c=IN IP6 "
    // Find "IP" and skip to address
    const char *ipStr = arkime_memcasestr((char *)line, lineLen, "ip", 2);
    if (!ipStr)
        return NULL;

    // Skip "IP" (2 chars), then skip address family (e.g. "4", "6") and spaces
    // e.g. "c=IN IP4 10.0.2.20" → after ipStr+=2 we have "4 10.0.2.20"
    // Need to skip "4" and the space to reach "10.0.2.20"
    ipStr += 2;
    // Skip address family digit(s) and any spaces
    while (ipStr < (char *)line + lineLen && (*ipStr != ' ' && !isalpha(*ipStr))) ipStr++;
    while (ipStr < (char *)line + lineLen && *ipStr == ' ') ipStr++;

    if (ipStr >= (char *)line + lineLen)
        return NULL;

    return ipStr;
}

/******************************************************************************/
// Parse m= line and add RTP fields
// e.g.: m=audio 49170 RTP/AVP 0 8 101
LOCAL void sdp_parse_media(ArkimeSession_t *session, const uint8_t *line, int lineLen,
                           const char *connectionIp, SdpPtMap *dynMap, int dynCount)
{
    if (lineLen < 6 || line[0] != 'm' || line[1] != '=')
        return;

    // Skip "m="
    int pos = 2;
    // Skip whitespace
    while (pos < lineLen && line[pos] == ' ') pos++;

    // Extract media type (audio, video, etc.)
    int mediaStart = pos;
    while (pos < lineLen && line[pos] != ' ') pos++;
    int mediaLen = pos - mediaStart;
    if (mediaLen <= 0) return;

    // Skip space
    while (pos < lineLen && line[pos] == ' ') pos++;

    // Extract port number
    int port = 0;
    while (pos < lineLen && isdigit(line[pos])) {
        port = port * 10 + (line[pos] - '0');
        pos++;
    }

    // Only process if we have a valid port for media (audio/video)
    if (port <= 0) return;

    // Add media type field
    arkime_field_string_add(rtpMediaField, session, (char *)line + mediaStart, mediaLen, TRUE);
    arkime_field_int_add(rtpPortField, session, port);

    // Skip space
    while (pos < lineLen && line[pos] == ' ') pos++;

    // Extract transport protocol (e.g., RTP/AVP, RTP/SAVP, UDP/TLS/RTP/SAVP)
    int transportStart = pos;
    while (pos < lineLen && line[pos] != ' ') pos++;
    int transportLen = pos - transportStart;
    if (transportLen > 0) {
        arkime_field_string_add(rtpTransportField, session, (char *)line + transportStart, transportLen, TRUE);
    }

    // Skip space
    while (pos < lineLen && line[pos] == ' ') pos++;

    // Add connection IP if available (from session-level or media-level c=)
    if (connectionIp && connectionIp[0] != '\0') {
        arkime_field_ip_add_str(rtpIpField, session, connectionIp);
    }

    // Parse payload type numbers and look up codecs
    while (pos < lineLen) {
        int pt = 0;
        while (pos < lineLen && isdigit(line[pos])) {
            pt = pt * 10 + (line[pos] - '0');
            pos++;
        }

        // Look up codec name
        const char *codec = sdp_pt_to_codec(pt, dynMap, dynCount);
        if (codec) {
            arkime_field_string_add(rtpCodecField, session, codec, strlen(codec), TRUE);
        }

        // Skip to next number or end
        while (pos < lineLen && (line[pos] == ' ')) pos++;

        // Skip non-digit (other attributes like profiles)
        while (pos < lineLen && !isdigit(line[pos]) && line[pos] != '\r' && line[pos] != '\n') {
            pos++;
        }
    }

    // Register with RTP bridge table for cross-session codec info propagation
    // Only register if we have a valid connection IP and port
    if (connectionIp && connectionIp[0] != '\0' && port > 0) {
        // Use the first payload type as the representative codec
        int firstPt = 0;
        for (int pi = 0; pi < dynCount; pi++) {
            // Find the first dynamic PT that might be the primary codec
            // or use the first PT from the m= line
        }
        // Get the first PT from m= line by re-parsing
        // m=audio 6000 RTP/AVP 99  → firstPt should be 99, not 6000
        int mPos = 2;
        while (mPos < lineLen && line[mPos] == ' ') mPos++;           // skip "m="
        while (mPos < lineLen && line[mPos] != ' ') mPos++;           // skip media type
        while (mPos < lineLen && line[mPos] == ' ') mPos++;           // skip spaces after media
        while (mPos < lineLen && isdigit(line[mPos])) mPos++;         // skip port number
        while (mPos < lineLen && line[mPos] == ' ') mPos++;           // skip spaces after port
        while (mPos < lineLen && line[mPos] != ' ') mPos++;           // skip transport (RTP/AVP)
        while (mPos < lineLen && line[mPos] == ' ') mPos++;           // skip spaces after transport
        while (mPos < lineLen && isdigit(line[mPos])) {                // parse first PT
            firstPt = firstPt * 10 + (line[mPos] - '0');
            mPos++;
        }

        const char *codecName = sdp_pt_to_codec(firstPt, dynMap, dynCount);
        if (codecName) {
            RtpBridgeInfo_t bridgeInfo;
            memset(&bridgeInfo, 0, sizeof(bridgeInfo));
            memcpy(bridgeInfo.mediaType, (char *)line + mediaStart, mediaLen);
            bridgeInfo.mediaType[mediaLen] = '\0';
            g_strlcpy(bridgeInfo.codec, codecName, sizeof(bridgeInfo.codec));
            bridgeInfo.payloadType = firstPt;
            bridgeInfo.ssrc = 0;

            // Store SIP call ID as session identifier if available
            // callIdField is ARKIME_FIELD_TYPE_STR_GHASH, so value is in ghash
            bridgeInfo.sipSessionId[0] = '\0';
            if (session->fields[callIdField] && session->fields[callIdField]->ghash) {
                GHashTableIter iter;
                gpointer callid_key;
                g_hash_table_iter_init(&iter, session->fields[callIdField]->ghash);
                if (g_hash_table_iter_next(&iter, &callid_key, NULL)) {
                    g_strlcpy(bridgeInfo.sipSessionId, (const char *)callid_key,
                              sizeof(bridgeInfo.sipSessionId));
                    LOG("sip: bridge entry callid='%s' len=%zu",
                        bridgeInfo.sipSessionId, strlen(bridgeInfo.sipSessionId));
                }
            }
            if (bridgeInfo.sipSessionId[0] == '\0') {
                LOG("sip: bridge entry NO callid field!");
            }

            LOG("sip: rtp_bridge_add ip=%s port=%u codec=%s media=%s",
                connectionIp, (uint16_t)port, codecName, bridgeInfo.mediaType);
            rtp_bridge_add(connectionIp, (uint16_t)port, &bridgeInfo);
        }
    }

    // Tag session based on media type
    arkime_session_add_tag(session, "sip:rtp");
    if (mediaLen == 5 && strncasecmp((char *)line + mediaStart, "video", 5) == 0) {
        arkime_session_add_tag(session, "sip:rtp-video");
    } else if (mediaLen == 5 && strncasecmp((char *)line + mediaStart, "audio", 5) == 0) {
        arkime_session_add_tag(session, "sip:rtp-audio");
    }
}

/******************************************************************************/
// Parse SDP body to extract RTP stream and codec information
// Uses two-pass parsing:
//   Pass 1: collect all a=rtpmap: dynamic PT mappings and c= connection IPs
//   Pass 2: process m= lines with fully populated dynMap
// This ensures dynamic payload types (e.g. PT 99=opus) are resolved
// when m= line is processed, since a=rtpmap: appears AFTER m= in SDP.
LOCAL void sip_parse_sdp_body(ArkimeSession_t *session, const uint8_t *data, int len)
{
    LOG("sip: sip_parse_sdp_body called, len=%d", len);

    if (!data || len <= 0) {
        LOG("sip: sip_parse_sdp_body: no data, returning");
        return;
    }

    /* ---- Pass 1: collect all a=rtpmap: entries, c= connection IPs, and m= line positions ---- */
    SdpPtMap dynMap[SDP_MAX_DYNAMIC_PTS];
    int dynCount = 0;
    char connectionIp[64] = "";

    /* Store m= line positions for pass 2: up to 4 media sections */
#define SDP_MAX_MEDIA 4
    struct {
        int  offset;
        int  lineLen;
        char mediaConnectionIp[64];
    } mediaLines[SDP_MAX_MEDIA];
    int mediaCount = 0;

    int offset = 0;
    while (offset < len && mediaCount < SDP_MAX_MEDIA) {
        int lineLen = 0;
        int consumed = sip_find_line(data + offset, len - offset, &lineLen);
        if (consumed < 0)
            break;

        const uint8_t *line = data + offset;

        LOG("sip: pass1 line=[%.*s] consumed=%d lineLen=%d", lineLen, line, consumed, lineLen);

        if (lineLen > 2 && line[0] == 'c' && line[1] == '=') {
            const char *ip = sdp_parse_connection(line, lineLen);
            LOG("sip: c= line, parsed ip=%s", ip ? ip : "(null)");
            if (ip) {
                int ipLen = (char *)data + offset + lineLen - ip;
                if (ipLen > (int)sizeof(connectionIp) - 1)
                    ipLen = sizeof(connectionIp) - 1;
                memcpy(connectionIp, ip, ipLen);
                connectionIp[ipLen] = '\0';
                /* Also update the most recent m= line's media-level connection */
                if (mediaCount > 0) {
                    memcpy(mediaLines[mediaCount - 1].mediaConnectionIp,
                           connectionIp, sizeof(mediaLines[mediaCount - 1].mediaConnectionIp));
                }
            }
        } else if (lineLen > 2 && line[0] == 'm' && line[1] == '=') {
            LOG("sip: m= line found at offset=%d, line=[%.*s]", offset, lineLen, line);
            /* Save m= line for pass 2 */
            mediaLines[mediaCount].offset  = offset;
            mediaLines[mediaCount].lineLen = lineLen;
            memcpy(mediaLines[mediaCount].mediaConnectionIp, connectionIp,
                   sizeof(mediaLines[mediaCount].mediaConnectionIp));
            mediaCount++;
        } else if (lineLen > 9 && strncasecmp((char *)line, "a=rtpmap:", 9) == 0) {
            int oldCount = dynCount;
            sdp_parse_rtpmap(line, lineLen, dynMap, &dynCount);
            LOG("sip: a=rtpmap line, dynCount was %d now %d", oldCount, dynCount);
        }

        offset += consumed;
    }

    LOG("sip: pass1 done: connectionIp=%s mediaCount=%d dynCount=%d", connectionIp, mediaCount, dynCount);

    /* ---- Pass 2: process m= lines with complete dynMap ---- */
    for (int i = 0; i < mediaCount; i++) {
        LOG("sip: pass2 calling sdp_parse_media i=%d offset=%d lineLen=%d connectionIp=%s",
            i, mediaLines[i].offset, mediaLines[i].lineLen,
            mediaLines[i].mediaConnectionIp);
        sdp_parse_media(session,
                        data + mediaLines[i].offset,
                        mediaLines[i].lineLen,
                        mediaLines[i].mediaConnectionIp,
                        dynMap, dynCount);
        LOG("sip: pass2 sdp_parse_media returned for i=%d", i);
    }
    LOG("sip: pass2 done");
}

/******************************************************************************/
// Find end of line, return length including CRLF or -1 if not found
LOCAL int sip_find_line(const uint8_t *data, int len, int *lineLen)
{
    for (int i = 0; i < len; i++) {
        if (data[i] == '\r' && i + 1 < len && data[i + 1] == '\n') {
            *lineLen = i;
            return i + 2;
        }
        if (data[i] == '\n') {
            *lineLen = i;
            return i + 1;
        }
    }
    return -1;
}

/******************************************************************************/
// Extract user part from SIP URI: sip:user@host or "Name" <sip:user@host>
LOCAL void sip_extract_user(ArkimeSession_t *session, const char *value, int valueLen)
{
    // Find sip: or sips:
    const char *sipUri = arkime_memcasestr(value, valueLen, "sip:", 4);
    if (!sipUri) {
        sipUri = arkime_memcasestr(value, valueLen, "sips:", 5);
        if (!sipUri)
            return;
        sipUri += 5;
    } else {
        sipUri += 4;
    }

    int remaining = valueLen - (sipUri - value);
    if (remaining <= 0)
        return;

    // Find @ to get user part
    int userLen = 0;
    for (int i = 0; i < remaining; i++) {
        if (sipUri[i] == '@') {
            userLen = i;
            break;
        }
        if (sipUri[i] == '>' || sipUri[i] == ';' || sipUri[i] == ' ')
            break;
    }

    if (userLen > 0) {
        arkime_field_string_add(userField, session, sipUri, userLen, TRUE);
    }
}

/******************************************************************************/
// Parse SIP header, return Content-Length value if found, -1 otherwise
LOCAL int sip_parse_header(ArkimeSession_t *session, const uint8_t *line, int lineLen)
{
    // Find colon
    int colonPos = -1;
    for (int i = 0; i < lineLen; i++) {
        if (line[i] == ':') {
            colonPos = i;
            break;
        }
    }

    if (colonPos <= 0)
        return -1;

    // Skip whitespace after colon
    int valueStart = colonPos + 1;
    while (valueStart < lineLen && (line[valueStart] == ' ' || line[valueStart] == '\t'))
        valueStart++;

    // Check for empty value
    if (valueStart >= lineLen)
        return -1;

    int valueLen = lineLen - valueStart;

    const char *name = (char *)line;
    const char *value = (char *)line + valueStart;

    // Match headers (including compact forms from RFC 3261)
    if ((colonPos == 7 && strncasecmp(name, "Call-ID", 7) == 0) ||
        (colonPos == 1 && (*name == 'i' || *name == 'I'))) {
        arkime_field_string_add(callIdField, session, value, valueLen, TRUE);
    } else if ((colonPos == 4 && strncasecmp(name, "From", 4) == 0) ||
               (colonPos == 1 && (*name == 'f' || *name == 'F'))) {
        arkime_field_string_add(fromField, session, value, valueLen, TRUE);
        sip_extract_user(session, value, valueLen);
    } else if ((colonPos == 2 && strncasecmp(name, "To", 2) == 0) ||
               (colonPos == 1 && (*name == 't' || *name == 'T'))) {
        arkime_field_string_add(toField, session, value, valueLen, TRUE);
        sip_extract_user(session, value, valueLen);
    } else if (colonPos == 10 && strncasecmp(name, "User-Agent", 10) == 0) {
        arkime_field_string_add(userAgentField, session, value, valueLen, TRUE);
    } else if ((colonPos == 3 && strncasecmp(name, "Via", 3) == 0) ||
               (colonPos == 1 && (*name == 'v' || *name == 'V'))) {
        arkime_field_string_add(viaField, session, value, valueLen, TRUE);
    } else if ((colonPos == 7 && strncasecmp(name, "Contact", 7) == 0) ||
               (colonPos == 1 && (*name == 'm' || *name == 'M'))) {
        arkime_field_string_add(contactField, session, value, valueLen, TRUE);
    } else if (colonPos == 13 && strncasecmp(name, "Authorization", 13) == 0) {
        // Extract username from Digest auth
        const char *userPtr = arkime_memcasestr(value, valueLen, "username=\"", 10);
        if (userPtr) {
            userPtr += 10;
            int remaining = valueLen - (userPtr - value);
            for (int i = 0; i < remaining; i++) {
                if (userPtr[i] == '"') {
                    arkime_field_string_add(userField, session, userPtr, i, TRUE);
                    break;
                }
            }
        }
    } else if ((colonPos == 14 && strncasecmp(name, "Content-Length", 14) == 0) ||
               (colonPos == 1 && (*name == 'l' || *name == 'L'))) {
        return arkime_atoin(value, valueLen);
    }

    return -1;
}

/******************************************************************************/
// Check if valid SIP method, switch on first char for efficiency
LOCAL int sip_is_method(const char *method, int methodLen)
{
    switch (method[0]) {
    case 'A':
        if (methodLen == 3 && memcmp(method, "ACK", 3) == 0)
            return 1;
        break;
    case 'B':
        if (methodLen == 3 && memcmp(method, "BYE", 3) == 0)
            return 1;
        break;
    case 'C':
        if (methodLen == 6 && memcmp(method, "CANCEL", 6) == 0)
            return 1;
        break;
    case 'I':
        if (methodLen == 6 && memcmp(method, "INVITE", 6) == 0)
            return 1;
        if (methodLen == 4 && memcmp(method, "INFO", 4) == 0)
            return 1;
        break;
    case 'M':
        if (methodLen == 7 && memcmp(method, "MESSAGE", 7) == 0)
            return 1;
        break;
    case 'N':
        if (methodLen == 6 && memcmp(method, "NOTIFY", 6) == 0)
            return 1;
        break;
    case 'O':
        if (methodLen == 7 && memcmp(method, "OPTIONS", 7) == 0)
            return 1;
        break;
    case 'P':
        if (methodLen == 5 && memcmp(method, "PRACK", 5) == 0)
            return 1;
        break;
    case 'R':
        if (methodLen == 8 && memcmp(method, "REGISTER", 8) == 0)
            return 1;
        if (methodLen == 5 && memcmp(method, "REFER", 5) == 0)
            return 1;
        break;
    case 'S':
        if (methodLen == 9 && memcmp(method, "SUBSCRIBE", 9) == 0)
            return 1;
        break;
    case 'U':
        if (methodLen == 6 && memcmp(method, "UPDATE", 6) == 0)
            return 1;
        break;
    }
    return 0;
}

/******************************************************************************/
// Parse SIP request line: "METHOD uri SIP/2.0"
LOCAL int sip_parse_request(ArkimeSession_t *session, const uint8_t *line, int lineLen)
{
    // Find first space
    int methodEnd = -1;
    for (int i = 0; i < lineLen && i < 20; i++) {
        if (line[i] == ' ') {
            methodEnd = i;
            break;
        }
    }

    if (methodEnd <= 0)
        return -1;

    const char *method = (char *)line;
    if (!sip_is_method(method, methodEnd))
        return -1;

    // Verify SIP/2.0 at end
    if (lineLen < methodEnd + 10)
        return -1;

    if (!arkime_memstr((char *)line, lineLen, "SIP/2.0", 7))
        return -1;

    arkime_field_string_add(methodField, session, method, methodEnd, TRUE);
    return 0;
}

/******************************************************************************/
// Parse SIP response line: "SIP/2.0 200 OK"
LOCAL int sip_parse_response(ArkimeSession_t *session, const uint8_t *line, int lineLen)
{
    if (lineLen < 12)
        return -1;

    if (memcmp(line, "SIP/2.0 ", 8) != 0)
        return -1;

    int statusCode = arkime_atoin((char *)line + 8, lineLen - 8);
    if (statusCode >= 100 && statusCode < 700) {
        arkime_field_int_add(statusCodeField, session, statusCode);
    }

    return 0;
}

/******************************************************************************/
// Process SIP message headers, return Content-Length (0 if not found), set isResponse
// Also returns headerEnd offset (position after empty line where body starts)
LOCAL int sip_process(ArkimeSession_t *session, const uint8_t *data, int len, int *isResponse, int *headerEnd)
{
    int offset = 0;
    int isFirst = 1;
    int contentLength = 0;
    *isResponse = 0;
    *headerEnd = 0;

    while (offset < len) {
        int lineLen = 0;
        int consumed = sip_find_line(data + offset, len - offset, &lineLen);

        if (consumed < 0)
            break;

        if (lineLen == 0) {
            // Empty line - end of headers, body starts here
            offset += consumed;
            *headerEnd = offset;
            break;
        }

        if (isFirst) {
            isFirst = 0;
            if (lineLen >= 7 && memcmp(data + offset, "SIP/2.0", 7) == 0) {
                sip_parse_response(session, data + offset, lineLen);
                *isResponse = 1;
            } else {
                sip_parse_request(session, data + offset, lineLen);
            }
        } else {
            int cl = sip_parse_header(session, data + offset, lineLen);
            if (cl >= 0)
                contentLength = cl;
        }

        offset += consumed;
    }

    return contentLength;
}

/******************************************************************************/
/* 从原始 SIP 数据中提取 Call-ID 头字段值                                       */
/* 用于 SIP BYE → RTP 会话关闭                                                 */
/******************************************************************************/
LOCAL void sip_extract_callid_from_data(const uint8_t *data, int len, char *callid, int callid_size)
{
    int offset = 0;
    callid[0] = '\0';

    while (offset < len) {
        int lineLen = 0;
        int consumed = sip_find_line(data + offset, len - offset, &lineLen);
        if (consumed < 0)
            break;

        /* 空行 = headers 结束 */
        if (lineLen == 0)
            break;

        const uint8_t *line = data + offset;

        /* 匹配 "Call-ID:"（大小写不敏感） */
        if (lineLen > 8 && strncasecmp((char *)line, "Call-ID:", 8) == 0) {
            int start = 8;
            while (start < lineLen && (line[start] == ' ' || line[start] == '\t'))
                start++;
            int idLen = lineLen - start;
            if (idLen > callid_size - 1)
                idLen = callid_size - 1;
            memcpy(callid, line + start, idLen);
            callid[idLen] = '\0';
            return;
        }
        /* 匹配紧凑形式 "i:" */
        if (lineLen > 1 && (line[0] == 'i' || line[0] == 'I') && line[1] == ':') {
            int start = 2;
            while (start < lineLen && (line[start] == ' ' || line[start] == '\t'))
                start++;
            int idLen = lineLen - start;
            if (idLen > callid_size - 1)
                idLen = callid_size - 1;
            memcpy(callid, line + start, idLen);
            callid[idLen] = '\0';
            return;
        }

        offset += consumed;
    }
}

/******************************************************************************/
/* 检测 SIP 请求是否方法为 BYE                                                  */
/******************************************************************************/
LOCAL int sip_is_bye_request(const uint8_t *data, int len)
{
    /* 检查第一行是否以 "BYE" 开头（后接空格或 CRLF） */
    if (len < 3)
        return 0;
    if (data[0] != 'B' || data[1] != 'Y' || data[2] != 'E')
        return 0;
    /* BYE 后必须是空格或行结束符 */
    if (len > 3 && data[3] != ' ' && data[3] != '\r' && data[3] != '\n')
        return 0;
    return 1;
}

/******************************************************************************/
LOCAL int sip_udp_parser(ArkimeSession_t *session, void *UNUSED(uw), const uint8_t *data, int len, int UNUSED(which))
{
    LOG("sip: sip_udp_parser called, len=%d", len);

    int isResponse;
    int headerEnd;
    int contentLength = sip_process(session, data, len, &isResponse, &headerEnd);

    LOG("sip: sip_process returned contentLength=%d, headerEnd=%d, isResponse=%d",
        contentLength, headerEnd, isResponse);

    /* === 方案B：检测 BYE 并关闭关联 RTP 会话 === */
    if (!isResponse && sip_is_bye_request(data, len)) {
        char callid[128];
        sip_extract_callid_from_data(data, len, callid, sizeof(callid));
        LOG("sip: BYE request detected, Call-ID='%s'", callid);
        if (callid[0]) {
            rtp_bridge_close_by_callid(callid);
        }
    }

    // Parse SDP body if present
    if (contentLength > 0 && headerEnd > 0) {
        int bodyLen = len - headerEnd;
        if (bodyLen > contentLength)
            bodyLen = contentLength;
        LOG("sip: parsing SDP body, bodyLen=%d", bodyLen);
        if (bodyLen > 0) {
            sip_parse_sdp_body(session, data + headerEnd, bodyLen);
        }
    } else {
        LOG("sip: no SDP body (contentLength=%d, headerEnd=%d)", contentLength, headerEnd);
    }

    return 0;
}

/******************************************************************************/
LOCAL int sip_tcp_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int len, int which)
{
    ArkimeParserBuf_t *sip = uw;

    if (arkime_parser_buf_add(sip, which, data, len) < 0) {
        arkime_session_add_tag(session, "sip:headers-too-long");
        return ARKIME_PARSER_UNREGISTER;
    }

    // Find double CRLF to detect end of message headers
    while (sip->len[which] > 4) {
        // Look for end of headers
        int endPos = -1;
        for (int i = 0; i < sip->len[which] - 3; i++) {
            if (sip->buf[which][i] == '\r' && sip->buf[which][i + 1] == '\n' &&
                sip->buf[which][i + 2] == '\r' && sip->buf[which][i + 3] == '\n') {
                endPos = i + 4;
                break;
            }
        }

        if (endPos < 0) {
            // No header terminator yet; if the buffer is full it never will fit
            if (sip->len[which] >= sip->bufMax) {
                arkime_session_add_tag(session, "sip:headers-too-long");
                return ARKIME_PARSER_UNREGISTER;
            }
            break;
        }

        int isResponse = 0;
        int headerEnd = 0;
        int contentLength = sip_process(session, sip->buf[which], endPos, &isResponse, &headerEnd);

        // Track serverWhich - server sends responses
        if (isResponse) {
            sip->serverWhich = which;
        }

        // Parse SDP body before deleting headers/skipping body
        if (contentLength > 0 && headerEnd > 0) {
            int bodyStart = headerEnd;
            int bodyAvail = sip->len[which] - bodyStart;
            int bodyLen = bodyAvail < contentLength ? bodyAvail : contentLength;
            if (bodyLen > 0) {
                sip_parse_sdp_body(session, sip->buf[which] + bodyStart, bodyLen);
            }
        }

        /* === 方案B：检测 BYE 并关闭关联 RTP 会话 === */
        if (!isResponse) {
            /* 检查缓冲消息的第一行是否为 "BYE" */
            if (sip_is_bye_request(sip->buf[which], endPos)) {
                char callid[128];
                sip_extract_callid_from_data(sip->buf[which], endPos, callid, sizeof(callid));
                LOG("sip-tcp: BYE request detected, Call-ID='%s'", callid);
                if (callid[0]) {
                    rtp_bridge_close_by_callid(callid);
                }
            }
        }

        // Delete headers
        arkime_parser_buf_del(sip, which, endPos);

        // Skip body if present
        if (contentLength > 0) {
            arkime_parser_buf_skip(sip, which, contentLength);
        }
    }

    // Limit parsing
    sip->version++;
    if (sip->version > 200) {
        return ARKIME_PARSER_UNREGISTER;
    }

    return 0;
}

/******************************************************************************/
LOCAL void sip_udp_classify(ArkimeSession_t *session, const uint8_t *data, int len, int UNUSED(which), void *UNUSED(uw))
{
    LOG("sip: sip_udp_classify called, len=%d", len);

    if (arkime_session_has_protocol(session, "sip")) {
        LOG("sip: already has sip protocol, returning");
        return;
    }

    if (len < 12) {
        LOG("sip: len < 12, returning");
        return;
    }

    // Verify SIP/2.0 present
    if (!arkime_memstr((char *)data, MIN(len, 200), "SIP/2.0", 7)) {
        LOG("sip: SIP/2.0 not found in first %d bytes: %.*s", MIN(len, 200), MIN(len, 50), data);
        return;
    }

    LOG("sip: SIP/2.0 found, classifying as sip");
    arkime_session_add_protocol(session, "sip");
    arkime_parsers_register(session, sip_udp_parser, NULL, NULL);
}

/******************************************************************************/
LOCAL void sip_tcp_classify(ArkimeSession_t *session, const uint8_t *data, int len, int UNUSED(which), void *UNUSED(uw))
{
    if (arkime_session_has_protocol(session, "sip"))
        return;

    if (len < 12)
        return;

    // Verify SIP/2.0 present
    if (!arkime_memstr((char *)data, MIN(len, 200), "SIP/2.0", 7))
        return;

    arkime_session_add_protocol(session, "sip");

    ArkimeParserBuf_t *sip = arkime_parser_buf_create();
    arkime_parsers_register(session, sip_tcp_parser, sip, arkime_parser_buf_session_free);
}

/******************************************************************************/
void arkime_parser_init()
{
    methodField = arkime_field_define("sip", "termfield",
                                      "sip.method", "Method", "sip.method",
                                      "SIP method (INVITE, BYE, REGISTER, etc.)",
                                      ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    statusCodeField = arkime_field_define("sip", "integer",
                                          "sip.statuscode", "Status Code", "sip.statuscode",
                                          "SIP response status codes",
                                          ARKIME_FIELD_TYPE_INT_GHASH, ARKIME_FIELD_FLAG_CNT,
                                          (char *)NULL);

    callIdField = arkime_field_define("sip", "termfield",
                                      "sip.callid", "Call ID", "sip.callid",
                                      "SIP Call-ID header",
                                      ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    fromField = arkime_field_define("sip", "termfield",
                                    "sip.from", "From", "sip.from",
                                    "SIP From header",
                                    ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    toField = arkime_field_define("sip", "termfield",
                                  "sip.to", "To", "sip.to",
                                  "SIP To header",
                                  ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                  (char *)NULL);

    userAgentField = arkime_field_define("sip", "termfield",
                                         "sip.user-agent", "User-Agent", "sip.useragent",
                                         "SIP User-Agent header",
                                         ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                         (char *)NULL);

    viaField = arkime_field_define("sip", "termfield",
                                   "sip.via", "Via", "sip.via",
                                   "SIP Via headers",
                                   ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                   (char *)NULL);

    contactField = arkime_field_define("sip", "termfield",
                                       "sip.contact", "Contact", "sip.contact",
                                       "SIP Contact header",
                                       ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                       (char *)NULL);

    userField = arkime_field_define("sip", "termfield",
                                     "sip.user", "User", "sip.user",
                                     "SIP user from URI or auth",
                                     ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                     "category", "user",
                                     (char *)NULL);

    rtpMediaField = arkime_field_define("sip", "termfield",
                                        "sip.rtp.media", "RTP Media Type", "sip.rtp.media",
                                        "SDP media type (audio, video, etc.)",
                                        ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                        (char *)NULL);

    rtpPortField = arkime_field_define("sip", "integer",
                                        "sip.rtp.port", "RTP Port", "sip.rtp.port",
                                        "RTP destination port from SDP",
                                        ARKIME_FIELD_TYPE_INT_GHASH, ARKIME_FIELD_FLAG_CNT,
                                        (char *)NULL);

    rtpCodecField = arkime_field_define("sip", "termfield",
                                         "sip.rtp.codec", "RTP Codec", "sip.rtp.codec",
                                         "RTP codec name (PCMU, H264, Opus, etc.)",
                                         ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                         (char *)NULL);

    rtpTransportField = arkime_field_define("sip", "termfield",
                                             "sip.rtp.transport", "RTP Transport", "sip.rtp.transport",
                                             "RTP transport protocol (RTP/AVP, RTP/SAVP, etc.)",
                                             ARKIME_FIELD_TYPE_STR_GHASH, ARKIME_FIELD_FLAG_CNT,
                                             (char *)NULL);

    rtpIpField = arkime_field_define("sip", "ip",
                                      "sip.rtp.ip", "RTP IP", "sip.rtp.ip",
                                      "RTP destination IP from SDP connection info",
                                      ARKIME_FIELD_TYPE_IP, ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    // UDP classifiers
    arkime_parsers_classifier_register_udp("sip", NULL, 0, (uint8_t *)"SIP/2.0", 7, sip_udp_classify);
    arkime_parsers_classifier_register_udp("sip", NULL, 0, (uint8_t *)"INVITE sip:", 11, sip_udp_classify);
    arkime_parsers_classifier_register_udp("sip", NULL, 0, (uint8_t *)"REGISTER sip:", 13, sip_udp_classify);
    arkime_parsers_classifier_register_udp("sip", NULL, 0, (uint8_t *)"OPTIONS sip:", 12, sip_udp_classify);
    arkime_parsers_classifier_register_udp("sip", NULL, 0, (uint8_t *)"NOTIFY sip:", 11, sip_udp_classify);

    // TCP classifiers
    arkime_parsers_classifier_register_tcp("sip", NULL, 0, (uint8_t *)"SIP/2.0", 7, sip_tcp_classify);
    arkime_parsers_classifier_register_tcp("sip", NULL, 0, (uint8_t *)"INVITE sip:", 11, sip_tcp_classify);
    arkime_parsers_classifier_register_tcp("sip", NULL, 0, (uint8_t *)"REGISTER sip:", 13, sip_tcp_classify);
    arkime_parsers_classifier_register_tcp("sip", NULL, 0, (uint8_t *)"NOTIFY sip:", 11, sip_tcp_classify);
}
