# Plan: POP3 File/Restore - Capture and Store Email Body Content

## Objective

Enhance the existing POP3 parser ([`capture/parsers/pop3.c`](capture/parsers/pop3.c)) to capture the email body content transferred via the POP3 `RETR` command and store it as a file on disk, similar to how the HTTP parser saves HTTP bodies.

## Background

The current POP3 parser is minimal - it only captures the USER name and decodes NTLMSSP blobs. POP3 is used to retrieve emails from a mail server. The key command for file transfer is:

- **`RETR <msg>`** - The server responds with the full email message (headers + body), terminated by `\r\n.\r\n` (CRLF.CRLF).

The email body may contain MIME-encoded attachments, but per the user's clarification, we only need to capture the raw email body content as a file, **without** full MIME parsing.

## Protocol Flow

```
Client: RETR 1
Server: +OK message follows
Server: <email headers and body, line by line>
Server: .                 <-- end of message marker
```

The message is terminated by a line containing only a single dot (`\r\n.\r\n`).

## Implementation Plan

### 1. Add New Fields to [`capture/parsers/pop3.c`](capture/parsers/pop3.c)

Define the following fields in `arkime_parser_init()`:

| Field Name | DB Name | Type | Description |
|---|---|---|---|
| `pop3.bodyfile` | `pop3.bodyFile` | STR_HASH | Path to saved email body file |
| `pop3.body.bodymagic` | `pop3.bodyMagic` | STR_HASH | libmagic content type of body |
| `pop3.body.md5` | `pop3.bodyMd5` | STR_HASH | MD5 hash of body content |
| `pop3.body.sha256` | `pop3.bodySha256` | STR_HASH | SHA256 hash of body content (if `config.supportSha256`) |

### 2. Extend [`POP3Info_t`](capture/parsers/pop3.c:11) Struct

Add new fields to track RETR state and body data:

```c
typedef struct {
    GString  *line[2];
    uint8_t   serverWhich;
    uint8_t   inNtlmAuth;
    uint8_t   ntlmCount;
    uint8_t   done;
    
    // NEW FIELDS:
    uint8_t   inRetr;           // Currently inside a RETR response
    uint8_t   seenRetrCmd;      // Client issued RETR command
    FILE     *bodyFile;         // File handle for writing body content
    GChecksum *checksum[2];     // [0]=MD5, [1]=SHA256
    uint32_t  bodyCount;        // Counter for multiple RETRs
    gboolean  firstBodyChunk;   // Track first chunk for magic detection
} POP3Info_t;
```

### 3. Modify [`pop3_process_line()`](capture/parsers/pop3.c:20) - Add RETR Command Detection

In the client command processing section, add detection of the `RETR` command:

```c
/* Client: "RETR <msg>" */
if (which != pop3->serverWhich && len > 5 &&
    strncasecmp(line, "RETR ", 5) == 0) {
    pop3->seenRetrCmd = 1;
    return;
}
```

### 4. Modify [`pop3_process_line()`](capture/parsers/pop3.c:20) - Add Server Response Handling

Add handling for the server's RETR response:

```c
/* Server: "+OK message follows" - start of RETR response */
if (which == pop3->serverWhich && pop3->seenRetrCmd && !pop3->inRetr) {
    if (len > 3 && strncasecmp(line, "+OK", 3) == 0) {
        pop3->inRetr = 1;
        pop3->seenRetrCmd = 0;
        pop3->firstBodyChunk = TRUE;
        return;
    }
}

/* Server: "." on a line by itself - end of RETR response */
if (which == pop3->serverWhich && pop3->inRetr) {
    if (len == 1 && line[0] == '.') {
        // End of message - close file, compute hashes
        if (pop3->bodyFile) {
            fclose(pop3->bodyFile);
            pop3->bodyFile = NULL;
        }
        pop3->inRetr = 0;
        return;
    }
    
    // Handle dot-stuffing: lines starting with ".." become "."
    const char *bodyData = line;
    int bodyLen = len;
    if (len > 0 && line[0] == '.') {
        bodyData = line + 1;
        bodyLen = len - 1;
    }
    
    // Write body content to file
    if (bodyLen > 0 && config.httpBodySave) {
        if (!pop3->bodyFile) {
            char idBuf[256];
            char path[512];
            arkime_session_id_string(session->sessionId, idBuf);
            snprintf(path, sizeof(path), "%s/%s_pop3_%u.eml",
                     config.contentSavePath, idBuf, pop3->bodyCount++);
            pop3->bodyFile = fopen(path, "wb");
            if (pop3->bodyFile) {
                arkime_field_string_add(bodyFileField, session, path, -1, TRUE);
            }
        }
        if (pop3->bodyFile) {
            fwrite(bodyData, 1, bodyLen, pop3->bodyFile);
            // Add newline that was stripped by line parsing
            fwrite("\n", 1, 1, pop3->bodyFile);
        }
    }
    
    // Update checksums
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
```

### 5. Modify [`pop3_free()`](capture/parsers/pop3.c:111) - Clean Up New Resources

```c
LOCAL void pop3_free(ArkimeSession_t UNUSED(*session), void *uw)
{
    POP3Info_t *pop3 = uw;
    g_string_free(pop3->line[0], TRUE);
    g_string_free(pop3->line[1], TRUE);
    
    // NEW: Close file if still open
    if (pop3->bodyFile)
        fclose(pop3->bodyFile);
    
    // NEW: Free checksums
    g_checksum_free(pop3->checksum[0]);
    if (config.supportSha256)
        g_checksum_free(pop3->checksum[1]);
    
    ARKIME_TYPE_FREE(POP3Info_t, pop3);
}
```

### 6. Add Save Function

Register a save function via `arkime_parsers_register2()` to compute and store hashes on session finalization:

```c
LOCAL void pop3_save(ArkimeSession_t *session, void *uw, int final)
{
    POP3Info_t *pop3 = uw;
    if (!final)
        return;
    
    // Store MD5 hash
    if (pop3->bodyCount > 0) {
        const char *md5 = g_checksum_get_string(pop3->checksum[0]);
        arkime_field_string_add(md5Field, session, (char *)md5, 32, TRUE);
        
        if (config.supportSha256) {
            const char *sha256 = g_checksum_get_string(pop3->checksum[1]);
            arkime_field_string_add(sha256Field, session, (char *)sha256, 64, TRUE);
        }
    }
}
```

### 7. Modify [`pop3_classify()`](capture/parsers/pop3.c:119) - Initialize New Fields and Register Save

```c
POP3Info_t *pop3 = ARKIME_TYPE_ALLOC0(POP3Info_t);
pop3->line[0] = g_string_sized_new(256);
pop3->line[1] = g_string_sized_new(256);
pop3->serverWhich = which;

// NEW: Initialize checksums
pop3->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
if (config.supportSha256)
    pop3->checksum[1] = g_checksum_new(G_CHECKSUM_SHA256);

// NEW: Use register2 to include save function
arkime_parsers_register2(session, pop3_parser, pop3, pop3_free, pop3_save);
```

### 8. Modify [`arkime_parser_init()`](capture/parsers/pop3.c:144) - Define New Fields

```c
void arkime_parser_init()
{
    // Existing field
    userField = arkime_field_define("pop3", "lotermfield",
                                    "pop3.user", "User", "pop3.user",
                                    "POP3 username",
                                    ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);
    
    // NEW fields
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
```

### 9. Add Detail View Template

Create [`capture/parsers/pop3.detail.jade`](capture/parsers/pop3.detail.jade) to display the captured data in the Arkime UI:

```jade
if (session.pop3)
  div.sessionDetailMeta.bold POP3
  dl.sessionDetailMeta(suffix="pop3")
    +arrayList(session.pop3, 'user', "Users", "pop3.user")
    +arrayList(session.pop3, 'bodyFile', "Body Files", "pop3.bodyfile")
    +arrayList(session.pop3, 'bodyMagic', "Body Magic", "pop3.bodymagic")
    +arrayList(session.pop3, 'bodyMd5', "Body MD5s", "pop3.body.md5", null, null, session)
    if (session.pop3.bodySha256)
      +arrayList(session.pop3, 'bodySha256', "Body SHA256s", "pop3.body.sha256", null, null, session)
```

## Key Design Decisions

1. **Reuse `config.httpBodySave` and `config.contentSavePath`**: Rather than introducing new POP3-specific config options, we reuse the existing HTTP body save mechanism. This means POP3 body saving is enabled/disabled alongside HTTP body saving.

2. **Dot-stuffing handling**: POP3 uses dot-stuffing - lines starting with `.` have an extra `.` prepended. The parser strips this during capture.

3. **No MIME parsing**: Per user request, we capture the raw email body without parsing MIME boundaries or decoding base64 attachments. The raw email text (headers + body) is saved as-is.

4. **File naming convention**: Files are named `<sessionId>_pop3_<count>.body` to distinguish from HTTP body files.

5. **Save function for hashes**: MD5 and SHA256 hashes are computed incrementally during body capture and stored in the save callback (when `final=1`), following the same pattern as HTTP/SMTP parsers.

## Files to Modify

| File | Change |
|---|---|
| [`capture/parsers/pop3.c`](capture/parsers/pop3.c) | Main implementation changes |
| [`capture/parsers/pop3.detail.jade`](capture/parsers/pop3.detail.jade) | New file - UI detail view template |

## Testing Considerations

1. Test with POP3 traffic containing `RETR` commands
2. Verify body files are created in `contentSavePath`
3. Verify MD5/SHA256 hashes are stored correctly
4. Verify dot-stuffing is properly handled
5. Verify multiple RETR commands in the same session work
6. Verify backward compatibility - existing USER/NTLM parsing should be unaffected
