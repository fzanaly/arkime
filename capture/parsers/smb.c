/* Copyright 2012-2017 AOL Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "arkime.h"

extern ArkimeConfig_t   config;

LOCAL  int domainField;
LOCAL  int userField;
LOCAL  int hostField;
LOCAL  int osField;
LOCAL  int verField;
LOCAL  int fnField;
LOCAL  int shareField;
LOCAL  int dialectField;
LOCAL  int fileField;        /* smb.file - reconstructed file reference */

#define MAX_SMB_BUFFER 8192
/* 安全 remlen 减法宏：防止 uint32_t 整数下溢 */
#define SMB_REMLEN_SUB(remlen_ptr, start_ptr, bsb_val) do { \
    uint32_t _consumed = BSB_WORK_PTR(bsb_val) - (const uint8_t *)(start_ptr); \
    *(remlen_ptr) = (_consumed >= *(remlen_ptr)) ? 0 : *(remlen_ptr) - _consumed; \
} while(0)

#define MAX_SMB1_DIALECTS 10
#define MAX_SMB_FILES    32
/* 单次传输的文件数据临时缓冲区大小 (128KB) */
#define SMB_FILE_BUF_SIZE 131072

typedef struct {
    uint16_t fid;             /* SMB1 FID / SMB2 Handle 低16位 */
    uint64_t persistentHandle;/* SMB2 完整 64-bit Persistent Handle (0 表示未使用) */
    uint64_t writeOffset;     /* 写操作的下一个期望文件偏移 (仅用于 Write 方向) */
    char     filename[1024];  /* 文件路径名 */
    uint8_t *data;            /* 累积的文件数据 */
    uint32_t dataLen;         /* 当前数据长度 */
    uint32_t dataAlloc;       /* 分配缓冲区大小 */
    int      used;            /* 槽位是否在用 */
} SMBFileInfo_t;

typedef struct {
    char               buf[2][MAX_SMB_BUFFER];
    uint32_t           remlen[2];
    short              buflen[2];
    uint16_t           flags2[2];
    uint8_t            version[2];
    char               state[2];
    char              *dialects[MAX_SMB1_DIALECTS];
    uint8_t            dialectsLen;
    /* 文件传输跟踪 */
    SMBFileInfo_t      files[MAX_SMB_FILES];
    /* 用于跨 which 方向传递文件名: pendingFilename[dir][...] */
    char               pendingFilename[2][1024];
    int                pendingFilenameLen[2];
    /* SMB2 文件句柄 -> 文件名映射 */
    uint64_t           smb2FileHandle[MAX_SMB_FILES]; /* Persistent handle */
    char               smb2FileName[MAX_SMB_FILES][1024];
    int                smb2FileCount;
    /* Read Request 跟踪 - 用于将 Read Response 数据关联到正确文件 */
    uint64_t           smb2ReadFileHandle;  /* SMB2 当前读操作的文件句柄 */
    uint64_t           smb2ReadReqOffset;   /* SMB2 Read Request 的文件偏移 */
    uint32_t           smb2ReadReqLength;   /* SMB2 Read Request 请求的数据长度 */
    uint16_t           smb1ReadFid;         /* SMB1 当前读操作的 FID */
    int                hasPendingRead;      /* 是否有待处理的 Read Request */
    /* Read Response 数据流式传输跟踪 */
    uint64_t           smb2ReadRspHandle;   /* 当前 Read Response 的文件句柄 */
    uint32_t           smb2ReadRspRemaining;/* Read Response 剩余数据字节数 */
    uint64_t           smb2ReadRspOffset;   /* Read Response 数据的文件偏移 */
    int                smb2ReadRspActive;   /* 是否正在处理 Read Response 数据 */
} SMBInfo_t;

// States
#define SMB_NETBIOS             0
#define SMB_SMBHEADER           1
#define SMB_SKIP                2
#define SMB1_TREE_CONNECT_ANDX 10
#define SMB1_DELETE            11
#define SMB1_OPEN_ANDX         12
#define SMB1_CREATE_ANDX       13
#define SMB1_SETUP_ANDX        14
#define SMB1_NEGOTIATE_REQ     15
#define SMB1_NEGOTIATE_RSP     16

#define SMB2_TREE_CONNECT      20
#define SMB2_CREATE            21
#define SMB2_NEGOTIATE         22

/* 新增 SMB1 文件传输状态 */
#define SMB1_OPEN_ANDX_RSP     17
#define SMB1_READ_ANDX         30
#define SMB1_WRITE_ANDX        31
#define SMB1_CLOSE             32

/* 新增 SMB2 文件传输状态 */
#define SMB2_CREATE_RSP        23
#define SMB2_READ              40
#define SMB2_WRITE             41
#define SMB2_CLOSE             42
#define SMB2_READ_RSP_DATA     43

// SMB1 Flags
#define SMB1_FLAGS_REPLY       0x80
#define SMB1_FLAGS2_UNICODE    0x8000

// SMB2 Flags
#define SMB2_FLAGS_SERVER_TO_REDIR 0x00000001

/******************************************************************************/
/* 查找或分配一个文件跟踪槽位 (SMB1: 按 FID) */
LOCAL SMBFileInfo_t *smb_find_file_by_fid(SMBInfo_t *smb, uint16_t fid)
{
    for (int i = 0; i < MAX_SMB_FILES; i++) {
        if (smb->files[i].used && smb->files[i].fid == fid)
            return &smb->files[i];
    }
    return NULL;
}

/* 分配一个新的文件跟踪槽位 (SMB1) */
LOCAL SMBFileInfo_t *smb_alloc_file_slot(SMBInfo_t *smb)
{
    for (int i = 0; i < MAX_SMB_FILES; i++) {
        if (!smb->files[i].used) {
            memset(&smb->files[i], 0, sizeof(SMBFileInfo_t));
            smb->files[i].used = 1;
            return &smb->files[i];
        }
    }
    return NULL;
}

/* 向文件槽追加数据 */
LOCAL int smb_append_file_data(SMBFileInfo_t *file, const uint8_t *data, uint32_t len)
{
    if (!file || !data || len == 0)
        return 0;

    if (file->dataLen + len > file->dataAlloc) {
        uint32_t newAlloc = file->dataAlloc ? file->dataAlloc * 2 : SMB_FILE_BUF_SIZE;
        while (file->dataLen + len > newAlloc)
            newAlloc *= 2;
        uint8_t *newData = g_realloc(file->data, newAlloc);
        if (!newData)
            return -1;
        file->data = newData;
        file->dataAlloc = newAlloc;
    }

    memcpy(file->data + file->dataLen, data, len);
    file->dataLen += len;
    return 0;
}

/* 释放文件槽 */
LOCAL void smb_free_file_slot(SMBFileInfo_t *file)
{
    if (file && file->data) {
        g_free(file->data);
        file->data = NULL;
    }
    if (file)
        memset(file, 0, sizeof(SMBFileInfo_t));
}

/* 按 SMB2 完整 64-bit Persistent Handle 查找文件槽 */
LOCAL SMBFileInfo_t *smb_find_file_by_persistent_handle(SMBInfo_t *smb, uint64_t handle)
{
    if (handle == 0)
        return NULL;
    for (int i = 0; i < MAX_SMB_FILES; i++) {
        if (smb->files[i].used && smb->files[i].persistentHandle == handle)
            return &smb->files[i];
    }
    return NULL;
}

/* 按文件偏移插入/追加数据，正确处理非顺序写入 */
/* 返回 0 成功, -1 失败 */
LOCAL int smb_write_file_data_at_offset(SMBFileInfo_t *file, const uint8_t *data, uint32_t len, uint64_t offset)
{
    if (!file || !data || len == 0)
        return 0;

    uint64_t endOffset = offset + len;
    if (endOffset > UINT32_MAX) {
        /* 单个文件超过 4GB 限制，不太可能 */
        return -1;
    }

    /* 确保缓冲区足够大 */
    if (endOffset > file->dataAlloc) {
        uint32_t newAlloc = file->dataAlloc ? file->dataAlloc * 2 : SMB_FILE_BUF_SIZE;
        while (endOffset > newAlloc)
            newAlloc *= 2;
        uint8_t *newData = g_realloc(file->data, newAlloc);
        if (!newData)
            return -1;
        file->data = newData;
        file->dataAlloc = newAlloc;
    }

    /* 如果 offset > dataLen，用零填充空洞 */
    if (offset > file->dataLen) {
        memset(file->data + file->dataLen, 0, offset - file->dataLen);
    }

    memcpy(file->data + offset, data, len);

    /* 更新 dataLen 为文件实际最大长度 */
    if (endOffset > file->dataLen)
        file->dataLen = endOffset;

    return 0;
}

/* 基于魔数(magic bytes)检测文件类型并返回标准扩展名 */
/* 返回的字符串是静态存储，不需要释放；返回 NULL 表示无法识别 */
LOCAL const char *smb_detect_file_extension(const uint8_t *data, uint32_t dataLen)
{
    if (!data || dataLen < 4)
        return NULL;

    /* PDF: %PDF */
    if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46)
        return ".pdf";

    /* ZIP/DOCX/XLSX/PPTX/JAR: PK\x03\x04 */
    if (data[0] == 0x50 && data[1] == 0x4B) {
        if (dataLen >= 6 && data[2] == 0x03 && data[3] == 0x04)
            return ".zip";
        if (data[2] == 0x05 && data[3] == 0x06)
            return ".zip";
        if (data[2] == 0x07 && data[3] == 0x08)
            return ".zip";
    }

    /* JPEG: \xFF\xD8\xFF */
    if (dataLen >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
        return ".jpg";

    /* PNG: \x89PNG */
    if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
        return ".png";

    /* GIF87a / GIF89a */
    if (dataLen >= 6 && data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 &&
        data[3] == 0x38 && (data[4] == 0x37 || data[4] == 0x39) && data[5] == 0x61)
        return ".gif";

    /* ELF: \x7FELF */
    if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46)
        return ".elf";

    /* PE/DOS executable: MZ */
    if (data[0] == 0x4D && data[1] == 0x5A)
        return ".exe";

    /* RTF: {\rtf */
    if (dataLen >= 5 && data[0] == 0x7B && data[1] == 0x5C && data[2] == 0x72 &&
        data[3] == 0x74 && data[4] == 0x66)
        return ".rtf";

    /* HTML: <html, <!DOCTYPE, <HTML, <!doctype */
    if (dataLen >= 5) {
        if ((data[0] == '<' && data[1] == 'h' && data[2] == 't' && data[3] == 'm' && data[4] == 'l') ||
            (data[0] == '<' && data[1] == 'H' && data[2] == 'T' && data[3] == 'M' && data[4] == 'L') ||
            (data[0] == '<' && data[1] == '!' && (data[2] == 'D' || data[2] == 'd') &&
             (data[3] == 'O' || data[3] == 'o') && (data[4] == 'C' || data[4] == 'c')))
            return ".html";
    }

    /* XML: <?xml */
    if (dataLen >= 5 && data[0] == '<' && data[1] == '?' && data[2] == 'x' &&
        data[3] == 'm' && data[4] == 'l')
        return ".xml";

    /* GZip: \x1F\x8B */
    if (data[0] == 0x1F && data[1] == 0x8B)
        return ".gz";

    /* BZip2: BZ (42 5A) */
    if (data[0] == 0x42 && data[1] == 0x5A)
        return ".bz2";

    /* 7z: 7z\xBC\xAF\x27\x1C */
    if (dataLen >= 6 && data[0] == 0x37 && data[1] == 0x7A && data[2] == 0xBC &&
        data[3] == 0xAF && data[4] == 0x27 && data[5] == 0x1C)
        return ".7z";

    /* OLE2 (旧版 Office .doc/.xls/.ppt): D0 CF 11 E0 A1 B1 1A E1 */
    if (dataLen >= 8 &&
        data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0 &&
        data[4] == 0xA1 && data[5] == 0xB1 && data[6] == 0x1A && data[7] == 0xE1)
        return ".ole";

    /* BMP: BM */
    if (data[0] == 0x42 && data[1] == 0x4D)
        return ".bmp";

    /* TIFF LE: II\x2A\x00 */
    if (data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00)
        return ".tiff";

    /* TIFF BE: MM\x00\x2A */
    if (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A)
        return ".tiff";

    /* MP3 ID3 tag: ID3 */
    if (dataLen >= 3 && data[0] == 0x49 && data[1] == 0x44 && data[2] == 0x33)
        return ".mp3";

    /* FLAC: fLaC */
    if (data[0] == 0x66 && data[1] == 0x4C && data[2] == 0x61 && data[3] == 0x43)
        return ".flac";

    /* WAV: RIFF....WAVE (at offset 8) */
    if (dataLen >= 12 &&
        data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
        data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45)
        return ".wav";

    /* AVI: RIFF....AVI  */
    if (dataLen >= 12 &&
        data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
        data[8] == 0x41 && data[9] == 0x56 && data[10] == 0x49 && data[11] == 0x20)
        return ".avi";

    return NULL;
}


/* 保存重建的文件到磁盘 */
LOCAL void smb_save_file(ArkimeSession_t *session, SMBFileInfo_t *file)
{
    if (!file || !file->used || file->dataLen == 0 || file->filename[0] == '\0')
        return;

    /* 从路径中提取文件名 */
    const char *base = strrchr(file->filename, '\\');
    if (!base)
        base = strrchr(file->filename, '/');
    if (!base)
        base = file->filename;
    else
        base++; /* skip the separator */

    /* 清理文件名中非法字符 */
    char safe_name[256];
    int j = 0;
    for (int i = 0; base[i] && j < (int)sizeof(safe_name) - 1; i++) {
        char c = base[i];
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
            c == '<' || c == '>' || c == '|' || c == '\"')
            c = '_';
        safe_name[j++] = c;
    }
    safe_name[j] = '\0';

    if (safe_name[0] == '\0')
        return;

    /* 基于魔数检测文件扩展名 */
    const char *ext = smb_detect_file_extension(file->data, file->dataLen);

    /* 生成 Arkime 文件管理的文件名 */
    const char *save_dir = config.contentSavePath ? config.contentSavePath : "/tmp";
    char file_tag[512];
    if (ext) {
        snprintf(file_tag, sizeof(file_tag), "smb-%s%s", safe_name, ext);
    } else {
        snprintf(file_tag, sizeof(file_tag), "smb-%s", safe_name);
    }
    
    char full_path[1024];
    int path_len = snprintf(full_path, sizeof(full_path), "%s/%s", save_dir, file_tag);
    if (path_len >= (int)sizeof(full_path))
        return;

    LOG("smb: saving file '%s' (%u bytes) to %s", safe_name, file->dataLen, full_path);

    /* 写入文件 */
    FILE *fp = fopen(full_path, "wb");
    if (!fp) {
        LOG("smb: ERROR - could not open %s for writing: %s", full_path, strerror(errno));
        return;
    }

    size_t written = fwrite(file->data, 1, file->dataLen, fp);
    fclose(fp);

    if (written != file->dataLen) {
        LOG("smb: WARNING - wrote %zu/%u bytes to %s", written, file->dataLen, full_path);
        /* 仍然继续，即使只写了部分数据 */
    }

    /* 非 dryrun 模式下注册到 Elasticsearch */
    if (!config.dryRun) {
        uint32_t file_id = 0;
        struct timeval tv = {0, 0};
        char *es_name = arkime_db_create_file_full(&tv, file_tag, file->dataLen, 0, &file_id, NULL);
        if (es_name) {
            arkime_field_string_add(fileField, session, es_name, -1, TRUE);
        } else {
            LOG("smb: arkime_db_create_file_full failed for %s", file_tag);
        }
    } else {
        /* dryrun 模式下仍然记录文件字段 */
        arkime_field_string_add(fileField, session, file_tag, -1, TRUE);
    }
}
/******************************************************************************/
LOCAL void smb_add_string(ArkimeSession_t *session, int field, const char *buf, int len, int useunicode)
{
    if (len == 0)
        return;

    GError *error = 0;
    gsize bread, bwritten;

    if (useunicode) {
        char *out = g_convert(buf, len, "utf-8", "ucs-2le", &bread, &bwritten, &error);
        if (error) {
            if (config.debug)
                LOG("ERROR %s", error->message);
            g_error_free(error);
        } else {
            if (!arkime_field_string_add(field, session, out, -1, FALSE)) {
                g_free(out);
            }
        }
    } else {
        arkime_field_string_add(field, session, buf, len, TRUE);
    }
}
/******************************************************************************/
// 2.2.13 AUTHENTICATE_MESSAGE from  http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-NLMP].pdf
LOCAL void smb_security_blob(ArkimeSession_t *session, uint8_t *data, int len)
{
    BSB bsb;

    /* Some clients put raw NTLMSSP directly in the SMB security blob (no
     * GSS-API/SPNEGO wrapping); detect and dispatch to the shared decoder. */
    if (len >= 8 && memcmp(data, "NTLMSSP\0", 8) == 0) {
        arkime_parsers_ntlm_decode(session, data, len);
        return;
    }

    BSB_INIT(bsb, data, len);

    uint32_t apc, atag, alen;
    uint8_t *value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen);

    if (!value || atag != 1)
        return;

    BSB_INIT(bsb, value, alen);
    value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen);

    if (!value || atag != 16)
        return;

    BSB_INIT(bsb, value, alen);
    value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen);
    if (!value || atag != 2)
        return;

    BSB_INIT(bsb, value, alen);
    value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen);

    if (!value || atag != 4 || alen < 7 || memcmp("NTLMSSP", value, 7) != 0)
        return;

    /* Also feed the full NTLMSSP blob to the shared decoder so user/host/domain
     * land in the global ntlm.* fields alongside the legacy smb.* fields. */
    arkime_parsers_ntlm_decode(session, value, alen);

    /* Woot, have the part we need to decode */
    BSB_INIT(bsb, value, alen);
    BSB_IMPORT_skip(bsb, 8);

    int type = 0;
    BSB_LIMPORT_u32(bsb, type);

    if (type != 3) // auth type
        return;

    uint32_t lens[6], offsets[6];
    for (int i = 0; i < ARRAY_LEN(lens); i++) {
        BSB_LIMPORT_u16(bsb, lens[i]);
        BSB_IMPORT_skip(bsb, 2);
        BSB_LIMPORT_u32(bsb, offsets[i]);

        if (BSB_IS_ERROR(bsb) || offsets[i] > BSB_SIZE(bsb) || lens[i] > BSB_SIZE(bsb) - offsets[i]) {
            arkime_session_add_tag(session, "smb:bad-security-blob");
            return;
        }
    }

    if (BSB_IS_ERROR(bsb))
        return;

    if (lens[2]) {
        smb_add_string(session, domainField, (char *)value + offsets[2], lens[2], TRUE);
    }
    if (lens[3]) {
        smb_add_string(session, userField, (char *)value + offsets[3], lens[3], TRUE);
    }
    if (lens[4]) {
        smb_add_string(session, hostField, (char *)value + offsets[4], lens[4], TRUE);
    }
}
/******************************************************************************/
LOCAL void smb1_str_null_split(char *buf, int len, char **out, int max)
{
    memset(out, 0, max * sizeof(char *));
    int start = 0;
    for (int i = 0, p = 0; i < len && p < max; i++) {
        if (buf[i] == 0) {
            out[p] = buf + start;
            start = i + 1;
            p++;
        }
    }
}
/******************************************************************************/
LOCAL void smb1_parse_osverdomain(ArkimeSession_t *session, char *buf, int len, int useunicode)
{
    char        *out;
    gsize        bread, bwritten;
    GError      *error = 0;

    if (useunicode)
        out = g_convert(buf, len, "utf-8", "ucs-2le", &bread, &bwritten, &error);
    else {
        out = buf;
        bwritten = len;
    }

    if (error) {
        if (config.debug)
            LOG("ERROR %s", error->message);
        g_error_free(error);
        return;
    }

    char *outs[3];
    smb1_str_null_split(out, bwritten, outs, 3);

    if (outs[0] && *outs[0])
        arkime_field_string_add(osField, session, outs[0], -1, TRUE);
    if (outs[1] && *outs[1])
        arkime_field_string_add(verField, session, outs[1], -1, TRUE);
    if (outs[2] && *outs[2])
        arkime_field_string_add(domainField, session, outs[2], -1, TRUE);

    if (useunicode) {
        g_free(out);
    }
}
/******************************************************************************/
LOCAL void smb1_parse_userdomainosver(ArkimeSession_t *session, char *buf, int len, int useunicode)
{
    char        *out;
    gsize        bread, bwritten;
    GError      *error = 0;

    if (useunicode)
        out = g_convert(buf, len, "utf-8", "ucs-2le", &bread, &bwritten, &error);
    else {
        out = buf;
        bwritten = len;
    }

    if (error) {
        if (config.debug)
            LOG("ERROR %s", error->message);
        g_error_free(error);
        return;
    }

    char *outs[4];
    smb1_str_null_split(out, bwritten, outs, 4);

    if (outs[0] && *outs[0])
        arkime_field_string_add(userField, session, outs[0], -1, TRUE);
    if (outs[1] && *outs[1])
        arkime_field_string_add(domainField, session, outs[1], -1, TRUE);
    if (outs[2] && *outs[2])
        arkime_field_string_add(osField, session, outs[2], -1, TRUE);
    if (outs[3] && *outs[3])
        arkime_field_string_add(verField, session, outs[3], -1, TRUE);

    if (useunicode) {
        g_free(out);
    }
}
/******************************************************************************/
LOCAL void smb1_parse_negotiate_request(SMBInfo_t *smb, char *buf, int len)
{
    BSB bsb;
    BSB_INIT(bsb, buf, len);

    if (smb->dialectsLen >= MAX_SMB1_DIALECTS)
        return;

    while (BSB_REMAINING(bsb) > 0) {
        BSB_IMPORT_skip(bsb, 1);
        const char *start = (char *)BSB_WORK_PTR(bsb);
        while (BSB_REMAINING(bsb) > 0 && *(BSB_WORK_PTR(bsb)) != 0)
            BSB_IMPORT_skip(bsb, 1);
        if (BSB_REMAINING(bsb) == 0)
            break;
        smb->dialects[smb->dialectsLen] = g_strdup(start);
        smb->dialectsLen++;
        if (smb->dialectsLen >= MAX_SMB1_DIALECTS)
            break;
        BSB_IMPORT_skip(bsb, 1);
    }
}
/******************************************************************************/
LOCAL int smb1_parse(ArkimeSession_t *session, SMBInfo_t *smb, BSB *bsb, char *state, uint32_t *remlen, int which)
{
    const uint8_t *start = BSB_WORK_PTR(*bsb);

    switch (*state) {
    case SMB_SMBHEADER: {
        uint8_t  cmd    = 0;
        uint8_t  flags = 0;
        if (BSB_REMAINING(*bsb) < 32) {
            return 1;
        }
        /* SMB1 header (32 bytes):
         *   bytes 0-3:   \xffSMB (protocol magic)
         *   bytes 4-11:  Status (8 bytes, SMB_ERROR)
         *   byte  12:    Command
         *   byte  13:    Flags
         *   bytes 14-15: Flags2 (little-endian)
         *   bytes 16-31: Reserved(4) + TID(2) + PID(2) + UID(2) + MID(2) + optional(4)
         */
        BSB_IMPORT_skip(*bsb, 4);   /* skip \xffSMB magic (bytes 0-3) */
        BSB_IMPORT_skip(*bsb, 8);   /* skip Status (bytes 4-11) */
        BSB_IMPORT_u08(*bsb, cmd);  /* byte 12: Command */
        BSB_IMPORT_u08(*bsb, flags); /* byte 13: Flags */
        BSB_LIMPORT_u16(*bsb, smb->flags2[which]); /* bytes 14-15: Flags2 */
        BSB_IMPORT_skip(*bsb, 16);  /* bytes 16-31: rest of header */

        if ((flags & SMB1_FLAGS_REPLY) == 0) {
            switch (cmd) {
            case 0x04:  /* Close */
                *state = SMB1_CLOSE;
                break;
            case 0x06:
                *state = SMB1_DELETE;
                break;
            case 0x2d:
                *state = SMB1_OPEN_ANDX;
                break;
            case 0x2e:  /* Read AndX */
                *state = SMB1_READ_ANDX;
                break;
            case 0x2f:  /* Write AndX */
                *state = SMB1_WRITE_ANDX;
                break;
            case 0x72:
                *state = SMB1_NEGOTIATE_REQ;
                break;
            case 0x73:
                *state = SMB1_SETUP_ANDX;
                break;
            case 0x75:
                *state = SMB1_TREE_CONNECT_ANDX;
                break;
            case 0xa2:
                *state = SMB1_CREATE_ANDX;
                break;
            default:
                *state = SMB_SKIP;
            }
        } else {
            switch (cmd) {
            case 0x04:  /* Close response */
                *state = SMB1_CLOSE;
                break;
            case 0x2d:  /* Open AndX response */
                *state = SMB1_OPEN_ANDX_RSP;
                break;
            case 0x2e:  /* Read AndX response */
                *state = SMB1_READ_ANDX;
                break;
            case 0x2f:  /* Write AndX response */
                *state = SMB_SKIP;
                break;
            case 0x72:
                *state = SMB1_NEGOTIATE_RSP;
                break;
            default:
                *state = SMB_SKIP;
            }
        }
#ifdef SMBDEBUG
        LOG("%d cmd: %x flags2: %x newstate: %d remlen: %u", which, cmd, smb->flags2[which], *state, *remlen);
#endif
        break;
    }
    case SMB1_CREATE_ANDX:
    case SMB1_OPEN_ANDX: {
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);
        BSB_IMPORT_skip(*bsb, wordcount * 2 + 3);
        if (BSB_IS_ERROR(*bsb))
            return 1;

        /* 保存文件名到 pendingFilename */
        int remaining = BSB_REMAINING(*bsb);
        if (remaining > 0 && remaining < (int)sizeof(smb->pendingFilename[which])) {
            memcpy(smb->pendingFilename[which], BSB_WORK_PTR(*bsb), remaining);
            smb->pendingFilenameLen[which] = remaining;
            smb->pendingFilename[which][remaining-1] = '\0';
        }

        smb_add_string(session, fnField, (char *)BSB_WORK_PTR(*bsb), BSB_REMAINING(*bsb), smb->flags2[which] & SMB1_FLAGS2_UNICODE);
        *state = SMB_SKIP;
        break;
    }
    case SMB1_OPEN_ANDX_RSP: {
        /* Open AndX 响应: 提取 FID */
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);
        if (wordcount >= 5) {
            uint16_t fid = 0;
            /* Word layout: AndXCommand(1)+Reserved(1), AndXOffset(2), FID(2), ... */
            BSB_IMPORT_skip(*bsb, 4);  /* skip AndXCommand+Reserved+AndXOffset */
            BSB_LIMPORT_u16(*bsb, fid); /* FID */
            /* FID 的第 8 位用于区分文件/目录 (0x80 表示目录、0x42FE 表示 . 等) */
            /* 某些 FID 是特殊句柄，不需要跟踪 */
            if (fid != 0xFFFF && fid != 0) {
                SMBFileInfo_t *file = smb_alloc_file_slot(smb);
                if (file) {
                    file->fid = fid;
                    /* 从 opposite direction 获取保存的文件名 */
                    int other = (which == 0) ? 1 : 0;
                    if (smb->pendingFilenameLen[other] > 0) {
                        int copyLen = MIN(smb->pendingFilenameLen[other], (int)sizeof(file->filename) - 1);
                        memcpy(file->filename, smb->pendingFilename[other], copyLen);
                        file->filename[copyLen] = '\0';
                    } else {
                        snprintf(file->filename, sizeof(file->filename), "unknown_0x%04x", fid);
                    }
#ifdef SMBDEBUG
                    LOG("smb: Open RSP FID=0x%04x filename='%s'", fid, file->filename);
#endif
                }
            }
        }
        *state = SMB_SKIP;
        break;
    }
    case SMB1_READ_ANDX: {
        /* Read AndX 请求或响应 */
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        if (which == 0) {
            /* SMB1 Read AndX Request: 解析 FID */
            int wordcount = 0;
            BSB_IMPORT_u08(*bsb, wordcount);
            if (wordcount >= 5) {
                /* Read AndX Request 参数:
                 * Word 0: AndXCommand(1) + AndXReserved(1)
                 * Word 1: AndXOffset(2)
                 * Word 2: FID(2)
                 */
                BSB_IMPORT_skip(*bsb, 4); /* AndXCommand+Reserved+AndXOffset */
                uint16_t fid = 0;
                BSB_LIMPORT_u16(*bsb, fid);
                if (fid != 0 && fid != 0xFFFF) {
                    smb->smb1ReadFid = fid;
                    smb->hasPendingRead = 1;
#ifdef SMBDEBUG
                    LOG("smb: Read RQ FID=0x%04x", fid);
#endif
                }
            }
            *state = SMB_SKIP;
            break;
        }

        /* SMB1 Read AndX 响应: 包含读取到的文件数据 */
        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);

        if (wordcount >= 8) {
            /* Read AndX 响应参数解析:
             * Word 0: AndXCommand + Reserved
             * Word 1: AndXOffset
             * Word 2: Remaining
             * Word 3: DataCompactionMode
             * Word 4-5: Reserved (2 words)
             * Word 6: DataLength (low 16 bits)
             * Word 7: DataOffset (from SMB header start)
             */
            uint16_t dataLength = 0;
            uint16_t dataOffset = 0;

            BSB_IMPORT_skip(*bsb, 10);  /* skip words 0-4 = 10 bytes */
            BSB_LIMPORT_u16(*bsb, dataLength);
            BSB_LIMPORT_u16(*bsb, dataOffset);

            if (dataLength > 0 && dataLength <= *remlen && dataOffset > 32 && dataOffset < *remlen + 32) {
                int actualOffset = dataOffset - 32;
                if (actualOffset < 0) actualOffset = 0;
                if (actualOffset + dataLength <= BSB_REMAINING(*bsb)) {
                    BSB_IMPORT_skip(*bsb, actualOffset);
                    if (!BSB_IS_ERROR(*bsb)) {
                        const uint8_t *fileData = BSB_WORK_PTR(*bsb);
                        if (dataLength <= BSB_REMAINING(*bsb)) {
                            /* 使用跟踪的 Read Request FID 查找正确文件 */
                            SMBFileInfo_t *file = NULL;
                            if (smb->hasPendingRead && smb->smb1ReadFid != 0) {
                                file = smb_find_file_by_fid(smb, smb->smb1ReadFid);
                                smb->hasPendingRead = 0;
                            }
                            /* 如果未找到，回退到第一个已用文件 */
                            if (!file) {
                                for (int i = 0; i < MAX_SMB_FILES; i++) {
                                    if (smb->files[i].used) {
                                        file = &smb->files[i];
                                        break;
                                    }
                                }
                            }
                            if (file) {
                                smb_append_file_data(file, fileData, dataLength);
#ifdef SMBDEBUG
                                LOG("smb: Read RSP appended %u bytes to FID=0x%04x '%s' (total %u)",
                                    dataLength, file->fid, file->filename, file->dataLen);
#endif
                            }
                        }
                    }
                }
            }
        }

        *state = SMB_SKIP;
        break;
    }
    case SMB1_WRITE_ANDX: {
        /* Write AndX 请求 (client->server): 包含上传的文件数据 */
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        if (which != 0) {
            /* 响应侧不需要处理 */
            *state = SMB_SKIP;
            break;
        }

        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);

        if (wordcount >= 14) {
            uint16_t fid = 0;
            uint16_t dataLength = 0;
            uint16_t dataOffset = 0;

            /* Word 0: AndXCommand+Reserved
             * Word 1: AndXOffset
             * Word 2: FID
             * Word 3-4: Offset (4 bytes)
             * Word 5-6: Reserved (4 bytes)
             * Word 7: WriteMode
             * Word 8: Remaining
             * Word 9: DataLength
             * Word 10: DataOffset
             * Word 11-12: DataLengthHigh (4 bytes) - for large writes
             * Word 13: Reserved
             */
            BSB_IMPORT_skip(*bsb, 4);  /* AndXCommand+Reserved+AndXOffset */
            BSB_LIMPORT_u16(*bsb, fid);
            BSB_IMPORT_skip(*bsb, 12); /* Offset(4)+Reserved(4)+WriteMode(2)+Remaining(2) */
            BSB_LIMPORT_u16(*bsb, dataLength);
            BSB_LIMPORT_u16(*bsb, dataOffset);

            if (dataLength > 0 && fid != 0 && fid != 0xFFFF) {
                /* DataOffset 是从 SMB header 起始的偏移量 */
                int actualOffset = dataOffset - 32;
                if (actualOffset < 0) actualOffset = 0;
                if (actualOffset + dataLength <= BSB_REMAINING(*bsb)) {
                    BSB_IMPORT_skip(*bsb, actualOffset);
                    if (!BSB_IS_ERROR(*bsb) && dataLength <= BSB_REMAINING(*bsb)) {
                        SMBFileInfo_t *file = smb_find_file_by_fid(smb, fid);
                        if (!file) {
                            /* 可能是先 Write 后 Open? 分配新槽 */
                            file = smb_alloc_file_slot(smb);
                            if (file) {
                                file->fid = fid;
                                snprintf(file->filename, sizeof(file->filename), "write_0x%04x", fid);
                            }
                        }
                        if (file) {
                            smb_append_file_data(file, BSB_WORK_PTR(*bsb), dataLength);
#ifdef SMBDEBUG
                            LOG("smb: Write RQ appended %u bytes to FID=0x%04x '%s' (total %u)",
                                dataLength, fid, file->filename, file->dataLen);
#endif
                        }
                    }
                }
            }
        }

        *state = SMB_SKIP;
        break;
    }
    case SMB1_CLOSE: {
        /* Close 请求或响应: 保存文件 */
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        if (which == 0) {
            /* 请求: 包含 FID */
            int wordcount = 0;
            BSB_IMPORT_u08(*bsb, wordcount);
            if (wordcount >= 3) {
                BSB_IMPORT_skip(*bsb, 4); /* AndXCommand+Reserved+AndXOffset */
                uint16_t fid = 0;
                BSB_LIMPORT_u16(*bsb, fid);
                if (fid != 0 && fid != 0xFFFF) {
                    SMBFileInfo_t *file = smb_find_file_by_fid(smb, fid);
                    if (file) {
#ifdef SMBDEBUG
                        LOG("smb: Close FID=0x%04x '%s' - saving %u bytes", fid, file->filename, file->dataLen);
#endif
                        smb_save_file(session, file);
                        smb_free_file_slot(file);
                    }
                }
            }
        }
        *state = SMB_SKIP;
        break;
    }
    case SMB1_DELETE: {
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);
        BSB_IMPORT_skip(*bsb, wordcount * 2 + 3);
        if (BSB_IS_ERROR(*bsb))
            return 1;
        smb_add_string(session, fnField, (char *)BSB_WORK_PTR(*bsb), BSB_REMAINING(*bsb), smb->flags2[which] & SMB1_FLAGS2_UNICODE);
        *state = SMB_SKIP;
        break;
    }
    case SMB1_TREE_CONNECT_ANDX: {
        if (BSB_REMAINING(*bsb) < *remlen) {
            return 1;
        }
        int passlength = 0;
        BSB_IMPORT_skip(*bsb, 6);
        BSB_IMPORT_u16(*bsb, passlength);
        BSB_IMPORT_skip(*bsb, 2 + passlength);

        uint32_t offset = ((BSB_WORK_PTR(*bsb) - start) % 2 == 0) ? 2 : 1;

        if (BSB_IS_ERROR(*bsb) || offset > BSB_REMAINING(*bsb)) {
            return 1;
        }
        smb_add_string(session, shareField, (char *)BSB_WORK_PTR(*bsb) + offset, BSB_REMAINING(*bsb) - offset, smb->flags2[which] & SMB1_FLAGS2_UNICODE);
        *state = SMB_SKIP;
        break;
    }

    case SMB1_SETUP_ANDX: { // http://msdn.microsoft.com/en-us/library/ee441849.aspx
        if (BSB_REMAINING(*bsb) < *remlen) {
            BSB_SET_ERROR(*bsb);
            return 1;
        }
        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);

        if (wordcount == 12) {
            BSB_IMPORT_skip(*bsb, 14);

            int securitylen = 0;
            BSB_LIMPORT_u16(*bsb, securitylen);

            BSB_IMPORT_skip(*bsb, 10);

            if (securitylen > BSB_REMAINING(*bsb)) {
                BSB_SET_ERROR(*bsb);
                return 1;
            }
            smb_security_blob(session, BSB_WORK_PTR(*bsb), securitylen);
            BSB_IMPORT_skip(*bsb, securitylen);

            uint32_t offset = ((BSB_WORK_PTR(*bsb) - start) % 2 == 0) ? 0 : 1;
            BSB_IMPORT_skip(*bsb, offset);

            if (!BSB_IS_ERROR(*bsb)) {
                smb1_parse_osverdomain(session, (char *)BSB_WORK_PTR(*bsb), BSB_REMAINING(*bsb), smb->flags2[which] & SMB1_FLAGS2_UNICODE);
            }
        } else if (wordcount == 13) {
            BSB_IMPORT_skip(*bsb, 14);

            int ansipw = 0;
            BSB_LIMPORT_u16(*bsb, ansipw);
            int upw = 0;
            BSB_LIMPORT_u16(*bsb, upw);

            BSB_IMPORT_skip(*bsb, 10 + ansipw + upw);

            uint32_t offset = ((BSB_WORK_PTR(*bsb) - start) % 2 == 0) ? 0 : 1;
            BSB_IMPORT_skip(*bsb, offset);

            if (!BSB_IS_ERROR(*bsb)) {
                smb1_parse_userdomainosver(session, (char *)BSB_WORK_PTR(*bsb), BSB_REMAINING(*bsb), smb->flags2[which] & SMB1_FLAGS2_UNICODE);
            }
        }

        *state = SMB_SKIP;
        break;
    }
    case SMB1_NEGOTIATE_REQ: {
        if (BSB_REMAINING(*bsb) < *remlen) {
            BSB_SET_ERROR(*bsb);
            return 1;
        }
        BSB_LIMPORT_skip(*bsb, 1); // wordcount

        int bytecount = 0;
        BSB_LIMPORT_u08(*bsb, bytecount);

        if (bytecount > 0)
            smb1_parse_negotiate_request(smb, (char *)BSB_WORK_PTR(*bsb), BSB_REMAINING(*bsb));

        *state = SMB_SKIP;
        break;
    }
    case SMB1_NEGOTIATE_RSP: {
        if (BSB_REMAINING(*bsb) < *remlen) {
            BSB_SET_ERROR(*bsb);
            return 1;
        }
        int wordcount = 0;
        BSB_IMPORT_u08(*bsb, wordcount);

        if (wordcount < 13) {
            *state = SMB_SKIP;
            break;
        }

        uint16_t dialect = 0;
        BSB_IMPORT_u08(*bsb, dialect);
        if (dialect < smb->dialectsLen) {
            arkime_field_string_add(dialectField, session, smb->dialects[dialect], -1, TRUE);
        }

        *state = SMB_SKIP;
        break;
    }
    } /* switch */

    SMB_REMLEN_SUB(remlen, start, *bsb);
    return 0;
}
/******************************************************************************/
LOCAL int smb2_parse(ArkimeSession_t *session, SMBInfo_t *smb, BSB *bsb, char *state, uint32_t *remlen, int UNUSED(which))
{
    const uint8_t *start = BSB_WORK_PTR(*bsb);

    LOG("smb2_parse ENTER state=%d which=%d", *state, which);
    switch (*state) {
    case SMB_SMBHEADER: {
        uint16_t  flags = 0;
        uint16_t  cmd = 0;

        if (BSB_REMAINING(*bsb) < 64) {
            if (*remlen >= 64 && *remlen <= MAX_SMB_BUFFER + 64) {
                return 1;
            }
            *state = SMB_SKIP;
            break;
        }
        /* SMB2 header (64 bytes) - This pcap uses COMPRESSED layout for ALL packets:
         * There is NO 4-byte NT Status field; Command is always at bytes 12-13
         * and Flags is always at bytes 16-19.
         *
         *   bytes 0-3:   ProtocolId (\xfeSMB)
         *   bytes 4-5:   StructureSize
         *   bytes 6-7:   CreditCharge
         *   bytes 8-9:   ChannelSequence
         *   bytes 10-11: Reserved
         *   bytes 12-13: Command  ← ALWAYS HERE (both request AND response)
         *   bytes 14-15: Credits
         *   bytes 16-19: Flags    ← ALWAYS HERE (bit 0 = SMB2_FLAGS_SERVER_TO_REDIR)
         *   bytes 20-23: NextCommand
         *   bytes 24-63: rest (MessageId 8 + ProcessId 2 + TreeId 2 + SessionId 8 + Signature 16)
         */
        LOG("SMB_SMBHEADER which=%d bsbRemain=%u cmd_raw=%02x%02x",
            which, (uint32_t)BSB_REMAINING(*bsb),
            start[12], start[13]);
        /* Compressed layout: Command always at bytes 12-13, Flags always at bytes 16-19.
         * The SMB2_FLAGS_SERVER_TO_REDIR bit in Flags distinguishes request vs response. */
        BSB_IMPORT_skip(*bsb, 12);  /* bytes 0-11: ProtocolId+StructSize+CreditCharge+ChSeq+Reserved */
        BSB_LIMPORT_u16(*bsb, cmd);  /* bytes 12-13: Command */
        BSB_IMPORT_skip(*bsb, 2);    /* bytes 14-15: Credits */
        BSB_LIMPORT_u32(*bsb, flags); /* bytes 16-19: Flags */
        BSB_IMPORT_skip(*bsb, 44);   /* bytes 20-63: rest */

        if ((flags & SMB2_FLAGS_SERVER_TO_REDIR) == 0) {
            switch (cmd) {
            case 0x03:
                *state = SMB2_TREE_CONNECT;
                break;
            case 0x05:
                *state = SMB2_CREATE;
                break;
            case 0x06:  /* Close */
                *state = SMB2_CLOSE;
                break;
            case 0x08:  /* Read */
                *state = SMB2_READ;
                break;
            case 0x09:  /* Write */
                *state = SMB2_WRITE;
                break;
            default:
                *state = SMB_SKIP;
            }
        } else {
            switch (cmd) {
            case 0x00:
                *state = SMB2_NEGOTIATE;
                break;
            case 0x05:  /* Create response */
                *state = SMB2_CREATE_RSP;
                break;
            case 0x06:  /* Close response */
                *state = SMB2_CLOSE;
                break;
            case 0x08:  /* Read response */
                *state = SMB2_READ;
                break;
            case 0x09:  /* Write response */
                *state = SMB2_WRITE;
                break;
            default:
                *state = SMB_SKIP;
            }
        }
        /* SMB2 协议始终使用 Unicode 字符串 */
        smb->flags2[which] = SMB1_FLAGS2_UNICODE;
#ifdef SMBDEBUG
        LOG("%d cmd: %x flags: %x newstate: %d remlen: %u", which, cmd, flags, *state, *remlen);
#endif
        SMB_REMLEN_SUB(remlen, start, *bsb);
        break;
    }
    case SMB2_NEGOTIATE: {
        if (BSB_REMAINING(*bsb) < 6) {
            return 1;
        }

        BSB_IMPORT_skip(*bsb, 4);

        uint16_t  dialect = 0;
        BSB_LIMPORT_u16(*bsb, dialect);
        if (dialect != 0 && dialect != 0x02FF) {
            char str[13];
            snprintf(str, sizeof(str), "SMB %d.%d.%d", (dialect >> 8) & 0xf, (dialect >> 4) & 0xf, dialect & 0xf);
            arkime_field_string_add(dialectField, session, str, -1, TRUE);
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        break;
    }
    case SMB2_TREE_CONNECT: {
        uint16_t  pathoffset = 0;
        uint16_t  pathlen = 0;

        if (BSB_REMAINING(*bsb) < 8) {
            return 1;
        }
        BSB_IMPORT_skip(*bsb, 4);
        BSB_LIMPORT_u16(*bsb, pathoffset);
        BSB_LIMPORT_u16(*bsb, pathlen);
        if (pathoffset < (64 + 8)) {
            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }
        pathoffset -= (64 + 8);
        BSB_IMPORT_skip(*bsb, pathoffset);

        if (!BSB_IS_ERROR(*bsb) && pathlen <= BSB_REMAINING(*bsb)) {
            smb_add_string(session, shareField, (char *)BSB_WORK_PTR(*bsb), pathlen, smb->flags2[which] & SMB1_FLAGS2_UNICODE);
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        break;
    }
    case SMB2_CREATE: {
        uint16_t  nameoffset = 0;
        uint16_t  namelen = 0;

        if (BSB_REMAINING(*bsb) < 48) {
            return 1;
        }
        BSB_IMPORT_skip(*bsb, 44);
        BSB_LIMPORT_u16(*bsb, nameoffset);
        BSB_LIMPORT_u16(*bsb, namelen);
        if (nameoffset < (64 + 48)) {
            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }
        nameoffset -= (64 + 48);
        BSB_IMPORT_skip(*bsb, nameoffset);

        if (!BSB_IS_ERROR(*bsb) && namelen <= BSB_REMAINING(*bsb)) {
            gsize bread, bwritten;
            GError      *error = 0;
            char *out = g_convert((char *)BSB_WORK_PTR(*bsb), namelen, "utf-8", "ucs-2le", &bread, &bwritten, &error);
            if (error) {
                LOG_RATE(5, "ERROR %s", error->message);
                g_error_free(error);
            } else {
                if (!arkime_field_string_add(fnField, session, out, -1, FALSE)) {
                    /* 保存 pending 文件名供 Create RSP 使用 */
                    int copyLen = MIN(namelen/2, (int)sizeof(smb->pendingFilename[0]) - 1);
                    /* UCS-2LE to ASCII 近似 */
                    for (int i = 0; i < copyLen && out[i]; i++) {
                        smb->pendingFilename[0][i] = out[i];
                    }
                    smb->pendingFilename[0][copyLen] = '\0';
                    smb->pendingFilenameLen[0] = copyLen;
                    g_free(out);
                }
            }
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        break;
    }
    case SMB2_CREATE_RSP: {
        /* Create 响应: 提取 FileId (Persistent + Volatile handle) */
        if (BSB_REMAINING(*bsb) < 88 || *remlen < 88) {
            if (BSB_REMAINING(*bsb) < 88 && *remlen >= 88 && *remlen <= MAX_SMB_BUFFER) {
                return 1;
            }
            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }
        /* SMB2 Create Response structure (固定部分):
         * StructureSize(2) = 89
         * OplockLevel(1)
         * Flags(1)
         * CreateAction(4)
         * CreationTime(8)
         * LastAccessTime(8)
         * LastWriteTime(8)
         * ChangeTime(8)
         * AllocationSize(8)
         * EndofFile(8)
         * FileAttributes(4)
         * Reserved(4)
         * FileId(16) = Persistent(8) + Volatile(8)
         * CreateContextsOffset(4)
         * CreateContextsLength(4)
         * Buffer (variable)
         * Total: 88 bytes fixed + variable
         */
        BSB_IMPORT_skip(*bsb, 64); /* skip to FileId */
        uint64_t persistentHandle = 0;
        uint64_t volatileHandle = 0;

        /* 手动读 8 字节 LE (BSB_LIMPORT_u64 存在但为了明确性手动分两次读) */
        {
            uint32_t lo = 0, hi = 0;
            BSB_LIMPORT_u32(*bsb, lo);
            BSB_LIMPORT_u32(*bsb, hi);
            persistentHandle = ((uint64_t)hi << 32) | lo;
        }
        {
            uint32_t lo = 0, hi = 0;
            BSB_LIMPORT_u32(*bsb, lo);
            BSB_LIMPORT_u32(*bsb, hi);
            volatileHandle = ((uint64_t)hi << 32) | lo;
        }
        /* 使用 persistentHandle 作为键 */
        if (persistentHandle != 0 && smb->smb2FileCount < MAX_SMB_FILES) {
            int idx = smb->smb2FileCount++;
            smb->smb2FileHandle[idx] = persistentHandle;
            if (smb->pendingFilenameLen[0] > 0) {
                memcpy(smb->smb2FileName[idx], smb->pendingFilename[0], 
                       MIN(smb->pendingFilenameLen[0], 1023));
                smb->smb2FileName[idx][MIN(smb->pendingFilenameLen[0], 1023)] = '\0';
            } else {
                snprintf(smb->smb2FileName[idx], sizeof(smb->smb2FileName[idx]), 
                         "smb2_file_%" PRIx64, persistentHandle);
            }
            /* 保持 volatileHandle "used" 以避免 set-but-not-used 警告 */
            (void)volatileHandle;
#ifdef SMBDEBUG
            LOG("smb2: Create RSP Persistent=0x%" PRIx64 " Volatile=0x%" PRIx64 " name='%s'",
                persistentHandle, volatileHandle, smb->smb2FileName[idx]);
#endif
            /* 同时分配文件跟踪数据槽 */
            SMBFileInfo_t *file = smb_alloc_file_slot(smb);
            if (file) {
                file->fid = (uint16_t)(persistentHandle & 0xFFFF); /* 复用 fid 字段存低16位 */
                file->persistentHandle = persistentHandle;          /* 保存完整 64-bit Handle */
                memcpy(file->filename, smb->smb2FileName[idx],
                       MIN((int)strlen(smb->smb2FileName[idx]), (int)sizeof(file->filename) - 1));
            }
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        LOG("smb: CREATE_RSP done handle=0x%" PRIx64 " state=%d remlen=%u",
            persistentHandle, *state, *remlen);
        break;
    }
    case SMB2_READ: {
        if (BSB_REMAINING(*bsb) < 2) {
            return 1;
        }
        if (which == 0) {
            /* SMB2 Read Request: 使用 StructureSize 动态计算 body 长度
             * 各 SMB 方言的 Read Request body 长度不同:
             *   SMB 2.0.2:   44 bytes (无 Channel、无 Flags)
             *   SMB 3.0/3.02:48 bytes (有 Channel、无 Flags)
             *   SMB 3.1.1:   52 bytes (有 Channel、有 Flags)
             * 但 StructureSize 都是 49 (协议版本无关)
             */
            uint16_t structSize = 0;
            BSB_LIMPORT_u16(*bsb, structSize);
            if (structSize < 24 || (uint32_t)(structSize - 2) > BSB_REMAINING(*bsb)) {
                /* 数据不足，等待更多数据 */
                return 1;
            }

            /* 读取 Length(4) 和 Offset(8)，不再跳过 */
            BSB_IMPORT_skip(*bsb, 2); /* Padding(1)+Reserved(1) */
            BSB_LIMPORT_u32(*bsb, smb->smb2ReadReqLength);
            BSB_LIMPORT_u64(*bsb, smb->smb2ReadReqOffset);

            /* Read FileId.Persistent (8 bytes) */
            uint64_t persistentHandle = 0;
            uint32_t lo = 0, hi = 0;
            BSB_LIMPORT_u32(*bsb, lo);
            BSB_LIMPORT_u32(*bsb, hi);
            persistentHandle = ((uint64_t)hi << 32) | lo;

            /* 跳过 body 剩余部分: structSize - 2(已读StructSize) - 2(Pad+Resv) - 4(Length) - 8(Offset) - 8(FileId Persist) = structSize - 24 */
            if (structSize > 24) {
                BSB_IMPORT_skip(*bsb, structSize - 24);
            }

            /* 记录正在读取的文件句柄和偏移 */
            if (persistentHandle != 0) {
                smb->smb2ReadFileHandle = persistentHandle;
                smb->hasPendingRead = 1;
#ifdef SMBDEBUG
                LOG("smb2: Read RQ handle=0x%" PRIx64 " structSize=%u", persistentHandle, structSize);
#endif
            }

            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }

        /* SMB2 Read Response: 包含文件数据 */
        /* SMB2 Read Response:
         * StructureSize(2)
         * DataOffset(1) - offset from SMB2 header start
         * Reserved(1)
         * DataLength(4)
         * Data (variable)
         */
        if (BSB_REMAINING(*bsb) < 8) {
            return 1;
        }
        uint8_t dataOffset = 0;
        uint32_t dataLength = 0;

        BSB_IMPORT_skip(*bsb, 2); /* StructureSize */
        BSB_IMPORT_u08(*bsb, dataOffset);
        BSB_IMPORT_skip(*bsb, 1); /* Reserved */
        BSB_LIMPORT_u32(*bsb, dataLength);


#ifdef SMBDEBUG
        LOG("smb2: Read RSP dataOffset=%u dataLength=%u bsbRemain=%u remlen=%u",
            dataOffset, dataLength, (uint32_t)BSB_REMAINING(*bsb), *remlen);
#endif

        if (dataLength > 0) {
            /* dataOffset 是从 SMB2 header 起始的偏移 */
            int readSoFar = 64 + 8; /* SMB2 header(64) + response header(8) */
            if (dataOffset > readSoFar) {
                int delta = dataOffset - readSoFar;
                if (delta <= (int)BSB_REMAINING(*bsb)) {
                    BSB_IMPORT_skip(*bsb, delta);
                }
            }
            
            if (!BSB_IS_ERROR(*bsb)) {
                uint32_t availData = MIN(dataLength, (uint32_t)BSB_REMAINING(*bsb));
                /* 使用跟踪的 Read Request FileId 查找正确文件 */
                SMBFileInfo_t *file = NULL;
                if (smb->hasPendingRead && smb->smb2ReadFileHandle != 0) {
                    file = smb_find_file_by_persistent_handle(smb, smb->smb2ReadFileHandle);
                    smb->hasPendingRead = 0;
                }
                /* 如果未找到，回退到第一个已用文件 */
                if (!file) {
                    for (int i = 0; i < MAX_SMB_FILES; i++) {
                        if (smb->files[i].used) {
                            file = &smb->files[i];
                            break;
                        }
                    }
                }
                if (file) {
                    /* 使用文件偏移写入 (smb2ReadReqOffset 来自 Read Request) */
                    smb_write_file_data_at_offset(file, BSB_WORK_PTR(*bsb), availData, smb->smb2ReadReqOffset);
#ifdef SMBDEBUG
                    LOG("smb2: Read RSP wrote %u/%u bytes at offset %" PRIu64 " to handle=0x%" PRIx64 " '%s' (total %u)",
                        availData, dataLength, smb->smb2ReadReqOffset, smb->smb2ReadFileHandle, file->filename, file->dataLen);
#endif
                    /* 如果还有更多数据要接收，设置流式传输状态 */
                    if (availData < dataLength) {
                        smb->smb2ReadRspHandle = smb->smb2ReadFileHandle;
                        smb->smb2ReadRspRemaining = dataLength - availData;
                        smb->smb2ReadRspOffset = smb->smb2ReadReqOffset + availData;
                        smb->smb2ReadRspActive = 1;
                        SMB_REMLEN_SUB(remlen, start, *bsb);
                        *state = SMB2_READ_RSP_DATA;
                        break;
                    }
                }
            }
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        break;
    }
    case SMB2_WRITE: {
        if (which != 0) {
            /* SMB2 Write Response: StructureSize(2)+Reserved(2) = 4字节，直接跳过 */
            if (BSB_REMAINING(*bsb) < 4) {
                return 1;
            }
            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }
        /* SMB2 Write Request (SMB 3.1.1):
         * StructureSize(2) = 49
         * DataOffset(2) - from SMB2 header
         * Length(4)
         * Offset(8) - file offset for write
         * FileId(16) - Persistent(8) + Volatile(8)
         * Channel(4)
         * RemainingBytes(4)
         * WriteChannelInfoOffset(2)
         * WriteChannelInfoLength(2)
         * Flags(4)
         * Data (variable at DataOffset)
         * 实际固定字段读取: StructSize(2)+DataOff(2)+Len(4)+Offset(8)+FileId(16)+VolatileSkip(8)+ChannelBlockSkip(12) = 44字节
         */
        if (BSB_REMAINING(*bsb) < 44) {
            return 1;
        }
        uint16_t dataOffset = 0;
        uint32_t length = 0;
        uint64_t fileOffset = 0;
        uint64_t persistentHandle = 0;

        BSB_IMPORT_skip(*bsb, 2); /* StructureSize */
        BSB_LIMPORT_u16(*bsb, dataOffset);
        BSB_LIMPORT_u32(*bsb, length);
        /* Offset (8 bytes) */
        {
            uint32_t lo = 0, hi = 0;
            BSB_LIMPORT_u32(*bsb, lo);
            BSB_LIMPORT_u32(*bsb, hi);
            fileOffset = ((uint64_t)hi << 32) | lo;
        }
        /* FileId (16 bytes) */
        {
            uint32_t lo = 0, hi = 0;
            BSB_LIMPORT_u32(*bsb, lo);
            BSB_LIMPORT_u32(*bsb, hi);
            persistentHandle = ((uint64_t)hi << 32) | lo;
        }
        BSB_IMPORT_skip(*bsb, 8); /* Volatile handle */

        /* Skip Channel(4) + RemainingBytes(4) + ChannelInfoOffset(2) + ChannelInfoLength(2) */
        BSB_IMPORT_skip(*bsb, 12);

        if (length > 0 && persistentHandle != 0) {
            /* DataOffset 是从 SMB2 header 起始的偏移 */
            int readSoFar = 64 + 44; /* SMB2 header(64) + request fields actually read(44) */
            if (dataOffset > readSoFar) {
                int delta = dataOffset - readSoFar;
                if (delta <= (int)BSB_REMAINING(*bsb)) {
                    BSB_IMPORT_skip(*bsb, delta);
                }
            }
            
            if (!BSB_IS_ERROR(*bsb)) {
#ifdef SMBDEBUG
                LOG("smb2: Write RQ dataOffset=%u length=%u bsbRemain=%u persistentHandle=0x%" PRIx64 " fileOffset=%" PRIu64,
                    dataOffset, length, (uint32_t)BSB_REMAINING(*bsb), persistentHandle, fileOffset);
#endif
                /* 只取缓冲区中实际可用的数据 */
                uint32_t availLen = MIN(length, (uint32_t)BSB_REMAINING(*bsb));
                /* 使用完整 64-bit Persistent Handle 查找文件 */
                SMBFileInfo_t *file = smb_find_file_by_persistent_handle(smb, persistentHandle);
                if (!file) {
                    /* 回退：按截断的 FID 查找 */
                    uint16_t fid = (uint16_t)(persistentHandle & 0xFFFF);
                    file = smb_find_file_by_fid(smb, fid);
                }
                if (!file) {
                    /* 创建新槽 */
                    file = smb_alloc_file_slot(smb);
                    if (file) {
                        file->fid = (uint16_t)(persistentHandle & 0xFFFF);
                        file->persistentHandle = persistentHandle;
                        snprintf(file->filename, sizeof(file->filename),
                                 "smb2_write_0x%" PRIx64, persistentHandle);
                    }
                }
                if (file) {
                    /* 使用 fileOffset 按正确偏移写入数据 */
                    smb_write_file_data_at_offset(file, BSB_WORK_PTR(*bsb), availLen, fileOffset);
#ifdef SMBDEBUG
                    LOG("smb2: Write RQ wrote %u/%u bytes at offset %" PRIu64 " to 0x%" PRIx64 " '%s' (total %u)",
                        availLen, length, fileOffset, persistentHandle, file->filename, file->dataLen);
#endif
                }
            }
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        break;
    }
    case SMB2_CLOSE: {
        /* Close: 保存文件 */
        if (BSB_REMAINING(*bsb) < 24) {
            return 1;
        }
        if (which == 0) {
            /* Request: 包含 FileId */
            /* SMB2 Close Request:
             * StructureSize(2) = 24
             * Flags(2)
             * Reserved(4)
             * FileId(16)
             */
            BSB_IMPORT_skip(*bsb, 8); /* StructureSize(2)+Flags(2)+Reserved(4) */
            uint64_t persistentHandle = 0;
            {
                uint32_t lo = 0, hi = 0;
                BSB_LIMPORT_u32(*bsb, lo);
                BSB_LIMPORT_u32(*bsb, hi);
                persistentHandle = ((uint64_t)hi << 32) | lo;
            }
            if (persistentHandle != 0) {
                /* 优先使用完整 64-bit Persistent Handle 查找 */
                SMBFileInfo_t *file = smb_find_file_by_persistent_handle(smb, persistentHandle);
                if (!file) {
                    /* 回退：按截断的 FID 查找 */
                    uint16_t fid = (uint16_t)(persistentHandle & 0xFFFF);
                    file = smb_find_file_by_fid(smb, fid);
                }
                if (file) {
#ifdef SMBDEBUG
                    LOG("smb2: Close handle=0x%" PRIx64 " '%s' - saving %u bytes",
                        persistentHandle, file->filename, file->dataLen);
#endif
                    smb_save_file(session, file);
                    smb_free_file_slot(file);
                }
                /* 从 SMB2 文件名映射中清除 */
                for (int i = 0; i < smb->smb2FileCount; i++) {
                    if (smb->smb2FileHandle[i] == persistentHandle) {
                        smb->smb2FileHandle[i] = 0;
                        smb->smb2FileName[i][0] = '\0';
                        break;
                    }
                }
            }
        }
        SMB_REMLEN_SUB(remlen, start, *bsb);
        *state = SMB_SKIP;
        break;
    }
    case SMB2_READ_RSP_DATA: {
        /* 流式传输: 跨多个 ENTER 调用持续接收 Read Response 数据 */
        if (!smb->smb2ReadRspActive || smb->smb2ReadRspRemaining == 0) {
            smb->smb2ReadRspActive = 0;
            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }

        SMBFileInfo_t *file = smb_find_file_by_persistent_handle(smb, smb->smb2ReadRspHandle);
        if (!file) {
            smb->smb2ReadRspActive = 0;
            SMB_REMLEN_SUB(remlen, start, *bsb);
            *state = SMB_SKIP;
            break;
        }

        uint32_t chunk = MIN(smb->smb2ReadRspRemaining, (uint32_t)BSB_REMAINING(*bsb));
        if (chunk > 0) {
            smb_write_file_data_at_offset(file, BSB_WORK_PTR(*bsb), chunk, smb->smb2ReadRspOffset);
            smb->smb2ReadRspOffset += chunk;
            smb->smb2ReadRspRemaining -= chunk;
            BSB_IMPORT_skip(*bsb, chunk);
#ifdef SMBDEBUG
            LOG("smb2: Read RSP data streaming: wrote %u bytes at offset %" PRIu64 " to '%s', %u remaining",
                chunk, smb->smb2ReadRspOffset - chunk, file->filename, smb->smb2ReadRspRemaining);
#endif
        }

        SMB_REMLEN_SUB(remlen, start, *bsb);

        if (smb->smb2ReadRspRemaining == 0) {
            smb->smb2ReadRspActive = 0;
            *state = SMB_SKIP;
        }
        break;
    }
    }

    return 0;
}
/******************************************************************************/
/**
 * 在 BSB 缓冲区中搜索 SMB2 魔术字节 (\xfeSMB 或 \xffSMB) 以重新同步流。
 * 当 remlen 损坏导致解析器失步时调用此函数。
 *
 * 如果找到魔术字节且位置 >= 4（即有前导 NBSS 头空间），
 * 则定位到 NBSS 头部（魔术前 4 字节）并设置 state=SMB_NETBIOS，
 * 让标准 NBSS 读取器正确解析长度字段。
 *
 * 如果找到魔术字节但位置 < 4，则定位到魔术字节，
 * 设置 state=SMB_SMBHEADER 并分配一个较大的 remlen。
 *
 * 如果未找到魔术字节，则消耗所有剩余数据并返回 0。
 */
static int smb_resync_stream(BSB *bsb, uint32_t *remlen, char *state, uint8_t *version)
{
    const uint8_t *pos = BSB_WORK_PTR(*bsb);
    uint32_t remaining = BSB_REMAINING(*bsb);
    uint32_t i;

    for (i = 0; i + 4 <= remaining; i++) {
        if ((pos[i] == 0xfe || pos[i] == 0xff) &&
            pos[i+1] == 'S' && pos[i+2] == 'M' && pos[i+3] == 'B') {

            if (i >= 4) {
                /* 跳转到 NBSS 头部（魔术字节前 4 字节），让 SMB_NETBIOS 正确解析长度和版本 */
                LOG("smb: resync - NBSS+magic at offset %u, version=0x%02x, remaining=%u",
                    i - 4, pos[i], remaining);
                BSB_IMPORT_skip(*bsb, i - 4);
                *state = SMB_NETBIOS;
            } else {
                /* 魔术出现在缓冲区开头附近，无法获取 NBSS 头，直接使用 SMB_SMBHEADER */
                LOG("smb: resync - magic at offset %u (no NBSS), version=0x%02x, remaining=%u",
                    i, pos[i], remaining);
                BSB_IMPORT_skip(*bsb, i);
                *version = pos[i];
                *remlen = MAX_SMB_BUFFER + 200;
                *state = SMB_SMBHEADER;
            }
            return 1;
        }
    }

    /* 未找到魔术字节，消耗所有剩余数据，下次 TCP 段从头开始 */
    LOG("smb: resync - no magic found in %u bytes, consuming all", remaining);
    BSB_IMPORT_skip(*bsb, remaining);
    *remlen = 0;
    *state = SMB_SKIP;
    return 0;
}
/******************************************************************************/
LOCAL int smb_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int remaining, int which)
{
    SMBInfo_t            *smb          = uw;
    char                 *state        = &smb->state[which];
    char                 *buf          = smb->buf[which];
    short                *buflen       = &smb->buflen[which];
    uint32_t             *remlen       = &smb->remlen[which];

    LOG("smb_parser ENTER which=%d remaining=%d state=%d buflen=%d remlen=%u",
        which, remaining, *state, *buflen, *remlen);
    while (remaining > 0) {
        BSB bsb;
        int done = 0;

        if (*buflen == 0) {
            BSB_INIT(bsb, data, remaining);
            data += remaining;
            remaining = 0;
        } else {
            int len = MIN(remaining, MAX_SMB_BUFFER - (*buflen));
            memcpy(buf + (*buflen), data, len);
            (*buflen) += len;
            remaining -= len;
            data += len;
            BSB_INIT(bsb, buf, *buflen);
        }

        if (*state != SMB_SKIP && *state != SMB_NETBIOS && *state != SMB_SMBHEADER
            && *state != SMB2_READ && *state != SMB2_READ_RSP_DATA && *remlen > MAX_SMB_BUFFER) {
            LOG("WARNING - Not enough room to parse SMB packet of size %u, trying stream resync", *remlen);
            smb_resync_stream(&bsb, remlen, state, &smb->version[which]);
            /* resync 已消耗部分或全部 BSB 数据，但 done 仍然为 0，内层循环会继续处理 */
        }

        while (!done && BSB_REMAINING(bsb) > 0) {
#ifdef SMBDEBUG
            LOG(" S: bsbremaining: %u remaining: %d state: %d buflen: %d remlen: %u done: %d", (uint32_t)BSB_REMAINING(bsb), remaining, *state, *buflen, *remlen, done);
#endif
            switch (*state) {
            case SMB_NETBIOS:
                if (BSB_REMAINING(bsb) < 5) {
                    done = 1;
                    break;
                }

                /* 先查看 NBSS 头长度而不消耗字节，防止数据不足时丢失 NBSS 头 */
                {
                    const uint8_t *p = BSB_WORK_PTR(bsb);
                    uint32_t nbssLen = ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];

                    if (nbssLen < 32) {
                        BSB_IMPORT_skip(bsb, 1);
                        BSB_IMPORT_u24(bsb, *remlen);
                        *state = SMB_SKIP;
                        break;
                    }

                    /* 检查是否有足够的字节容纳 SMB2 头 (NBSS头4 + SMB2头64 = 68字节) */
                    if (BSB_REMAINING(bsb) < 4 + 64) {
                        done = 1;
                        break;  /* 不消耗 NBSS 头，保留在缓冲区中以便下次重试 */
                    }
                }

                /* 现在有足够数据，消耗 NBSS 头 */
                BSB_IMPORT_skip(bsb, 1);
                BSB_IMPORT_u24(bsb, *remlen);
                // Peek at SMBHEADER for version
                smb->version[which] = *(BSB_WORK_PTR(bsb));
                *state = SMB_SMBHEADER;
                break;
            case SMB_SKIP:
                /* 防止 remlen 整数下溢导致死循环 */
                if (*remlen > MAX_SMB_BUFFER) {
                    LOG("smb: remlen corrupted in SMB_SKIP (%u), resyncing stream", *remlen);
                    smb_resync_stream(&bsb, remlen, state, &smb->version[which]);
                    break;
                }
                if (BSB_REMAINING(bsb) < *remlen) {
                    *remlen -= BSB_REMAINING(bsb);
                    BSB_IMPORT_skip(bsb, BSB_REMAINING(bsb));
                } else {
                    BSB_IMPORT_skip(bsb, *remlen);
                    *remlen = 0;
                    *state = SMB_NETBIOS;
                }
                break;
            default:
                if (smb->version[which] == 0xff) {
                    done = smb1_parse(session, smb, &bsb, state, remlen, which);
                } else {
                    done = smb2_parse(session, smb, &bsb, state, remlen, which);
                }
                /* 防御性检查：防止 large remlen 错误触发 resync。
                 * 对于 SMB2_READ（大数据传输，如 Read Response 文件数据）和
                 * SMB2_READ_RSP_DATA（流式传输中）、SMB_SKIP（跳过大量剩余数据时），
                 * remlen 大于 MAX_SMB_BUFFER 是正常情况，不应触发 resync。
                 * 这些状态已在第 1801 行的入口检查中被排除，此处保持一致。 */
                if (*remlen > MAX_SMB_BUFFER
                    && *state != SMB_NETBIOS
                    && *state != SMB_SMBHEADER
                    && *state != SMB_SKIP
                    && *state != SMB2_READ
                    && *state != SMB2_READ_RSP_DATA) {
                    LOG("smb: remlen corrupted after state handler (%u, state=%d), resyncing stream", *remlen, *state);
                    smb_resync_stream(&bsb, remlen, state, &smb->version[which]);
                }
            }

#ifdef SMBDEBUG
            LOG(" E: bsbremaining: %u remaining: %d state: %d buflen: %d remlen: %u done: %d", (uint32_t)BSB_REMAINING(bsb), remaining, *state, *buflen, *remlen, done);
#endif
        }

        if (BSB_IS_ERROR(bsb)) {
            arkime_parsers_unregister(session, smb);
            return 0;
        }

        if (BSB_REMAINING(bsb) > 0 && BSB_WORK_PTR(bsb) != (uint8_t *)buf) {
#ifdef SMBDEBUG
            //LOG("  Moving data %ld %s", BSB_REMAINING(bsb), arkime_session_id_string(session->protocol, session->addr1, session->port1, session->addr2, session->port2));
#endif
            if (BSB_REMAINING(bsb) > MAX_SMB_BUFFER) {
                LOG("WARNING - Not enough room to parse SMB packet of size %u", (uint32_t)BSB_REMAINING(bsb));
                arkime_parsers_unregister(session, smb);
                return 0;
            }
            memmove(buf, BSB_WORK_PTR(bsb), BSB_REMAINING(bsb));
        }
        *buflen = BSB_REMAINING(bsb);
    }
    return 0;
}
/******************************************************************************/
LOCAL void smb_free(ArkimeSession_t UNUSED(*session), void *uw)
{
    SMBInfo_t            *smb          = uw;

    for (int i = 0; i < smb->dialectsLen; i++) {
        g_free(smb->dialects[i]);
    }

    /* 保存所有剩余的文件数据 */
    for (int i = 0; i < MAX_SMB_FILES; i++) {
        if (smb->files[i].used && smb->files[i].dataLen > 0) {
            smb_save_file(session, &smb->files[i]);
        }
        smb_free_file_slot(&smb->files[i]);
    }

    ARKIME_TYPE_FREE(SMBInfo_t, smb);
}
/******************************************************************************/
LOCAL void smb_classify(ArkimeSession_t *session, const uint8_t *data, int UNUSED(len), int UNUSED(which), void *UNUSED(uw))
{
    /* 支持两种 SMB 封装：
     * 1. NetBIOS (port 139): 4 字节 NBSS 头 + SMB @ offset 4
     * 2. 直连 (port 445):    SMB @ offset 0 (无 NBSS 头)
     * classifier offset=5 匹配 NBSS 模式, offset=1 匹配直连模式
     */
    if (data[0] != 0xff && data[0] != 0xfe && data[4] != 0xff && data[4] != 0xfe)
        return;

    if (arkime_session_has_protocol(session, "smb"))
        return;

    arkime_session_add_protocol(session, "smb");

    SMBInfo_t            *smb          = ARKIME_TYPE_ALLOC0(SMBInfo_t);

    arkime_parsers_register(session, smb_parser, smb, smb_free);
}
/******************************************************************************/
void arkime_parser_init()
{
    shareField = arkime_field_define("smb", "termfield",
                                     "smb.share", "Share", "smb.share",
                                     "SMB shares connected to",
                                     ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                     (char *)NULL);

    fnField = arkime_field_define("smb", "termfield",
                                  "smb.fn", "Filename", "smb.filename",
                                  "SMB files opened, created, deleted",
                                  ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                  (char *)NULL);

    osField = arkime_field_define("smb", "termfield",
                                  "smb.os", "OS", "smb.os",
                                  "SMB OS information",
                                  ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                  (char *)NULL);

    domainField = arkime_field_define("smb", "termfield",
                                      "smb.domain", "Domain", "smb.domain",
                                      "SMB domain",
                                      ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    verField = arkime_field_define("smb", "termfield",
                                   "smb.ver", "Version", "smb.version",
                                   "SMB Version information",
                                   ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                   (char *)NULL);

    dialectField = arkime_field_define("smb", "termfield",
                                       "smb.dialect", "Dialect", "smb.dialect",
                                       "SMB Dialect information",
                                       ARKIME_FIELD_TYPE_STR,  0,
                                       (char *)NULL);

    userField = arkime_field_define("smb", "termfield",
                                    "smb.user", "User", "smb.user",
                                    "SMB User",
                                    ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                    "category", "user",
                                    (char *)NULL);

    hostField = arkime_field_define("smb", "termfield",
                                    "host.smb", "SMB Host", "smb.host",
                                    "SMB Host name",
                                    ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_CNT,
                                    "category", "host",
                                    "aliases", "[\"smb.host\"]",
                                    (char *)NULL);

    arkime_field_define("smb", "lotextfield",
                        "host.smb.tokens", "Hostname Tokens", "smb.hostTokens",
                        "SMB Host Tokens",
                        ARKIME_FIELD_TYPE_STR_HASH,  ARKIME_FIELD_FLAG_FAKE,
                        "aliases", "[\"smb.host.tokens\"]",
                        (char *)NULL);

    fileField = arkime_field_define("smb", "termfield",
                                    "smb.files", "File", "smb.files",
                                    "Reconstructed file from SMB transfer",
                                    ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    /* NetBIOS 封装的 SMB (port 139): NBSS 头(4字节) + "\xffSMB" */
    arkime_parsers_classifier_register_tcp("smb", NULL, 5, (uint8_t *)"SMB", 3, smb_classify);
    /* 直连 SMB (port 445): 直接 "\xffSMB" */
    arkime_parsers_classifier_register_tcp("smb", NULL, 1, (uint8_t *)"SMB", 3, smb_classify);
}
