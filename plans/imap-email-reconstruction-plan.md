# IMAP 邮件还原实现计划

## 1. 背景分析

### 当前 IMAP 解析器状态
- 文件: `capture/parsers/imap.c` (270 行)
- 纯行解析器（line-by-line），使用 `memchr` 查找 `\n`
- 已解析字段: `email.src`、`email.dst`、`email.subject`、`email.folder`
- 无 body 文件保存功能
- 使用 `arkime_parsers_register`（无 save 回调）

### IMAP FETCH 响应格式
```
* 1 FETCH (BODY[] {1234}
<1234 bytes of email content - full RFC 5322 message>
)
```

关键点：
- `{size}` 表示 literal 数据的字节数
- literal 数据是完整的 RFC 5322 邮件（headers + body + attachments）
- literal 结束后，下一行通常是 `)`
- literal 数据可能包含任意二进制内容，不能按行处理

### 与 POP3 的关键区别
| 特性 | POP3 | IMAP |
|------|------|------|
| 响应格式 | 逐行传输，`.` 结束 | literal 格式 `{size}` + 精确字节数 |
| 行解析 | 可以按行处理 body | literal 数据不能按行处理 |
| 邮件内容 | 纯文本行 | 可能包含二进制附件 |

## 2. 实现方案

### 核心思路
IMAP 解析器需要从纯行解析器升级为**混合解析器**：
1. 正常模式下按行解析（处理命令和响应）
2. 检测到 `{size}` literal 时，切换到**原始数据模式**，直接将数据写入 body 文件
3. literal 结束后，恢复行解析模式

### 修改点

#### 2.1 IMAPInfo_t 结构体扩展

```c
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
```

#### 2.2 imap_parser() 修改 - 核心变更

当前 `imap_parser()` 是纯行解析器。需要改为：

```
imap_parser(session, uw, data, remaining, which):
    while remaining > 0:
        if imap->inLiteral:
            // 原始数据模式：直接写入 body 文件
            writeLen = min(remaining, imap->literalRemaining)
            if bodyFile is open:
                fwrite(data, writeLen, bodyFile)
                update checksums
                if firstBodyChunk: magic detection
            imap->literalRemaining -= writeLen
            remaining -= writeLen
            data += writeLen
            
            if imap->literalRemaining == 0:
                imap->inLiteral = FALSE
                // literal 结束，下一行应该是 ")"
                // 继续处理剩余数据（按行模式）
        else:
            // 正常行解析模式（现有逻辑）
            find \n in data
            if not found: buffer data, return
            process line
            advance to next line
```

#### 2.3 imap_process_line() 修改

在 `imap_process_line()` 中，当检测到 FETCH 响应中的 `{size}` 格式时，启动 literal 模式：

```c
// 在 server 响应处理中，检测 FETCH literal
if (which == imap->serverWhich) {
    if (imap->inFetch && len > 0) {
        // 检查是否包含 {size} 格式
        const char *brace = memchr(line, '{', len);
        if (brace) {
            const char *endBrace = memchr(brace, '}', line + len - brace);
            if (endBrace) {
                int size = atoi(brace + 1);
                if (size > 0) {
                    imap->inLiteral = TRUE;
                    imap->literalRemaining = size;
                    
                    // 打开 body 文件
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
                    
                    // literal 数据可能在当前行的 {size} 之后立即开始
                    // 格式: "* 1 FETCH (BODY[] {1234}\r\n<data>"
                    // literal 数据在下一行开始
                    return;
                }
            }
        }
    }
}
```

**重要：** IMAP literal 格式中，`{size}` 之后的数据在**下一行**开始。格式为：
```
* 1 FETCH (BODY[] {1234}
<1234 bytes of data...>
)
```

所以当检测到 `{size}` 时，我们只需设置 `inLiteral` 和 `literalRemaining`，实际数据会在下一次 `imap_parser()` 调用时处理。

#### 2.4 imap_free() 修改

```c
LOCAL void imap_free(ArkimeSession_t *session, void *uw)
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
```

#### 2.5 imap_save() 新增

```c
LOCAL void imap_save(ArkimeSession_t *session, void *uw, int final)
{
    IMAPInfo_t *imap = uw;
    if (!final)
        return;
    
    if (imap->bodyCount > 0) {
        const char *md5 = g_checksum_get_string(imap->checksum[0]);
        arkime_field_string_add(md5Field, session, (char *)md5, 32, TRUE);
        
        if (config.supportSha256) {
            const char *sha256 = g_checksum_get_string(imap->checksum[1]);
            arkime_field_string_add(sha256Field, session, (char *)sha256, 64, TRUE);
        }
    }
}
```

#### 2.6 imap_classify() 修改

```c
// 初始化 checksum
imap->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
if (config.supportSha256)
    imap->checksum[1] = g_checksum_new(G_CHECKSUM_SHA256);

// 使用 register2（支持 save 回调）
arkime_parsers_register2(session, imap_parser, imap, imap_free, imap_save);
```

#### 2.7 arkime_parser_init() 新增字段

```c
bodyFileField = arkime_field_define("imap", "termfield",
                                    "imap.bodyfile", "IMAP Body File", "imap.bodyFile",
                                    "IMAP email body saved file path",
                                    ARKIME_FIELD_TYPE_STR_HASH, 0,
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
```

#### 2.8 imap.detail.jade 新增

```jade
if (session.imap)
  div.sessionDetailMeta.bold IMAP
  dl.sessionDetailMeta(suffix="imap")
    +arrayList(session.imap, 'bodyFile', "Body Files", "email.bodyfile")
    +arrayList(session.imap, 'bodyMagic', "Body Magic", "email.body.bodymagic")
    +arrayList(session.imap, 'bodyMd5', "Body MD5s", "email.body.md5", null, null, session)
    if (session.imap.bodySha256)
      +arrayList(session.imap, 'bodySha256', "Body SHA256s", "email.body.sha256", null, null, session)
```

## 3. 数据流图

```mermaid
flowchart TD
    A[TCP 数据到达] --> B[imap_parser 接收数据]
    B --> C{imap->inLiteral?}
    
    C -->|是| D[原始数据模式]
    D --> D1[计算写入长度 = minremaining, data_len]
    D --> D2[写入 body 文件]
    D --> D3[更新 checksum]
    D --> D4[更新 literalRemaining]
    D --> D5{literalRemaining == 0?}
    D5 -->|是| D6[inLiteral = FALSE]
    D5 -->|否| D7[继续处理剩余数据]
    D6 --> B
    
    C -->|否| E[行解析模式]
    E --> E1[查找 \n]
    E1 --> E2{找到 \n?}
    E2 -->|否| E3[缓冲数据, 返回]
    E2 -->|是| E4[处理完整行]
    E4 --> E5{检测到 {size}?}
    E5 -->|是| E6[设置 inLiteral / literalRemaining]
    E5 -->|否| E7[正常行处理]
    E6 --> B
    E7 --> B
```

## 4. 执行步骤

| 步骤 | 文件 | 修改内容 |
|------|------|----------|
| 1 | `capture/parsers/imap.c` | 扩展 `IMAPInfo_t` 结构体，添加 body 保存字段 |
| 2 | `capture/parsers/imap.c` | 修改 `imap_parser()`：添加 literal 数据处理逻辑 |
| 3 | `capture/parsers/imap.c` | 修改 `imap_process_line()`：检测 `{size}` 格式，启动 literal 模式 |
| 4 | `capture/parsers/imap.c` | 修改 `imap_free()`：释放 body 文件和 checksum |
| 5 | `capture/parsers/imap.c` | 新增 `imap_save()`：保存 checksum 到 session |
| 6 | `capture/parsers/imap.c` | 修改 `imap_classify()`：初始化 checksum，使用 register2 |
| 7 | `capture/parsers/imap.c` | 修改 `arkime_parser_init()`：注册 body 相关字段 |
| 8 | `capture/parsers/imap.detail.jade` | 新建 Jade 模板文件 |
| 9 | 编译验证 | `make` 编译测试 |

## 5. 注意事项

1. **Literal 数据完整性**：`{size}` 指定了精确的字节数，必须确保写入完整数据
2. **跨 TCP 分段**：literal 数据可能跨越多个 TCP 包，`imap_parser()` 的 `while` 循环会持续处理直到 `remaining == 0`
3. **行缓冲冲突**：当 `inLiteral` 为 TRUE 时，不能将数据缓冲到 `imap->line`，必须直接处理
4. **文件路径**：使用 `config.contentSavePath` 配置的路径，文件命名格式为 `<sessionId>_imap_<count>.eml`
5. **与 SMTP/POP3 一致**：字段命名风格与 SMTP/POP3 保持一致，使用 `imap.*` 前缀
