# SMTP 邮件还原修复计划 v3.1 - 修复 Content-Type 重复问题（修正版）

## 问题描述

还原的 `.eml` 文件中，当邮件头包含折叠行（folded header）时，Content-Type 行出现重复。例如：

```
Content-Type: multipart/alternative;
 Content-Type: multipart/alternative;	boundary="----=_NextPart_001_0005_01CA45B0.095693F0"
```

这导致 `.eml` 文件无法正常打开。

## 根因分析

RFC 5322 允许长 header 行通过折叠行延续到下一行，折叠行以空格或 tab 开头。

状态机处理流程：

```
EMAIL_DATA_HEADER: 累积 "Content-Type: multipart/alternative;"
  → EMAIL_DATA_HEADER_RETURN: 写入 "Content-Type: multipart/alternative;\n" 到 body 文件  ← 第一次写入
  → EMAIL_DATA_HEADER_DONE: 检测到 '\t'，写入 " " 到 body 文件，追加到 line
  → EMAIL_DATA_HEADER: 继续累积 "boundary=..."
  → EMAIL_DATA_HEADER_RETURN: line="Content-Type: multipart/alternative;\tboundary=..."
                             再次写入 body 文件  ← 第二次写入（重复！）
```

**关键问题**：`EMAIL_DATA_HEADER_RETURN` 在折叠行的第一段和完整行时都会被调用，导致 header 行被写入两次。

## v3.0 修复的问题

v3.0 使用 `inFoldedHeader` 标志跳过第二次写入，但导致折叠行的第二部分（如 `boundary=...`）丢失。

## v3.1 修正方案

**核心思路**：将 header 行的 body 文件写入逻辑从 `EMAIL_DATA_HEADER_RETURN` **移到** `EMAIL_DATA_HEADER_DONE`。这样每个 header 行只在解析完毕时写入一次，包含完整的折叠内容。

### 修改 1: EMAIL_DATA_HEADER_RETURN - 移除 header 行写入

在 [`capture/parsers/smtp.c:624`](../capture/parsers/smtp.c:624) 中，移除 header 行写入 body 文件的代码，只保留：
- "." 空消息处理（关闭 body 文件）
- 空行处理（写入 `\n` 分隔符）
- **打开 body 文件**（首次 header 行时）
- 状态转换到 `EMAIL_DATA_HEADER_DONE`

### 修改 2: EMAIL_DATA_HEADER_DONE - 添加 header 行写入

在 [`capture/parsers/smtp.c:710`](../capture/parsers/smtp.c:710) 中，在 header 解析代码之前，将完整的 `line` 写入 body 文件：

```c
case EMAIL_DATA_HEADER_DONE: {
    *state = EMAIL_DATA_HEADER;

    if (*data == ' ' || *data == '\t') {
        /* Folded header line - write continuation to body file */
        if (config.httpBodySave && email->bodyFile) {
            fwrite(" ", 1, 1, email->bodyFile);
            g_checksum_update(email->bodyChecksum[0], (guchar *)" ", 1);
            if (config.supportSha256) {
                g_checksum_update(email->bodyChecksum[1], (guchar *)" ", 1);
            }
        }
        g_string_append_c(line, ' ');
        break;
    }

    /* Non-folded line - write complete header line to body file */
    if (config.httpBodySave && email->bodyFile && line->len > 0) {
        fwrite(line->str, 1, line->len, email->bodyFile);
        fwrite("\n", 1, 1, email->bodyFile);
        g_checksum_update(email->bodyChecksum[0], (guchar *)line->str, line->len);
        g_checksum_update(email->bodyChecksum[0], (guchar *)"\n", 1);
        if (config.supportSha256) {
            g_checksum_update(email->bodyChecksum[1], (guchar *)line->str, line->len);
            g_checksum_update(email->bodyChecksum[1], (guchar *)"\n", 1);
        }
        if (email->firstBodyChunk) {
            email->firstBodyChunk = 0;
            arkime_parsers_magic(session, bodyMagicField, line->str, line->len);
        }
    }

    // ... existing header parsing code ...
```

### 修改 3: 移除 inFoldedHeader 标志

从 [`SMTPInfo_t`](../capture/parsers/smtp.c:71) 中移除 `inFoldedHeader` 字段（不再需要）。

### 修改 4: 同理处理 MIME 头

对 [`EMAIL_MIME_RETURN`](../capture/parsers/smtp.c:1005) 和 [`EMAIL_MIME_DONE`](../capture/parsers/smtp.c:1050) 做同样的修改：
- `EMAIL_MIME_RETURN`：移除 MIME header 行写入
- `EMAIL_MIME_DONE`：在 MIME header 解析前写入完整 line

## 预期效果

修复后，对于折叠 header：

```
Content-Type: multipart/alternative;
\tboundary="----=..."
```

body 文件中只写入一次完整的 header 行：

```
Content-Type: multipart/alternative;
 boundary="----=..."
```

不再出现重复行，`.eml` 文件可以正常打开。
