# SMTP 邮件还原功能修复计划

## 问题分析

还原的 `.eml` 文件不完整，原因是：

### 问题 1：邮件 header 没有被保存到 body 文件中

SMTP 的 `DATA` 命令后的内容分为两部分：
1. **Header 部分**（`EMAIL_DATA_HEADER` 状态）- 包含 From、To、Subject、Date、Message-ID 等 RFC 5322 头部
2. **Body 部分**（`EMAIL_DATA` 状态）- 空行之后的实际邮件内容

当前的实现只在 `EMAIL_DATA_RETURN` 中保存 body 内容，**没有保存 header 内容**。一个有效的 `.eml` 文件需要包含完整的 RFC 5322 格式：
```
From: sender@example.com
To: recipient@example.com
Subject: Test
Date: ...
Message-ID: ...

This is the email body.
```

### 问题 2：BDAT 模式结束时没有关闭 body 文件

BDAT（SMTP CHUNKING，RFC 3030）是 `DATA` 的替代方案。当 `bdatRemaining` 减到 0 时（第 998-1007 行），状态被直接重置为 `EMAIL_CMD`，没有经过 `EMAIL_DATA_RETURN` 中的 body 文件关闭和哈希存储逻辑。

### 问题 3：BDAT 模式的 body 保存位置不对

BDAT 数据是原始字节流，逐字符进入 `EMAIL_DATA` 状态。但 body 保存逻辑在 `EMAIL_DATA_RETURN` 中，依赖 `\r\n` 行结构。对于 BDAT，应该在字符级别保存数据。

## 修复方案

### 修复 1：在 EMAIL_DATA_HEADER 状态中也保存 header 到 body 文件

在 `EMAIL_DATA_HEADER_RETURN` 和 `EMAIL_DATA_HEADER_DONE` 中，将 header 行写入 body 文件。

**修改位置**：`smtp_parser()` 函数中的 `EMAIL_DATA_HEADER_RETURN` 和 `EMAIL_DATA_HEADER_DONE` 状态。

在 `EMAIL_DATA_HEADER_RETURN` 中：
- 当 `*line->str == 0`（空行，header 结束）时：如果 body 文件已打开，写入空行分隔符
- 当 `strcmp(line->str, ".") == 0`（空邮件）时：不处理
- 其他情况（header 行）：将 header 行写入 body 文件

在 `EMAIL_DATA_HEADER_DONE` 中：
- 将 header 行写入 body 文件（注意处理折叠行）

### 修复 2：在 BDAT 结束时关闭 body 文件

在循环末尾的 BDAT 处理代码中（第 998-1007 行），当 `bdatRemaining[which] == 0` 时，关闭 body 文件并存储哈希。

### 修复 3：BDAT 模式的 body 保存

对于 BDAT 模式，数据是原始字节流。应该在 `EMAIL_DATA` 状态中，当 `inBDAT` 被设置时，直接将每个字符写入 body 文件（而不是等待行结束）。

## 修改文件

仅修改 [`capture/parsers/smtp.c`](capture/parsers/smtp.c)

## 详细修改

### 修改 1：EMAIL_DATA_HEADER_RETURN - 保存 header 行

在 `case EMAIL_DATA_HEADER_RETURN:` 中，添加 body 文件写入逻辑：

```c
case EMAIL_DATA_HEADER_RETURN: {
    // ... 现有逻辑 ...
    
    if (strcmp(line->str, ".") == 0) {
        // 空邮件，不保存
        email->needStatus[which] = 1;
        *state = EMAIL_CMD;
    } else if (*line->str == 0) {
        // 空行 = header 结束，写入空行分隔符到 body 文件
        if (config.httpBodySave && email->bodyFile) {
            fwrite("\n", 1, 1, email->bodyFile);
        }
        *state = EMAIL_DATA;
        // ...
    } else {
        // header 行，写入 body 文件
        if (config.httpBodySave) {
            // 首次打开 body 文件
            if (!email->bodyFile) {
                char idBuf[256], path[512];
                arkime_session_id_string(session->sessionId, idBuf);
                snprintf(path, sizeof(path), "%s/%s_smtp_%u.eml",
                        config.contentSavePath, idBuf, email->bodyCount++);
                email->bodyFile = fopen(path, "wb");
                if (email->bodyFile) {
                    arkime_field_string_add(bodyFileField, session, path, -1, TRUE);
                    email->inBodySave = 1;
                    email->firstBodyChunk = 1;
                }
            }
            if (email->bodyFile) {
                fwrite(line->str, 1, line->len, email->bodyFile);
                fwrite("\n", 1, 1, email->bodyFile);
                // 更新校验和
                g_checksum_update(email->bodyChecksum[0], (guchar *)line->str, line->len);
                g_checksum_update(email->bodyChecksum[0], (guchar *)"\n", 1);
                if (config.supportSha256) {
                    g_checksum_update(email->bodyChecksum[1], (guchar *)line->str, line->len);
                    g_checksum_update(email->bodyChecksum[1], (guchar *)"\n", 1);
                }
                // 首次数据块进行 magic 检测
                if (email->firstBodyChunk) {
                    email->firstBodyChunk = 0;
                    arkime_parsers_magic(session, bodyMagicField, line->str, line->len);
                }
            }
        }
        *state = EMAIL_DATA_HEADER_DONE;
    }
    // ...
}
```

### 修改 2：EMAIL_DATA_HEADER_DONE - 处理折叠行

在 `case EMAIL_DATA_HEADER_DONE:` 中，对于折叠行（以空格或 tab 开头），也写入 body 文件：

```c
case EMAIL_DATA_HEADER_DONE: {
    *state = EMAIL_DATA_HEADER;
    
    if (*data == ' ' || *data == '\t') {
        // 折叠行，追加到 body 文件
        if (config.httpBodySave && email->bodyFile) {
            fwrite(" ", 1, 1, email->bodyFile);
        }
        g_string_append_c(line, ' ');
        break;
    }
    
    // ... 现有 header 解析逻辑 ...
    
    g_string_truncate(line, 0);
    if (*data != '\n')
        continue;
    break;
}
```

### 修改 3：BDAT 结束时关闭 body 文件

在循环末尾的 BDAT 处理代码中：

```c
if (email->inBDAT & 1 << which) {
    email->bdatRemaining[which]--;
    if (email->bdatRemaining[which] == 0) {
        /* BDAT chunk complete - close body file if open */
        if (email->bodyFile) {
            fclose(email->bodyFile);
            email->bodyFile = NULL;
            
            const char *md5 = g_checksum_get_string(email->bodyChecksum[0]);
            arkime_field_string_add(bodyMd5Field, session, (char *)md5, 32, TRUE);
            if (config.supportSha256) {
                const char *sha256 = g_checksum_get_string(email->bodyChecksum[1]);
                arkime_field_string_add(bodySha256Field, session, (char *)sha256, 64, TRUE);
            }
        }
        
        *state = EMAIL_CMD;
        email->inBDAT &= ~(1 << which);
    }
}
```

### 修改 4：EMAIL_DATA 中处理 BDAT 原始数据

对于 BDAT 模式，在 `EMAIL_DATA` 状态中直接保存字符：

```c
case EMAIL_DATA: {
    if (*data == '\r') {
        (*state)++;
        break;
    }
    g_string_append_c(line, (gchar)*data);
    break;
}
```

对于 BDAT，不需要修改 `EMAIL_DATA`，因为 BDAT 数据中如果包含 `\r\n`，仍然会经过 `EMAIL_DATA_RETURN` 处理。但 BDAT 的最后一个数据块可能没有 `\r\n` 结尾，这时 body 保存逻辑在 `EMAIL_DATA` 中不会触发。

实际上，对于 BDAT 模式，更简单的方式是在 `EMAIL_DATA` 状态中，如果 `inBDAT` 被设置，直接将字符写入文件：

```c
case EMAIL_DATA: {
    if (*data == '\r') {
        (*state)++;
        break;
    }
    g_string_append_c(line, (gchar)*data);
    
    /* For BDAT mode, write raw data directly to body file */
    if (email->inBDAT & (1 << which) && config.httpBodySave) {
        // ... 直接写入字符 ...
    }
    break;
}
```

但这样会导致重复写入（因为 `EMAIL_DATA_RETURN` 也会写入）。更好的方式是在 BDAT 结束时统一处理。

## 简化方案

考虑到 BDAT 的使用相对较少，且修复复杂度高，建议先修复最常见的 DATA 模式问题（header 未保存），BDAT 的修复可以放在后续。

### 优先级

1. **修复 header 未保存问题**（最关键）- 邮件 header 是 `.eml` 文件的核心组成部分
2. **修复 BDAT 结束时关闭文件**（次要）
3. **BDAT 原始数据保存**（可选）
