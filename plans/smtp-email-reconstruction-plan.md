# SMTP 邮件还原功能实现计划

## 背景分析

当前 Arkime 的 SMTP 解析器（[`capture/parsers/smtp.c`](capture/parsers/smtp.c)）仅提取邮件**元数据**（发件人、收件人、主题、附件哈希等），**不保存原始邮件正文到磁盘文件**。相比之下，POP3 解析器（[`capture/parsers/pop3.c`](capture/parsers/pop3.c)）已经实现了将邮件正文保存为 `.eml` 文件的功能。

## 目标

在 SMTP 解析器中增加邮件正文保存功能，将 SMTP 会话中传输的完整邮件（包括 DATA 和 BDAT 命令）保存为 `.eml` 文件，并在 Web 界面上展示文件路径和相关信息。

---

## 修改方案

### 1. 修改 [`capture/parsers/smtp.c`](capture/parsers/smtp.c) - SMTP 解析器

#### 1.1 新增字段定义

在 `arkime_parser_init()` 函数中新增以下字段：

| 字段表达式 | 友好名称 | 说明 |
|-----------|---------|------|
| `email.bodyfile` | SMTP Body File | 保存的邮件文件路径 |
| `email.bodymd5` | SMTP Body MD5 | 邮件正文 MD5（与附件 MD5 区分） |
| `email.bodysha256` | SMTP Body SHA256 | 邮件正文 SHA256 |
| `email.bodymagic` | SMTP Body Magic | 邮件正文内容类型 |

#### 1.2 修改 `SMTPInfo_t` 结构体

在现有结构体中新增：

```c
typedef struct {
    // ... 现有字段 ...
    FILE              *bodyFile;          // 邮件正文文件指针
    GChecksum         *bodyChecksum[2];   // bodyChecksum[0]=MD5, bodyChecksum[1]=SHA256
    uint16_t           bodyCount;         // 邮件正文计数
    uint16_t           inBodySave: 1;     // 是否正在保存正文
    uint16_t           firstBodyChunk: 1; // 是否是第一个正文块（用于 magic 检测）
} SMTPInfo_t;
```

#### 1.3 修改 `smtp_classify()` 函数

在注册解析器时初始化新的 checksum：

```c
// 新增 bodyChecksum 初始化
email->bodyChecksum[0] = g_checksum_new(G_CHECKSUM_MD5);
if (config.supportSha256)
    email->bodyChecksum[1] = g_checksum_new(G_CHECKSUM_SHA256);
```

#### 1.4 修改 `smtp_free()` 函数

释放新增的资源：

```c
// 关闭文件
if (email->bodyFile)
    fclose(email->bodyFile);
// 释放 checksum
g_checksum_free(email->bodyChecksum[0]);
if (config.supportSha256)
    g_checksum_free(email->bodyChecksum[1]);
```

#### 1.5 修改 `smtp_parser()` 函数 - DATA 状态处理

在 `EMAIL_DATA_RETURN` 状态（[`smtp.c:730`](capture/parsers/smtp.c:730)）中增加正文保存逻辑：

**关键位置**：当收到 "." 结束行时（第 736 行），在重置状态之前，关闭文件并保存哈希。

**保存逻辑**（参考 POP3 的 [`pop3.c:121-151`](capture/parsers/pop3.c:121)）：

1. **文件保存**：在 `EMAIL_DATA` 状态中，逐行将邮件正文写入文件
   - 文件路径格式：`{contentSavePath}/{sessionId}_smtp_{bodyCount}.eml`
   - 使用 `config.contentSavePath` 配置（默认 `/data/file`）
   - 受 `config.httpBodySave` 配置控制

2. **dot-stuffing 处理**：SMTP 协议中，以 "." 开头的行表示正文结束（RFC 5321），正文中的 "." 会被转义为 ".."，需要还原

3. **BDAT 支持**：对于使用 BDAT 命令（SMTP CHUNKING 扩展）的会话，同样需要保存正文

4. **哈希计算**：在写入文件的同时，更新 MD5 和 SHA256 校验和

5. **Magic 检测**：对第一个数据块调用 `arkime_parsers_magic()` 检测内容类型

#### 1.6 修改 `smtp_parser()` 函数 - 保存回调

在 `EMAIL_CMD_RETURN` 状态中，当检测到 DATA 命令完成（收到 "." 或 BDAT 结束）时，在 `pop3_save` 类似的逻辑中：

```c
// 在 smtp_parser 中，当 DATA 结束时：
if (/* DATA 结束条件 */) {
    // 关闭文件
    if (email->bodyFile) {
        fclose(email->bodyFile);
        email->bodyFile = NULL;
    }
    // 保存 MD5
    if (email->bodyCount > 0) {
        const char *md5 = g_checksum_get_string(email->bodyChecksum[0]);
        arkime_field_string_add(bodyMd5Field, session, (char *)md5, 32, TRUE);
        if (config.supportSha256) {
            const char *sha256 = g_checksum_get_string(email->bodyChecksum[1]);
            arkime_field_string_add(bodySha256Field, session, (char *)sha256, 64, TRUE);
        }
    }
}
```

### 2. 新增 [`capture/parsers/smtp.detail.jade`](capture/parsers/smtp.detail.jade) - Web 详情模板

创建新的 Jade 模板文件，在 SMTP 会话详情中展示邮件正文信息：

```jade
if (session.email)
  div.sessionDetailMeta.bold SMTP Body
  dl.sessionDetailMeta(suffix="smtp")
    +arrayList(session.email, 'bodyFile', "Body Files", "email.bodyfile")
    +arrayList(session.email, 'bodyMagic', "Body Magic", "email.bodymagic")
    +arrayList(session.email, 'bodyMd5', "Body MD5s", "email.body.md5", null, null, session)
    if (session.email.bodySha256)
      +arrayList(session.email, 'bodySha256', "Body SHA256s", "email.body.sha256", null, null, session)
```

### 3. 修改 [`capture/parsers/email.detail.jade`](capture/parsers/email.detail.jade) - 集成展示

在现有 email 详情模板中增加 body 文件相关展示行，或通过条件判断展示。

---

## 详细实现步骤

### 步骤 1：修改 `SMTPInfo_t` 结构体

在 [`smtp.c:43-58`](capture/parsers/smtp.c:43) 的结构体中新增字段。

### 步骤 2：新增字段变量

在 [`smtp.c:22-41`](capture/parsers/smtp.c:22) 的全局变量区域新增：
- `bodyFileField`
- `bodyMd5Field`  
- `bodySha256Field`
- `bodyMagicField`

### 步骤 3：在 `arkime_parser_init()` 中注册新字段

在 [`smtp.c:983-1139`](capture/parsers/smtp.c:983) 的 `arkime_parser_init()` 函数末尾新增字段定义。

### 步骤 4：修改 `smtp_classify()` 初始化

在 [`smtp.c:950-981`](capture/parsers/smtp.c:950) 的 `smtp_classify()` 中初始化 bodyChecksum 和 bodyFile。

### 步骤 5：修改 `smtp_free()` 清理

在 [`smtp.c:926-948`](capture/parsers/smtp.c:926) 的 `smtp_free()` 中释放 body 相关资源。

### 步骤 6：修改 `smtp_parser()` DATA 处理逻辑

在 [`smtp.c:719-798`](capture/parsers/smtp.c:719) 的 `EMAIL_DATA` 和 `EMAIL_DATA_RETURN` 状态中增加正文保存逻辑。

### 步骤 7：创建 `smtp.detail.jade`

创建新的 Jade 模板文件。

### 步骤 8：重新编译

运行 `make` 重新编译解析器。

---

## 关键设计决策

### 1. 文件命名格式

参考 POP3 的命名格式 `{sessionId}_pop3_{count}.eml`，SMTP 使用：
```
{contentSavePath}/{sessionId}_smtp_{bodyCount}.eml
```

### 2. 配置控制

复用现有的 `config.httpBodySave` 配置项（[`config.c:1313`](capture/config.c:1313)），当设置为 `true` 时启用邮件正文保存。

### 3. 多邮件支持

SMTP 会话可能包含多封邮件（通过多次 DATA 命令），使用 `bodyCount` 计数器区分。

### 4. BDAT 支持

SMTP CHUNKING 扩展（RFC 3030）使用 BDAT 命令代替 DATA，需要在 BDAT 处理路径中也增加正文保存逻辑（[`smtp.c:496-512`](capture/parsers/smtp.c:496)）。

### 5. 附件 vs 正文

当前 SMTP 解析器已经对 MIME 附件进行 Base64 解码并计算哈希。新增的正文保存功能保存的是**原始邮件内容**（包括邮件头和所有 MIME 部分），与附件哈希是互补关系。

---

## 影响范围

| 文件 | 修改类型 | 说明 |
|------|---------|------|
| [`capture/parsers/smtp.c`](capture/parsers/smtp.c) | 修改 | 新增字段、结构体、保存逻辑 |
| [`capture/parsers/smtp.detail.jade`](capture/parsers/smtp.detail.jade) | 新增 | Web 详情展示模板 |
| [`capture/parsers/email.detail.jade`](capture/parsers/email.detail.jade) | 可选修改 | 集成展示 body 文件信息 |

## 风险与注意事项

1. **磁盘空间**：保存邮件正文会占用磁盘空间，需确保 `contentSavePath` 目录有足够空间
2. **性能**：文件 I/O 操作可能影响解析性能，但参考 HTTP 和 POP3 的实现，影响可控
3. **隐私**：保存的邮件文件包含敏感信息，需确保文件权限设置正确
4. **TLS 加密**：如果 SMTP 会话使用 STARTTLS 加密，则无法解析邮件内容（当前解析器在 STARTTLS 后会切换到 TLS 模式并忽略后续数据）
