# SMB 文件提取修复计划

## 问题描述

测试 pcap (`/data/pcap/5.pcap`) 中包含通过 SMB 协议传输的 12 个 PDF 文件。其他工具（如 Wireshark）可以完整还原出 12 个 PDF，但 Arkime 的 SMB 解析器只还原出 3 个，且这 3 个文件都无法打开（内容损坏）。

## 根本原因分析

通过对 [`capture/parsers/smb.c`](capture/parsers/smb.c) 的全面代码审查，发现了以下关键问题：

---

### 问题 1（最严重）：SMB Read Request 未解析 FileId/FID

**位置**: SMB1 [`smb1_parse()`](capture/parsers/smb.c:694-704)，SMB2 [`smb2_parse()`](capture/parsers/smb.c:1247-1252)

SMB Read Response 不包含 FileId（SMB2）或 FID（SMB1），只有 Read Request 中携带了文件标识符。当前代码完全跳过了 Read Request 的解析：

```c
// SMB1 Read Request - 完全跳过
case SMB1_READ_ANDX: {
    if (which == 0) {
        /* 请求方: 只需要读取 FID 来确认读取目标 */
        /* 但数据在响应中，请求不需要特殊处理，直接 skip */
        *state = SMB_SKIP;
        break;
    }
```

```c
// SMB2 Read Request - 完全跳过
if (which == 0) {
    /* 请求: skip */
    *remlen -= (BSB_WORK_PTR(*bsb) - start);
    *state = SMB_SKIP;
    break;
}
```

**后果**: 响应数据不知道属于哪个文件，只能靠猜测。

---

### 问题 2：SMB Read Response 数据关联到错误文件

**位置**: SMB1 [`smb1_parse()`](capture/parsers/smb.c:740-749)，SMB2 [`smb2_parse()`](capture/parsers/smb.c:1319-1328)

由于没有从 Request 中获取 FileId，Response 处理时遍历所有已用文件槽并将数据附到"最后一个使用的文件"：

```c
// SMB2 Read Response - 错误地附加到最后一个使用的文件
for (int i = MAX_SMB_FILES - 1; i >= 0; i--) {
    if (smb->files[i].used) {
        smb_append_file_data(&smb->files[i], BSB_WORK_PTR(*bsb), availData);
        break;
    }
}
```

**后果**: 当多个文件同时传输时，数据会混入错误文件，导致：
- 部分文件数据缺失（只提取出 3 个而非 12 个）
- 文件内容损坏（提取出的 3 个无法打开）

---

### 问题 3：SMB2 Write Request 忽略文件偏移 (fileOffset)

**位置**: [`smb2_parse()`](capture/parsers/smb.c:1371-1391)

```c
uint64_t fileOffset = 0;
// ... 读取 fileOffset ...
/* 保持 fileOffset "used" 以避免 set-but-not-used 警告 */
(void)fileOffset;
```

数据被简单地 `smb_append_file_data()` 追加到缓冲区末尾，而非放在正确的文件偏移位置。当数据分多块写入且偏移不连续时，文件必然损坏。

---

### 问题 4：SMB2 Write Request 文件查找使用截断的 Handle

**位置**: [`smb2_parse()`](capture/parsers/smb.c:1411)

```c
uint16_t fid = (uint16_t)(persistentHandle & 0xFFFF);
SMBFileInfo_t *file = smb_find_file_by_fid(smb, fid);
```

64-bit Persistent Handle 被截断为 16-bit，当不同文件具有相同的低 16 位时，会产生哈希冲突，导致数据写入错误文件。

---

### 问题 5：并发文件槽数量限制

**位置**: [`smb.c`](capture/parsers/smb.c:21)

```c
#define MAX_SMB_FILES    8
```

仅 8 个槽位。12 个 PDF 并发传输时，超出部分会被静默丢弃。

---

### 问题 6：SMB2 未设置 flags2

**位置**: [`smb2_parse()`](capture/parsers/smb.c:981-1074)

SMB2 解析器从未设置 `smb->flags2[which]`，但 [`SMB2_TREE_CONNECT`](capture/parsers/smb.c:1114) 和 [`SMB2_CREATE`](capture/parsers/smb.c:1147) 中使用了 `smb->flags2[which] & SMB1_FLAGS2_UNICODE` 来判断字符串编码。对于 SMB2，所有字符串都是 Unicode (UCS-2LE)，因此应始终设置 SMB1_FLAGS2_UNICODE 标志。

---

## 修复方案

### 修复 1：Read Request 解析 FileId/FID 并跟踪

**目标**: 让 Read Response 能够正确关联到对应的文件。

**实现方案**:

1. 在 `SMBInfo_t` 结构体中添加字段：
   ```c
   uint64_t smb2ReadFileHandle;  // SMB2 当前读操作的文件句柄
   uint16_t smb1ReadFid;         // SMB1 当前读操作的 FID
   int      hasPendingRead;      // 是否有待处理的 Read Request
   ```

2. **SMB1 Read Request** 解析（`smb1_parse` case `SMB1_READ_ANDX`, `which==0`）：
   - 解析 WordCount 和参数区
   - 提取 FID（在 Read AndX Request 的 Word 5 中）
   - 存储到 `smb->smb1ReadFid`
   - 设置 `smb->hasPendingRead = 1`

3. **SMB2 Read Request** 解析（`smb2_parse` case `SMB2_READ`, `which==0`）：
   - 解析 SMB2 Read Request 结构体
   - 提取 FileId（Persistent Handle）
   - 存储到 `smb->smb2ReadFileHandle`
   - 设置 `smb->hasPendingRead = 1`

### 修复 2：Read Response 使用跟踪的 FileId 写入正确文件

**目标**: Read Response 数据写入正确文件槽。

**实现方案**:

1. **SMB1 Read Response**（`smb1_parse` case `SMB1_READ_ANDX`, `which==1`）：
   - 检查 `smb->hasPendingRead`
   - 使用 `smb->smb1ReadFid` 调用 `smb_find_file_by_fid()` 查找文件槽
   - 若找到，将数据附加到该文件槽
   - 清除 `smb->hasPendingRead`

2. **SMB2 Read Response**（`smb2_parse` case `SMB2_READ`, `which==1`）：
   - 检查 `smb->hasPendingRead`
   - 使用 `(uint16_t)(smb->smb2ReadFileHandle & 0xFFFF)` 查找文件槽
   - 若找到，将数据附加到该文件槽
   - 清除 `smb->hasPendingRead`

### 修复 3：SMB2 Write 使用完整 64-bit Handle（配合修复 4）

**位置**: `smb2_parse` case `SMB2_WRITE`

**方案 A（推荐）**: 在 `SMBFileInfo_t` 中添加 `uint64_t persistentHandle` 字段，使用完整 64-bit 匹配：

```c
// SMBFileInfo_t 新增字段
uint64_t persistentHandle;  // SMB2 的完整 64-bit Persistent Handle

// Create Response 时设置
file->persistentHandle = persistentHandle;

// Write Request 时查找
SMBFileInfo_t *file = smb_find_file_by_persistent_handle(smb, persistentHandle);
```

**方案 B（简化）**: 仅增大 fid 为 uint64_t，但需要考虑与 SMB1 的兼容性。

### 修复 4：SMB2 Write 处理文件偏移

**目标**: 数据按正确偏移写入，而非简单追加。

**实现方案**:

1. 在 `SMBFileInfo_t` 中添加偏移跟踪：
   ```c
   uint64_t writeOffset;  // 写操作的文件偏移
   ```

2. 在 SMB2 Write Request 处理中，使用 `fileOffset` 确定数据位置：
   - 如果 `fileOffset == file->dataLen`（顺序写入），直接追加
   - 如果 `fileOffset < file->dataLen`（重复/覆盖），更新已有数据
   - 如果 `fileOffset > file->dataLen`（有空洞），扩展缓冲区

3. 对于简单的顺序写入场景，至少确保：
   - 检查 `fileOffset` 是否与期望的 `dataLen` 匹配
   - 如果不匹配，记录警告日志
   - 始终按 `fileOffset` 放置数据

### 修复 5：增加 MAX_SMB_FILES

**位置**: [`smb.c`](capture/parsers/smb.c:21)

```c
#define MAX_SMB_FILES    32  // 从 8 增加到 32
```

同时增加 `smb2FileHandle` 和 `smb2FileName` 数组大小。

### 修复 6：SMB2 初始化 flags2

**位置**: `smb2_parse` case `SMB_SMBHEADER`

在 SMB2 头部解析完成后，设置：
```c
smb->flags2[which] = SMB1_FLAGS2_UNICODE;  // SMB2 始终使用 Unicode
```

### 修复 7：改进文件名提取和扩展名检测

**位置**: [`smb_save_file()`](capture/parsers/smb.c:263-340) 和 [`smb_detect_file_extension()`](capture/parsers/smb.c:148-259)

1. **优先使用 SMB 协议中的原始文件名和扩展名**：
   - 从 SMB Create/Open 消息中提取完整文件名
   - 如果文件名包含扩展名（如 `report.pdf`），优先使用协议中的扩展名
   - 魔数检测作为后备方案

2. **改进魔数检测**：
   - 确保至少读取足够字节用于检测
   - 添加更多文件类型的魔数检测

### 修复 8：优化文件槽释放时机

**位置**: `smb2_parse` case `SMB2_CLOSE`

当前 Close 处理中，文件保存后立即释放槽位。这可能导致同一个文件被多次 Create/Close 时，新 Create 分配了不同的槽位。确保 Close 正确清除所有关联的映射。

---

## 测试验证

### 使用测试 pcap 验证

```bash
# 编译修改后的 SMB 解析器
cd /data/arkime
./configure && make -j$(nproc)

# 运行 SMB 解析器处理测试 pcap
./capture/arkime -r /data/pcap/5.pcap --dryRun

# 检查提取的文件
ls -la /tmp/smb-*.pdf
```

### 预期结果

- 正确提取 12 个 PDF 文件
- 每个文件使用正确的文件名（如 `smb-document1.pdf`）
- 每个文件可以正常打开（内容完整）

### 回归测试

运行现有 SMB 测试确保不破坏已有功能：
```bash
cd /data/arkime/tests
perl smb.t
```

---

## 影响范围

| 文件 | 修改内容 | 影响 |
|------|---------|------|
| `capture/parsers/smb.c` | 结构体、常量、SMB1/SMB2 解析逻辑 | SMB 文件提取功能 |
| `tests/smb.t` | 新增文件提取测试用例 | 测试覆盖 |

## 优先级

1. **P0 - 阻塞性 Bug**（必须修复）：问题 1 + 2（Read Request/Response 关联）
2. **P0 - 阻塞性 Bug**（必须修复）：问题 4（Write offset 忽略）
3. **P1 - 功能缺陷**（应该修复）：问题 3（Handle 截断）
4. **P1 - 功能缺陷**（应该修复）：问题 5（MAX_SMB_FILES）
5. **P2 - 边缘情况**（可以修复）：问题 6（flags2）
6. **P2 - 改进**（可以修复）：问题 7（文件名处理）
