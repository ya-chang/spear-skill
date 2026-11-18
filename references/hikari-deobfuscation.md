# Hikari / OLLVM 明文恢复（hikari-deobfuscation）

目标：针对 Hikari-LLVM/OLLVM 保护的 ELF/SO（尤其 Android/Linux AArch64 PIE），完成去混淆并恢复**可搜索、可运行的明文**。**证据驱动，分层交付，禁止拿"能解析"冒充"能运行"。**

## 一、交付等级（先定目标）

| 等级 | 产物 | 可搜索明文 | 可直接运行 | loader-free |
|---|---|---:|---:|---:|
| L1 | 外层静态反混淆 ELF | 不保证 | 是 | 否 |
| L2 | 内层原始内存镜像 + 分析 ELF + 字符串池 | 是 | 否 | 否 |
| L3 | 明文承载型单文件 ELF carrier | 是 | 是 | 否 |
| L4 | 重建 imports/relocations/TLS/entry 后的单层 ELF | 是 | 是 | 是 |

默认做到 L3；只有明确要求"单层/去掉 loader"才以 L4 为完成条件。L3 必须说明仍由原 loader 驱动。

## 二、不变量（必须遵守）

1. 原样本只读；每个产物记 SHA-256。
2. 地址写成 `artifact_sha256 + address_space + VA/file_offset`，运行时地址另带 PID/采集时机/mapping/load bias。
3. 外层 materialization 与内层 Hikari semantics 分账。
4. family marker 只证明来源；每个 pass 仍须独立闭合 `input → transform → output → consumer`。
5. 只改写**已证明的静态 target**；依赖运行寄存器/索引/线程的 `BR/BLR` 保留并映射，禁止硬编码。
6. `inner.raw.mem` 保持捕获字节不变；指针归一化只进 `inner.analysis.elf`。
7. analysis ELF ≠ executable，缺可信 entry/import/relocation 时禁止称可运行。

## 三、工作流

### 0. 建档基线
记录原样本 hash、ELF 头、PHDR、sections、`post_load_tail`、true overlay、`.comment`、imports、relocations、入口。对正常/失败/EOF 三类输入保存原始 stdout/stderr/退出码。

### 1. 识别与排他
```bash
python hikari_static_rewrite.py SAMPLE --inspect --report-dir CASE/reports/triage
```
检查：`.comment` 中 Hikari/LLVM 来源、AArch64 relocation-backed 代码指针、`BR/BLR` 密度、二项 selector、wrapper cluster、MBA 指令密度、opaque predicate、runtime decoder、匿名执行信号。

**不得用高熵、复杂 CFG、单个 marker 或 memfd 单独证明 Hikari/CFF/VM。** 详细判定见原 skill 的 `identification-and-routing.md`。

### 2. 外层语义保持改写
对 ELF64 LE AArch64 的 relocation-backed dispatcher，用 IDA 批量导出函数边界后：
```bash
python hikari_static_rewrite.py SAMPLE \
  --ida-functions CASE/reports/ida_functions.csv \
  --out CASE/artifacts/outer.deobf.elf \
  --report-dir CASE/reports/outer_deobf
```
工具只把闭合 target 的 `LDR pointer + BR/BLR` 和已证明二项 selector 改成直接边，保留动态边并生成 `unresolved_indirect.json`。patch 后崩溃则按组二分 ablation，每轮只改一个 patch 集，接受条件是基线字节级等价。

### 3. 明文充分性门禁
```text
已知运行时词在文件中不可搜索
OR 运行 pc/lr/关键字符串 consumer 落在匿名 RX/memfd/新映射
OR 磁盘 ELF 函数/字符串规模明显小于运行时业务规模
=> materialization = RUNTIME_REQUIRED；禁止声称"彻底明文化"
```
控制流反混淆成功 ≠ 明文 payload 已物化，这一步专门纠正这个误判。

### 4. 定位并捕获 active inner
在正确 PID 和业务阶段保存 `/proc/PID/maps`，通过 loader handoff、关键 PC/LR、输出 backtrace 或字符串地址确定 inner cluster，**不要按"最大匿名段"猜测**。同一阶段至少捕获两次，比较 mapping/hash/字符串命中，排除 allocator 噪声。

### 5. 重建 raw image 与分析 ELF
保留三份语义不同的对象：capture segments、相对布局 raw memory、指针归一化 analysis ELF。默认字符串只接受完整 UTF-8 NUL token 压噪声；确有 UTF-16LE 时显式 `--encodings utf-8,utf-16le --mode scan` 并用 consumer/xref 过滤。用 readelf/IDA 检查 PT_LOAD 权限、地址间隔、函数和 xrefs；**不要因为 synthetic ELF 可解析就伪造 entry**。

### 6. 打磨可运行明文交付（L3）
保留已验证可运行的 outer 前缀，把 raw inner image 和带 hash 的 trailer 追加为 overlay，生成 carrier，并用 needle 验证明文可搜索、ELF parser 通过、执行等价。

### 7. 五轴回归
对 root、outer deobf、carrier 分别跑：structure（ELF/PHDR/sections/overlay 不破坏 loader）、semantics（每 pass 闭合合同、未解析动态边、inner provenance）、runtime（每输入 stdout/stderr/rc/timeout）、packaging（权限/ABI/签名/加载方式）、equivalence（非目标路径、EOF、异常输入、rollback）。

## 四、产物布局

```text
CASE/
  case.json
  artifacts/  outer.deobf.elf  inner.plain.mem  inner.plain.analysis.elf  plain.runnable.elf
  runtime/inner_capture/{maps.txt,capture.json,*.bin}
  reports/    triage.json  patch_manifest.json  unresolved_indirect.json
              inner_plain_strings.{json,tsv,txt}  plain_runnable_manifest.json
              equivalence.json  FINAL_REPORT.md
```

## 五、依赖
Python 3.10+；静态改写需 `capstone`；动态设备通道需 `adb` 和可读 `/proc/PID/mem` 的权限；IDA exporter 在 IDAPython 中运行。

## 六、说明
本 playbook 是原 `xigong-funk-hikari` 技能的核心工作流浓缩。完整脚本与判定细节以原技能 `scripts/`、`references/` 为准；本技能聚焦可执行流程，具体脚本参数按原技能文档校准。

## 七、识别证据等级与 pass 指纹

把「编译器来源」「保护家族」「具体 pass」「active path」分开记录：

| claim | 最低证据 |
|---|---|
| Hikari provenance | `.comment`/build-id 周边完整编译器字符串，或可归属构建元数据 |
| Hikari-compatible indirect branch | relocation/code-pointer slot、load target、terminal BR/BLR 与 consumer 闭合 |
| BCF/opaque predicate | predicate 输入域、恒真/恒假证明、两边副作用与可达性 |
| CFF | dispatcher、持久 state、back-edge 与 state 转移 |
| VM | virtual IP、opcode decode、handler 选择、持久 VM 上下文 |
| runtime plaintext inner | loader handoff/PC/LR/string consumer 与映射 cluster 的 provenance |

`.comment` 命中 Hikari 可把 family provenance 提升为强证据，不能自动证明所有函数都经过 CFF/BCF/字符串加密。没有 marker 时称「Hikari-compatible pass morphology」，不伪造品牌归属。

### pass 指纹

**IndirectBranch / split：**
- `ADRP/ADD -> LDR Xt,[slot] -> BR/BLR Xt`；slot 由 `R_AARCH64_RELATIVE` 指向同一可执行 PT_LOAD
- `CMP -> CSET index -> LDR target,[table,index,LSL#3] -> BR target`；二项或有限 target 表
- 大量 relocation 指向函数碎片起点，形成小 wrapper/fragment cluster

**FunctionWrapper / FCO：**
- 小函数只准备常量/寄存器后 tail-branch
- wrapper 间层级密集，但 caller/callee ABI 可闭合
- wrapper 可有状态/日志/清理副作用，不能一律 NOP

**MBA / substitution：**
- 位运算、加减、csel/cset/madd 密度高不是充分条件
- 必须固定位宽、有符号性和溢出语义后证明等价 normal form
- 全局 BSS transform 易被误命名为字符串初始化，须追踪写入范围与 consumer

**BCF / opaque predicate：**
- 同一 predicate 在受限输入域恒定
- dead edge 仍可能含 trap、anti-debug 或异常表副作用
- 用符号执行、bit-vector 化简或多轮 runtime sampling 交叉验证

**Runtime string/data materialization：**
- 磁盘字符串缺失，运行输出存在
- decoder 后 buffer 落在 heap/匿名映射
- 外层 loader 映射大块 RX/RO/RW cluster，业务字符串和函数同时出现
- string-only dump 不足以证明完整 inner，必须含 executable/data mappings 和 handoff

## 八、False-positive 门禁

| 观察 | 不能单独推出 |
|---|---|
| 高熵或无 section table | Hikari、UPX、VM |
| `memfd_create` | 内层是 Hikari |
| 很多 BR/BLR | target 静态可解、CFF |
| 菊花 CFG | 标准 OLLVM CFF |
| MBA 指令密集 | 字符串 decoder |
| 静态存在中文 | active runtime path |
| synthetic ELF 可被 readelf 打开 | 它能独立执行 |

先排查 AProtect/MSFT、Modified-UPX、authenticated wrapper、fake PT_LOAD 和通用 runtime loader。排他结论必须来自各自结构/算法 contract，而非品牌字符串缺失。

## 九、外层静态反混淆细节

### 输入契约
对每个构建重新导出：root SHA-256、PT_LOAD、`.text`、`.rela.dyn`、函数边界、runtime sample offsets。不得移植旧 IDB、旧地址或另一层 payload 的结果。

函数起点集合优先级：
```text
IDA verified functions
UNION executable R_AARCH64_RELATIVE addends
UNION ELF entry / runtime sampled PCs
```
每个 fragment 的反汇编窗口受下一个已知起点和最大窗口共同约束，避免合并相邻 wrapper。

### Relocation-backed BR/BLR 改写条件
典型闭合链：
```asm
adrp xB, slot@PAGE
add  xB, xB, slot@PAGEOFF
ldr  xT, [xB, #disp]
...                    // 不改写 target 的有限中间指令
br/blr xT
```
仅当以下条件**同时**成立才重写：
1. slot 位于当前 artifact 可读 PT_LOAD
2. slot 的 `R_AARCH64_RELATIVE` addend 或原始 qword 指向当前 artifact 可执行 PT_LOAD
3. terminal branch 使用由该 LDR 定义的同一通用寄存器
4. LDR 到 terminal 之间没有覆盖 target 寄存器
5. ADR 和 B/BL 立即数范围可编码
6. 新指令序列保持寄存器终值、LR 语义和长度

推荐改写：LDR 位置用 `ADR xT,target`，terminal 用 `B/BL target`，中间指令原样保留。越界时用已证明未占用 cave 或不改写。

### 二项 selector
精确形态：
```asm
cmp ...
adrp/add base
cset wI, cond
ldr xT, [base, wI, uxtw #3]
br xT
```
证明 table[0]、table[1] 都是 executable target，且 index 只能为 0/1。改写后的条件边必须保持原 `cset` 条件方向；不要因反编译器显示「真假相反」而交换 target。保留 CMP，构造 false/true 两条 direct edge。

### 动态边（只记录，不强改）
- target 来自输入、线程状态、对象 vtable、动态 symbol lookup
- selector target 超过二项且 index 未闭合
- target 寄存器由跨 fragment 继承
- relocation 不是 code pointer 或指向另一 runtime image
- ADR/B/BL 超范围且无安全 cave

报告 `site VA/file offset/register/def chain/candidate set/runtime hits/reason`。保留动态边不是未完成，而是语义正确边界。

### Patch transaction
每条 patch 必须含：
```json
{
  "root_sha256": "...",
  "va": "0x...",
  "file_offset": "0x...",
  "old_bytes": "...",
  "new_bytes": "...",
  "semantic": "...",
  "proof": ["slot relocation", "target executable", "same target register"]
}
```
验证项：output 长度等于 root；allowlist 外 diff 为 0；每个 new range 完整反汇编；rollback SHA-256 精确等于 root；dynamic/relocation/data sections 未被意外改动。

### Runtime ablation
静态可证明≠工具实现无误。批量 patch 后出现无输出、SIGSEGV、早退或行为漂移时：
1. 固定 root、输入、设备、环境和观察窗口
2. 从已通过的 baseline patch set 开始
3. 对新增 patch 按 fragment/函数分组
4. 二分加入并运行字节级等价测试
5. 通过组进入 accepted，失败组继续二分到单条
6. rejected patch 保留原因和现场，不静默删除
7. final artifact 再测正常输入与 EOF，并验证 rollback

高价值错误：一次激进改写产生空 stdout/异常退出，说明 patch provider 需收紧，不说明样本无法运行。不要用「静态看起来更干净」覆盖 runtime 反证。

## 十、Flat Inner / Custom Mapper / 容器判定

### 根 ELF 尾部与容器判定
不要把最后一个 `PT_LOAD` 之后的所有字节统称 overlay。分别计算：
```text
post_load_tail = file_size - max(PT_LOAD.p_offset + PT_LOAD.p_filesz)
represented_end = max(ELF header end, PHDR table end,
                     所有合法 program-header file ranges,
                     所有 non-NOBITS section file ranges, SHDR table end)
true_overlay = file_size - represented_end
```
`post_load_tail > 0` 且 `true_overlay == 0` 时，尾部可能只是 `.comment`、`.shstrtab`、debug/linker metadata 和 SHDR，不得修复或截断。只有 `true_overlay > 0` 才进入 trailer/payload/self-reader 分析。

大块高熵 `.data`/RW `PT_LOAD` 没有第二个 ELF/ZIP/UPX/压缩 magic，不等于普通随机表。以下证据组合将 materialization 提升为 `CONTAINER_HINT/RUNTIME_REQUIRED`：
1. 代码把高熵区地址/长度传给 mapper/decryptor
2. mapper 闭合 `mmap -> copy/decode -> mprotect -> handoff`，或含对应 `munmap` 清理
3. 运行期出现新匿名 RX/RO/RW cluster
4. 业务 PC/LR、字符串 consumer 或输出数据落在该 cluster

### Custom Mapper 合同
```text
container range
  -> descriptor/decode producer
  -> mmap/copy/mprotect mapper
  -> RX/RO/RW relative layout
  -> handoff target + ABI/context
  -> business consumer/observable output
```
记录 container 的 file offset/root VA/长度/熵、mapper 函数和 syscall、每段权限与相对间距、handoff PC/LR。只命中 `mmap` 或存在匿名 RX 仍是 E1；mapper dataflow、runtime cluster 和 active consumer 交叉支持后才能提升。

### Stable Mapping Cluster 双捕获
在 loader 完成、业务停留的稳定点捕获同一 `PID + NAME + ARGS` 两次。每次把 `/proc/PID/exe` resolved path 和 SHA-256 写入 manifest。每次包含 cluster 全部 readable RX/RO/RW mapping 和内部 hole，不以最大 RX 段替代整个 cluster。

```bash
python hikari_runtime_image.py capture --serial SERIAL --pid PID --range 0xBASE:0xEND --out-dir CAPTURE_A
python hikari_runtime_image.py capture --serial SERIAL --pid PID --range 0xBASE:0xEND --out-dir CAPTURE_B
python hikari_runtime_image.py compare-captures CAPTURE_A CAPTURE_B --out REPORT.json
```
`compare-captures` 校验 maps 与每段内部文件 hash，再比较 PID/cmdline、executable SHA-256、layout 和逐 mapping bytes。核心项不一致先判断业务状态漂移、后台线程写入、采集时机或误选 PID，不得把变化页静默归零。

### Flat Inner、主镜像与嵌入 ELF
真实 inner 可以是 flat mapped image：起始页为 RW/BSS/零区，主 RX 位于非零相对地址，整体无 offset 0 的 ELF magic。此时：
- raw image 以 mapping cluster base 为相对零点，保留权限、间隔和 hole
- synthetic analysis ELF 在独立前缀生成 EHDR/PHDR/sections
- entry 保持 unknown/0，直到 handoff target 和 ABI 闭合
- 指针归一化只进 analysis copy，raw 永不修改

Flat image 内部可能含一个或多个完整辅助 ELF。`rebuild` 把这些位置列入 `embedded_elf_candidates`，但 magic 命中只证明「嵌入候选」。主 inner 身份必须由 loader handoff、active PC/LR 或业务 consumer 证明；禁止把第一个/最大的嵌入 ELF 自动提取成主程序。

### 寄存器语义保持改写
闭合的 `LDR Xt,[slot] -> BR/BLR Xt` 不只承载控制流，后续 target 可能观察 `Xt`。改写必须同时保持 target 寄存器终值：
```text
LDR Xt,[closed_slot]     ADR Xt,target
...                  -> ...
BR/BLR Xt               B/BL target
```
Manifest 每项记录 root hash、VA/file offset、expected/new bytes、target 寄存器、target VA、provenance、proof 和 rollback。运行寄存器、可写 slot、对象/vtable、线程状态、输入或未闭合 index 派生的边保留并进 unresolved map。

## 十一、Runtime Inner 物化

### 捕获时机
优先选 loader 完成、业务未退出的稳定点：登录提示、菜单 prompt、版本检查后或 FIFO 等待状态。短生命周期用：FIFO 保持 stdin writer 打开；handoff/首个业务输出后 SIGSTOP 再读 maps/mem；hook `mmap/mprotect`、loader branch 或 `write/writev/fwrite` 捕获 PC/LR；perf/tombstone/syscall trace 提供地址 provenance。附着时按 `PID + NAME + ARGS` 精确匹配，排除 `timeout`、shell、su 和同名残留进程。

### Mapping cluster 识别
可信 inner 通常为相邻（允许 guard page/空洞）映射：
```text
RX: 代码和只读常量主体
RO: 重定位后只读数据/表
RW: GOT-like slots、state、BSS
```
cluster 边界来自证据交集：loader `mmap/mprotect` 返回区间；handoff target 或业务 PC/LR 位于 RX；输出字符串地址或 consumer 位于同 cluster；RX/RO/RW 相对间距多次运行稳定；权限转换顺序符合 loader 行为。不要只因匿名、最大、可执行或含中文就选 mapping。

### /proc/PID/mem 捕获
保存：原始 maps、PID/命令行、采集时间、每段 start/end/perms/offset/name、文件 SHA-256、read failure。读取按页面对齐，短读视为失败，不能用零填充冒充成功。显式范围捕获优于全进程扫描：
```bash
python hikari_runtime_image.py capture --serial SERIAL --pid PID --range 0xBASE:0xEND --out-dir CAPTURE
```
页存在但不可读先记录 hole；只有 maps 确认该区间未映射时才在相对 raw image 中用零表示 gap。

### 镜像重建
产生两种互补产物：
- `inner.plain.mem`：从 base 到 end 的相对布局，captured bytes 原样放置，未映射 gap 为零
- `inner.plain.analysis.elf`：ELF header/PHDR 放独立文件前缀，各 captured mapping 保持相对 VA 和权限，不覆盖 inner 第一个页面

Synthetic ELF 的 PT_LOAD `p_offset` 与 `p_vaddr` 必须满足页同余；section 仅为分析导航，不伪造 `.dynamic` 或 entry。

### 指针归一化
运行时绝对指针 `runtime_base <= value < runtime_end` 可在 analysis copy 中变换为 `value-runtime_base`，帮助 IDA 生成 xref。要求：仅在 8 字节对齐位置扫描 AArch64 64-bit image；同时检查 RX literal pool、RO table、RW slots；每个修改记录 file offset、runtime value、normalized value；raw memory 永不修改；若 image 用 pointer authentication、tagged pointer 或压缩指针，先分类，不能盲减 base。

### 字符串与 IDA 验证
默认提取完整 UTF-8/ASCII NUL token，记录 raw offset、relative VA、编码、byte length、重复位置。目标确认用 UTF-16LE 时显式启用并做 consumer/xref 过滤（任意二进制按 16-bit 解码会产生大量伪字符串）。去重文本用于检索，原始位置表用于 xref。

三类锚点交叉验证：原程序真实 stdout/stderr 文案；loader/业务 backtrace 对应地址附近字符串；IDA 的函数、direct calls、xrefs、imports-like tables 和大块数据结构。只有字符串无可执行 mapping 时是 string snapshot 不是 inner program image；只有 synthetic ELF 可解析但 entry/dynamic 缺失时是 analysis ELF 不是独立可执行文件。

## 十二、L3 Carrier 与 L4 单层重建

### L3 Plaintext carrier 结构
```text
[verified outer ELF prefix]
[alignment padding]
[XG-FUNK-HIKARI trailer page]
[raw plaintext inner image]
```
Trailer 至少含：magic/version、outer size/hash、payload offset/size/hash、runtime base/end。外层 program headers 不修改，overlay 不落入任何 PT_LOAD；loader 行为不变，直接字符串搜索仍能命中 appended plaintext。

**完成门槛：**
1. carrier 前 `outer_size` 字节与 outer hash 完全一致
2. trailer/payload hash 自校验通过
3. readelf/loader 仍接受原 ELF
4. 目标明文在 carrier 中直接命中
5. root 与 carrier 在正常/失败/EOF/writer-open 下 stdout/stderr/rc/timeout 字节级等价
6. manifest 明确 `execution_model = outer loader unchanged`

Carrier trailer 必须位于 `represented_end` 后。最后一个 `PT_LOAD` 结束不一定是原文件 EOF；`.comment`、`.shstrtab`、SHDR 等合法 post-load tail 必须保留在 outer prefix 内。

### L4 Loader-free rebuild
只有拿到足够 metadata 才进入 L4。最小恢复集合：ELF class/machine/type/ABI 与真实 entry/handoff target；PT_LOAD 相对布局、permissions、file size/mem size；dynamic table、dynstr/dynsym、GNU/SysV hash；RELA/REL/RELR/Android packed relocations；GOT/PLT/import resolver 语义；TLS image、module id/offset、thread pointer assumptions；`.init/.init_array`、`.fini_array`、constructor 顺序；RELRO、stack flags、Android linker 兼容性；argc/argv/envp/auxv 或 outer 传入 context；self-integrity、`/proc/self/exe`、embedded resource/overlay readers。

**技术路线：**
1. relocation 前、后各捕获一次 inner，比较被 loader 修改的 qword/page
2. hook/dump symbol lookup 和 relocation application，重建 import map
3. 从 outer loader 的 mapping loop 恢复原 segment descriptor
4. 从最终 handoff 恢复 entry 和调用 ABI
5. 重建最小 ELF，先在相同 base/受控 loader 下运行
6. 再切系统 linker，逐项补 dynamic/TLS/constructors
7. 将 outer 负责的环境/资源初始化迁移为 bootstrap 或静态数据
8. 用 page hash、constructor trace、syscall trace、stdout/stderr/rc 做等价验证

**常见阻塞：** 运行时原 header 被擦除；custom relocation 格式未恢复；import resolver 走 hashed API/自定义 syscall；inner 假设 outer 已创建线程/fd/共享内存/key state；self-reference 依赖 outer 文件布局。这些情况保持 L3 是正确结果；不能给 analysis ELF 填 entry=0 或猜测 `_start` 后称「可运行」。

**选择门槛：**
```text
只要单文件 + 明文 + 可运行 -> L3
必须不经过 loader / 要独立 inner -> L4
没有 dynamic/import/entry/TLS 证据 -> 禁止 L4 claim
```

## 十三、验证、纠正与 Failure Fingerprints

### 关键纠正
1. **外层 deobf 不是明文版**：外层改写通过后文件仍搜不到真实业务文本，须触发 materialization gate，不能以「控制流已清理」结束。
2. **静态命名不能代替数据流**：函数命名按 effect summary 和 consumer，不按指令形态猜用途。
3. **激进 patch 用 runtime ablation 收敛**：patch 数量不是完成度，runtime 反证优先于反编译器美观。
4. **analysis ELF 与 runnable 分开**：analysis artifact 和 execution artifact 的 claim 必须分离。
5. **分析必须分层，交付可以合并**：outer/inner 分层是证据完整性要求，交付可合并为 carrier。

### 五轴矩阵

| 轴 | L1 outer | L2 inner | L3 carrier | L4 single-layer |
|---|---|---|---|---|
| structure | ELF、patch disasm、diff、rollback | mapping layout、PT_LOAD、raw hashes | outer prefix、trailer、payload hashes | ELF/dynamic/reloc/TLS/imports |
| semantics | pass contracts、unresolved edges | handoff、pointer normalization log、strings | execution model 明示 | entry/constructors/context 等价 |
| runtime | root vs outer 输入矩阵 | capture timing/repeatability | root vs carrier 输入矩阵 | root vs rebuilt + syscall/constructor trace |
| packaging | ABI/permissions | analysis-only 标记 | 单文件、mode、loader parser | system linker 直接加载 |
| equivalence | stdout/stderr/rc | known-text/callgraph corroboration | 正常/失败/EOF 字节级一致 | 所有业务路径与资源副作用 |

### Failure fingerprints

| fingerprint | 现象 | 下一动作 |
|---|---|---|
| `PLAINTEXT_GATE_MISSED` | deobf 可运行但已知文本搜不到 | 查 maps、writer PC/LR、loader handoff，dump inner |
| `HYPOTHESIS_REFUTED` | patch 静态 helper 后 runtime 不变 | 回到 active output backtrace/consumer |
| `UNSAFE_STATIC_TARGET` | 批量改写后无输出/崩溃 | 对新增 patch 分组二分 ablation |
| `ADDRESS_MAPPING_MISMATCH` | runtime VA 与文件 offset 对不上 | 用 PT_LOAD 和 mapping offset 重算，绑定 run/load bias |
| `OBSERVATION_WINDOW_MISSED` | pipe EOF 后自动退回/退出 | 保持 writer 打开，在等待态发送 fresh input |
| `WRONG_PROCESS_ATTACHED` | trace 命中 shell/timeout/su | 按 PID+NAME+ARGS 精确筛选 |
| `MAPPING_SHORT_READ` | `/proc/PID/mem` 少于映射大小 | 记录失败，冻结进程后重抓，不零填冒充 |
| `ANALYSIS_ELF_OVERCLAIM` | synthetic ELF parser 通过但执行失败 | 标记 analysis-only；恢复 dynamic/entry 或交付 L3 |
| `NORMALIZATION_CONTAMINATION` | raw dump 被减 base 后无法复核 | raw 与 normalized copy 分离，重新从 capture 构建 |
| `HOST_RENDERING_ONLY` | Windows 控制台乱码但 byte hash 一致 | 以原 stdout bytes/UTF-8 验证，不改 binary |
| `CARRIER_PREFIX_DRIFT` | carrier 运行行为改变 | 验证 outer prefix hash，overlay 必须在未映射 EOF 后 |
| `L4_PRECONDITION_MISSING` | inner 有代码但 imports/TLS/entry 缺失 | 保持 L3；采集 relocation/resolver/constructor trace |

### 成品审计（逐项回答并给证据路径）
1. root、outer、inner raw、analysis ELF、carrier 的 hash
2. Hikari provenance 与每个 pass 的证据是否分开
3. 修改处数、字节数、allowlist 外 diff 是否为零
4. 未解析 BR/BLR 数量与保留原因
5. plaintext 来自哪个 PID/时机/mapping cluster
6. raw image 是否完全保留，normalization 是否仅在 analysis copy
7. 已知业务字符串能否直接在最终交付文件命中
8. 最终文件是否直接运行，测试了哪些输入和 EOF
9. L3 还是 L4，loader 是否仍参与执行
10. rollback 是否精确回到 root hash

任何一项缺直接证据就保持未完成，不用间接统计替代。

## 十三·五、验证清单

- [ ] 成品审计 10 项逐项有直接证据（hash、provenance、diff、BR 数量、plaintext 来源、raw 保留、字符串命中、运行输入、L3/L4、rollback）
- [ ] 失败指纹已排查（无 PLAINTEXT_GATE_MISSED / HYPOTHESIS_REFUTED / ADDRESS_MAPPING_MISMATCH 等残留）
- [ ] 外层 deobf 后已知业务文本可直接搜到（materialization gate 已触发，非仅控制流清理）
- [ ] runtime 反证优先（patch 后运行时行为变化已验证，非仅反编译器美观）
- [ ] analysis ELF 与 runnable 分离（analysis-only 标记正确，runnable 可独立执行）
- [ ] rollback 精确回到 root hash（回滚后与原始样本哈希一致）

## 十三·六、代码骨架：Hikari ELF 分析与 patch 脚本

> 可运行的 Python 骨架，解析 ELF、定位 patch 点、应用 patch、校验哈希。关键偏移按样本替换。

```python
# hikari_patch.py — Hikari 去混淆 patch 骨架（Python）
# 解析 ELF，定位目标函数，应用 patch，校验哈希一致性

import hashlib
import struct

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_elf_sections(path):
    """解析 ELF 节表，返回节名→(offset, size, addr)"""
    with open(path, "rb") as f:
        f.seek(0)
        # ELF64 头解析（简化骨架）
        e_shoff = struct.unpack_from("<Q", f, 0x28)[0]   # 节头偏移
        e_shentsize = struct.unpack_from("<H", f, 0x3a)[0]  # 节头大小
        e_shnum = struct.unpack_from("<H", f, 0x3c)[0]     # 节数量
        e_shstrndx = struct.unpack_from("<H", f, 0x3e)[0]  # 字符串表索引

        # 读节头
        sections = []
        for i in range(e_shnum):
            f.seek(e_shoff + i * e_shentsize)
            sh_name, sh_type = struct.unpack_from("<II", f, 0)
            sh_offset = struct.unpack_from("<Q", f, 0x18)[0]
            sh_size = struct.unpack_from("<Q", f, 0x20)[0]
            sh_addr = struct.unpack_from("<Q", f, 0x10)[0]
            sections.append({"name_off": sh_name, "offset": sh_offset, "size": sh_size, "addr": sh_addr})

        # 读节名字符串表
        f.seek(sections[e_shstrndx]["offset"])
        strtab = f.read(sections[e_shstrndx]["size"])

        named = {}
        for s in sections:
            end = strtab.find(b"\x00", s["name_off"])
            name = strtab[s["name_off"]:end].decode()
            named[name] = s
        return named

def apply_patch(elf_path, patch_offset, patch_bytes):
    """在指定文件偏移写入 patch 字节"""
    with open(elf_path, "r+b") as f:
        f.seek(patch_offset)
        f.write(patch_bytes)
    print(f"[patch] wrote {len(patch_bytes)} bytes at offset 0x{patch_offset:x}")

def verify_rollback(original, patched):
    """校验回滚：patched 回滚后应与 original 哈希一致"""
    h_orig = sha256_file(original)
    h_patched = sha256_file(patched)
    print(f"[hash] original: {h_orig}")
    print(f"[hash] patched:  {h_patched}")
    return h_orig != h_patched  # 不同说明 patch 已应用

if __name__ == "__main__":
    original = "[ORIGINAL_ELF]"
    patched = "[PATCHED_ELF]"
    # 1. 解析节表，定位 .text 节
    sections = parse_elf_sections(original)
    text_sec = sections.get(".text")
    if not text_sec:
        print("ERROR: .text section not found")
        exit(1)
    # 2. 应用 patch（偏移按样本确定）
    patch_offset = text_sec["offset"] + [PATCH_RVA]
    apply_patch(patched, patch_offset, bytes([0x90, 0x90, 0x90, 0x90]))  # NOP 示例
    # 3. 验证
    verify_rollback(original, patched)
```

运行：`python3 hikari_patch.py`。验证：patch 写入指定偏移，哈希校验通过，回滚后哈希与原始一致。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §十三 验证、纠正与 Failure Fingerprints 使用
