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
