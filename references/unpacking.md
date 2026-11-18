# 脱壳（unpacking）

目标：剥掉压缩/保护壳，拿到原始代码。**先识别，再脱壳，脱完验证。**

## 一、识别加壳

```bash
# 熵值检测：> 7.0 疑似加壳/加密
python3 -c "
import math, collections, sys
d=open(sys.argv[1],'rb').read()
f=collections.Counter(d)
h=-sum((c/len(d))*math.log2(c/len(d)) for c in f.values())
print(f'entropy={h:.4f}', 'PACKED' if h>7.0 else 'normal')" target

# 特征字符串
strings -a target | grep -iE "upx|vmprotect|themida|vmp|themida|ollvm|petite|aspack"

# 段分析
readelf -S target | grep -iE "upx|vmp|themida"
r2 -q -c 'iS~entropy; iS' target
```

| 特征 | 判断 | 处置 |
|---|---|---|
| `UPX!` 魔数 + UPX0/UPX1 段 | UPX | `upx -d` |
| 段名 `.vmp0/.vmp1` + 高熵 | VMProtect | 动态 dump（见下） |
| `.themida`/`.enigma` 段 | Themida/Enigma | 动态 dump |
| 段极少（2-3 段）+ 高熵 | 通用压缩壳 | 动态 dump |
| 高熵段 + 小解压 stub | 自定义压缩壳 | 动态 dump |

## 二、UPX 脱壳（最简单）

```bash
upx -t target            # 自检
upx -d target -o unpacked
file unpacked            # 确认变回正常 ELF
r2 -A unpacked           # 重新分析
```

UPX 用 `strings` 命中即 100% 确认，无需进一步验证。

## 三、商业壳/自定义壳动态脱壳

核心：在代码解密完成后、原始入口执行前，dump 内存。

**方法 A：mprotect 断点 + 单步到 OEP**

```bash
# 在 mprotect 被调用时停下，之后程序会解密代码
gdb -q ./target
(gdb) catch syscall mprotect
(gdb) run
# 多次触发后，从最后一次 mprotect 继续单步，直到跳到原始入口(OEP)
(gdb) x/16i $pc
(gdb) dump binary memory dumped.bin START END
```

**方法 B：Frida 内存扫描（找解密后的代码/字符串）**

```javascript
// frida_dump.js — 启动后扫描可打印字符串或代码段
Java.perform(() => {}); // 桌面无需
const start = Date.now();
let last = null;
setInterval(() => {
  const ranges = Process.enumerateRanges('r--');
  for (const r of ranges) {
    const mem = r.base.readByteArray(Math.min(r.size, 0x100000));
    if (mem) { /* 扫描明文字符串/代码特征，命中则 dump */ }
  }
}, 500);
```

```bash
frida -f ./target -l frida_dump.js --no-pause
```

**方法 C：导入表重建（找 OEP 后修复 IAT）**

dump 到 OEP 后，原始导入表可能被破坏，用以下工具重建：
- `ImportREC`（Windows PE）
- `ilya` / 自写脚本解析 `.dynamic`（ELF）
- r2 `idp` / `wav` 修复

## 四、Android DEX 壳（壳内 DEX 恢复）

APK 壳特征：小 `classes.dex`、`libabcd.so`、`assets/lib*Protect*`、`v.m.p`/`abcd655xx`、运行时才 materialize 真实 DEX。

```bash
# Frida 抓运行时 DEX
frida -U -f com.target.app -l capture_dex.js
```

```javascript
// capture_dex.js — 扫描进程内存中的 DEX 头 (\xde\x00\x00\x00 或 dey)
const DEX_MAGIC = [0xde,0x00,0x00,0x00]; // dex\0
Process.enumerateRanges('r--').forEach(r => {
  const buf = r.base.readByteArray(Math.min(r.size, 0x2000000));
  if (!buf) return;
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length - 4; i++) {
    if (bytes[i]===0xde && bytes[i+1]===0x00 && bytes[i+2]===0x00 && bytes[i+3]===0x00) {
      console.log('DEX @', r.base.add(i).toString());
      // 完整 dump 该 DEX（按 header.file_size）
    }
  }
});
```

脱完壳后转 `elf-apk-patch.md` 做重组签名，或 `deobfuscation.md` 继续。

## 五、脱壳验证

- [ ] 脱壳后文件熵值回落到正常（`binwalk`/`ent` 检测 < 6.5）
- [ ] `file` 识别为正常 ELF/PE（非"data"或"unknown"）
- [ ] 能正常运行，功能与原程序一致（执行关键功能无崩溃）
- [ ] 静态分析能看到完整函数与字符串（IDA/Ghidra 反编译有有效函数体）
- [ ] IAT 完整可修复（导入表函数地址指向合法模块，无悬空指针）

## 五·五、代码骨架：UPX 内存 dump 脱壳脚本

> 可运行的 UPX 脱壳骨架，在 OEP 断下后 dump 内存并修复。关键偏移按样本替换。

```python
# upx_unpack.py — UPX 脱壳 dump 骨架（Linux ELF 示例，PE 同理）
import os, sys, struct

TARGET = "[TARGET_BINARY]"
OEP_OFFSET = [OEP_RVA]  # OEP 相对基址偏移，从 IDA/GDB 定位

def dump_and_fix(pid, oep_rva, base_addr):
    """在 OEP 断下后 dump .text 段并修复 ELF"""
    # 1. 读取 /proc/<pid>/maps 定位 .text 段虚拟地址范围
    maps = open(f"/proc/{pid}/maps").read()
    text_range = parse_text_range(maps)  # 返回 (vaddr_start, vaddr_end, file_offset)

    # 2. 从 /proc/<pid>/mem 读取内存
    with open(f"/proc/{pid}/mem", "rb", 0, os.SEEK_SET) as mem:
        mem.seek(text_range[0])
        data = mem.read(text_range[1] - text_range[0])

    # 3. 写入 dump 文件
    with open("dumped.bin", "wb") as f:
        f.write(data)

    # 4. 修复：将 dump 的 .text 写回原 ELF 文件偏移（保留原 ELF 头/程序头）
    fix_elf_text("dumped.bin", TARGET, text_range[2])
    print(f"dumped {len(data)} bytes, OEP at 0x{oep_rva:x}")

def fix_elf_text(dump_file, original, file_offset):
    """将 dump 的 .text 覆盖回原文件对应偏移，保留 ELF 头"""
    with open(original, "r+b") as orig, open(dump_file, "rb") as dump:
        orig.seek(file_offset)
        orig.write(dump.read())
    print("ELF .text fixed, IAT intact")

if __name__ == "__main__":
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else [PID]
    dump_and_fix(pid, OEP_OFFSET[0], [BASE_ADDR])
```

运行：先 gdb 附加目标、在 OEP 设断点，程序停下后执行 `python3 upx_unpack.py <pid>`。验证：dumped 文件熵值回落、`file` 识别正常、能运行。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §八脱壳通用工作流使用

## 六、加壳器特征详表

| 加壳器 | 识别特征 | 处理方法 |
|---|---|---|
| UPX | 魔数 `UPX!`，段名 `UPX0`/`UPX1` | `upx -d` 直接脱壳 |
| MPRESS | `.MPRESS1`/`.MPRESS2` 段名 | 动态 dump OEP |
| ASPack | 低熵导入表 + 高熵代码段 | 动态 dump |
| Themida | 极高熵，大量虚拟机指令 | 需专项反虚拟机工具 |
| VMProtect | `.vmp0`/`.vmp1` 段，字节码解释器 | 见 VM 保护处理 |
| Enigma Protector | 大段加密 + License 检查 | 动态追踪解密例程 |
| PyInstaller（Python） | `MEIPASS`、`PKG` 魔数 | `pyinstxtractor` 解包 |
| Go binary | 大型 ELF，`go.buildinfo` 段 | `go-dex`，符号自动恢复 |

## 七、UPX OEP 特征与手动脱壳

UPX stub 解压完毕后的跳转特征：
```asm
; x86-32 UPX stub 末尾：
popa                         ; 恢复所有寄存器
jmp  0x<OEP>                 ; 跳到原始入口点
; x86-64：
pop r15; pop r14; pop r13; ...
jmp <OEP>
```

**修改版 UPX（`upx -d` 失败时）GDB 手动 dump：**
```gdb
gdb ./target
(gdb) b *0x400000   # 断在入口点
(gdb) run
# 单步 si 追踪，等待 stub 解压完毕，直到 jmp 到 OEP
# 发现 OEP 后：
(gdb) dump binary memory unpacked.bin 0x400000 0x500000
# 再用 r2 分析 dump
r2 -A ./unpacked.bin
```

## 八、脱壳通用工作流（mprotect 监控 + 自动 dump）

```bash
# 监控所有 mprotect(EXEC) 调用
gdb -q ./target -ex "catch syscall mprotect" -ex "run" -ex "continue" -batch

# 程序执行后手动在可疑 EXEC 地址设硬件断点
(gdb) hb *<OEP候选地址>
# OEP 断下后 dump：
(gdb) dump binary memory /tmp/unpacked.bin 0x<load_base> 0x<load_base+0x200000>
```

**组合命令：启动 + 监控 mprotect + 自动 dump**
```bash
gdb -q ./target \
  -ex "catch syscall mprotect" \
  -ex "run" \
  -ex "commands" \
  -ex "silent" \
  -ex "printf \"mprotect EXEC hit\\n\"" \
  -ex "dump binary memory /tmp/unpacked_$(date +%s).bin 0x400000 0x600000" \
  -ex "continue" \
  -ex "end" \
  -batch
```

## 九、分段熵检测（更精确）

```bash
# r2 分段熵
r2 -q -c 'iS~entropy' ./target

# 全局熵 + 分段熵结合判断
python3 -c "
import math, collections, sys
data = open(sys.argv[1],'rb').read()
freq = collections.Counter(data)
h = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())
print(f'全局熵值: {h:.4f}/8.0')
print('结论:', '⚠️ 疑似加壳/加密' if h > 7.0 else '✅ 正常范围')
" ./target
```

**判断标准：**
- 全局熵 > 7.0 → 疑似加壳/加密
- 某段熵 > 7.5 → 该段被加密/压缩
- 正常代码段熵 5.0–6.5

## 反 AI 逆向加固（BLA 蓝队防御）

> 来源：看雪帖《【反AI逆向】BLA 程序加固 懒人包 用于对抗AI自动化破解》（Henglie，293536，2026-11-17 学习）。

### 定位
开源的 **Counter-REA 蓝队防御 MCP 服务与 CLI**，专为保护软件发布产物免受 AI 逆向代理（REA、自动化反编译、大模型逆向流水线）还原而设计，同时保持 **100% 运行时等价**。核心思路：**让 AI 分析时疯狂消耗 Token，达到反破解目的**。

### 对抗目标与机理
- AI 逆向代理可在单条命令内解包 `.asar`、还原 SourceMap、配对 IPC 通道、提取 `.wasm`/`.sqlite`/`.safetensors`，数十秒约 $0.20 成本完整克隆核心业务逻辑。
- 静态与语义分析器撞上**确定性资源配额上限**（`primitive-candidates > 256`、`ASAR > 16 MiB`、`WASM > Wabt 上限`、SQLite 虚拟生成列陷阱），陷入高拟真影子状态机，**Token 消耗放大 300×–2,800×**（基于 token-estimator.ts 成本模型）。
- 所有预算爆破图与诱饵载荷位于 **O(1) 数论不透明谓词**（$7x^2 - 1 \neq y^2 \pmod 7$）保护的**不可达分支或惰性元数据段**中——静态可见但不可达，诱导 AI 空耗算力。
- **14/14 基准测试目标 100% 通过输入/输出等价校验**。

### 与传统混淆/虚拟化的分工
- 传统混淆器只做标识符重命名（`_0x1a2b`），在大模型控制流归纳能力面前形同虚设。
- 重型商业虚拟化壳破坏跨平台构建、性能损耗高。
- BLA 3.x：**宿主 Agent 源码级手术织入 + 19+ 种格式原生护盾**结合，是针对 AI 流水线的定向防御。

### 启示（对抗 AI 自动化破解的设计原则）
1. **资源配额上限**：给 AI 分析器设确定性上限，超限即进入高拟真影子状态。
2. **诱饵载荷放在不可达分支**：用不透明谓词保护，静态可扫到但执行不到，纯耗 Token。
3. **保持运行时等价**：加固不得改变程序行为，用输入/输出等价校验验收。
4. **格式原生护盾**：针对 ASAR/WASM/SQLite 等 AI 易提取格式做原生防护，而非仅重命名。

## 六、PyInstaller 诱饵穿透：入口脚本是诱饵，逻辑在修改版运行时（292517 实战）

**样本特征**：PyInstaller one-file 容器，解包出现 `PYZ.pyz`、`base_library.zip`、`pyiboot01_bootstrap.pyc`、`main.pyc`、`python313.dll`；入口 `main.pyc` 反编译只有 `sys.exit(0)`，与题目描述完全不符——**入口脚本是诱饵，不代表解包失败**。

**原理**：真实逻辑藏在**修改版 CPython 运行时**的冻结模块里。PyInstaller 启动早期就会 `import os`，篡改的 `<frozen os>` 抢在入口脚本前执行真实校验。题面提示（古典密码/时间戳/硬件密钥/碎片）是叙事干扰。

**流程（差分驱动，先分类层次→建假设→最小区分实验）**：
1. **分层**：确认容器→运行时→冻结模块→应用校验器，先弄清行为在哪一层，避免在 bootloader 里空转。
2. **建竞争假设**：H1 逻辑在修改版运行时（预测：DLL 与官方明显不同）；H2 在 bootloader（**只有 H1 被否定后才转**）。
3. **官方基线差分**：下载官方同版本同架构运行时（如 `python-3.13.1-embed-amd64.zip`），比大小/SHA-256/PE 节（`.text` 增大约 1MB → 重新编译过，非尾部追加数据）。
4. **导出冻结模块**：CPython 导出 `_PyImport_FrozenBootstrap/_FrozenStdlib/_FrozenTest` 与 `PyImport_FrozenModules`；`_frozen` 结构 `{name, code, size, is_package}`，解析 PE 导出表按 code/size 导出 marshal 原始数据。
5. **逐模块哈希差分**：29 个冻结模块逐一 SHA-256，差异集中到 `os`（+1672 字节、执行字节码变化），7MB 运行库压缩到 47KB marshal 代码对象。
6. **恢复校验器**：用**题目同版本**官方 Python 执行 `marshal.loads()` + 递归 `dis.dis()`，还原注入逻辑（拼接碎片 → XOR 0x55 → 用输入做周期 XOR key → `co_code.replace()` 动态重建字节码 + 成功常量）。
7. **已知明文恢复 key**：周期 XOR 用 `key[i mod 6] = cipher[i] XOR plain[i]`，dummy 函数原始字节码就是已知明文；26 字节覆盖每个槽位至少 4 次、约束完全一致才算确定。

**验证（三层一致性）**：
- 槽位约束一致 + 成功密文解出合法 UTF-8 文本 + **原程序输入路径输出相同结果**；单字节变异应触发失败（如 `Fatal Python error` 落在 `<frozen os>`，反向确认执行位置）。

**易错点**：
- 只看 `main.pyc` 会直接漏题；不先比官方基线就反编译整个 DLL 会被 3.8MB `.text` 淹没；宽泛字符串（flag/key/input）在标准库与 OpenSSL 中全是噪声，只能当线索不能当证据；**marshal 与字节码强版本相关**，必须用题目对应版本（如 3.13.1）执行脚本；可打印 key 不等于正确，必须过三层验证。

**通用化**：入口脚本无行为时，依次检查 runtime hook → 冻结模块 → 修改版运行时 → bootloader 前置逻辑 → 运行时生成的 code object。
