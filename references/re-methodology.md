# 通用逆向方法论（re-methodology）

适用于 PE / ELF / MACH-O / APK / SO / 固件 / JS 等任意目标。四阶段循环。

## 阶段 0：建档与基线

```bash
sha256sum target
file target
readelf -h target      # ELF；PE 用 pefile；Mach-O 用 otool
readelf -S -l target   # 段、程序头
readelf -d target      # 动态依赖、NEEDED
strings -a target | head -100
```

记录：文件类型、架构（x86/x64/ARM/ARM64）、编译器与优化级别、安全标志（PIE/NX/canary/RELRO/CFI）、入口点、导入表。

## 阶段 1：静态侦察

```bash
r2 -A -q -c 'aaa; afl; axt' target      # r2 全量分析 + 函数列表 + 交叉引用
r2 -q -c 'iI; iS~entropy' target        # 信息 + 段熵值（判断是否加壳）
objdump -d target | less                 # 反汇编
nm target                               # 符号表（未 strip）
```

- 熵值 > 7.0 → 疑似加壳/加密（转 `unpacking.md`）
- 函数极少 + 大量 `call [reg]` → 混淆/VM（转 `deobfuscation.md` / `vm-bytecode.md`）
- 有 `v.m.p`/`abcd`/小 DEX/`libabcd.so` → 壳（转 `elf-apk-patch.md`）

## 阶段 2：动态验证

静态看不清的（自解密、运行时 DEX、动态调用）用动态补：

```bash
strace -tt -T ./target 2>&1 | tee /tmp/strace.log
ltrace -e strcmp,memcmp,EVP_*,AES_* ./target
gdb -q ./target
frida -f ./target -l hook.js
```

动态优先看：
- `open`/`read`：密钥文件、配置、运行时 DEX
- `mprotect(EXEC)`：自解码/脱壳触发点
- `strcmp`/`memcmp`：密码/校验比较
- 加密库函数：算法识别

## 阶段 3：定位与还原

- **定位 CHECK_FN**：找校验/激活/注册入口。线索：字符串 "register/license/key/激活"、`strcmp` 热点、返回值分支。
- **还原算法**：识别加密/哈希/签名算法（见 `deobfuscation.md` 算法特征表），还原成可复现的 Python/C 实现。
- **还原结构**：vtable、结构体布局、类型重建（见 `linux-dynamic.md` 结构体恢复）。

## 阶段 4：交付与验证

- 打补丁：记录 `OFFSET` + `PATCH_BYTE`，保留原始副本，验证字节级差异仅在目标处。
- 写注册机：还原算法后，用独立实现生成有效序列号/卡密，回填验证。
- 重建镜像：脱壳/重组后，验证可运行 + 行为等价。

**完成标准**：不是"能安装"，而是"校验通过 + 行为符合预期 + 有验证证据"。

## 常用命令速查

| 目的 | 命令 |
|---|---|
| 看入口/段 | `readelf -h -l target` |
| 看导入 | `readelf -d target` / `rabin2 -i target` |
| 反汇编函数 | `objdump -d target` / `r2 pdf @ sym` |
| 找字符串引用 | `r2 axt @ <addr>` |
| 搜字节 | `r2 /x <hex>` / GDB `find` |
| 看内存映射 | `cat /proc/<pid>/maps` / pwndbg `vmmap` |
| 查算法常数 | `strings` + 常数表（0xd76aa478=MD5，0x63=AES S-box） |

## 调用约定速查

| 平台 | 约定 | 参数传递 |
|---|---|---|
| x86 cdecl | 调用者清理栈 | 参数从右往左压栈 |
| x86 stdcall | 被调用者清理栈 | 参数从右往左压栈 |
| x64 Windows | Microsoft x64 | RCX, RDX, R8, R9，多余走栈 |
| x64 System V | AMD64 ABI | RDI, RSI, RDX, RCX, R8, R9，多余走栈 |
| ARM | AAPCS | R0-R3，多余走栈 |

## 常见代码模式识别

```c
// 字符串混淆（XOR 解密循环）
for (int i = 0; i < len; i++)
    str[i] ^= key;

// 反调试（IsDebuggerPresent）
if (IsDebuggerPresent())
    exit(1);

// API 哈希（恶意软件常用，隐藏导入）
hash = 0;
while (*name)
    hash = ror(hash, 13) + *name++;

// 栈字符串构造
char s[8];
*(DWORD*)s = 0x6C6C6548;  // "Hell"
*(DWORD*)(s+4) = 0x6F;    // "o\0"
```

## 权威文档与白皮书 URL 索引

遇到不确定的指令语义、调用约定、加密规范，优先查以下权威来源，不要凭记忆臆测。

### x86 / x86-64

**Intel（首选）：**

| 文档 | URL | 关键内容 |
|---|---|---|
| Intel SDM（完整版 7 卷合一 PDF） | https://cdrdv2.intel.com/v1/dl/getContent/671200 | 最权威，含所有指令语义 |
| Intel SDM Volume 2A（指令集 A-M） | https://cdrdv2.intel.com/v1/dl/getContent/671110 | ADD 到 MOVQ |
| Intel SDM Volume 2B（指令集 N-Z） | https://cdrdv2.intel.com/v1/dl/getContent/671108 | NOP 到 XTEST |
| Intel SDM Volume 2C（VEX/EVEX 扩展） | https://cdrdv2.intel.com/v1/dl/getContent/671112 | AVX/AVX-512 |
| Intel SDM Volume 1（基础架构） | https://cdrdv2.intel.com/v1/dl/getContent/671094 | 寄存器、寻址模式 |
| Intel Intrinsics Guide（在线版） | https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html | SIMD 内置函数对应指令 |
| Intel 64 ABI（System V AMD64） | https://refspecs.linuxbase.org/elf/x86-64-abi-0.99.pdf | 调用约定、栈布局 |

**AMD：**
- AMD64 Architecture Programmer's Manual Vol.1-5：https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/

**在线快速查询：**

| 工具 | URL | 用途 |
|---|---|---|
| Felix Cloutier x86 Reference | https://www.felixcloutier.com/x86/ | 按指令名快速查语义 |
| uops.info（微架构延迟） | https://uops.info/table.html | 查延迟/吞吐量 |
| Godbolt Compiler Explorer | https://godbolt.org | 对比不同编译器输出 |

### ARM64 / AArch64

**ARM 官方（首选）：**

| 文档 | URL | 关键内容 |
|---|---|---|
| ARM Architecture Reference Manual (DDI 0487) | https://developer.arm.com/documentation/ddi0487/latest | 最权威 AArch64 手册 |
| Arm A64 ISA Reference（在线 HTML） | https://developer.arm.com/documentation/ddi0596/latest | 按指令名索引 |
| Arm Cortex-A Series Programmer's Guide | https://developer.arm.com/documentation/den0013/latest | 编程模型，入门 |
| Arm64 Procedure Call Standard (AAPCS64) | https://github.com/ARM-software/abi-aa/releases | 调用约定 |
| Arm NEON Intrinsics Reference | https://developer.arm.com/architectures/instruction-sets/intrinsics/ | NEON 指令查询 |

### 通用逆向工具文档

| 工具 | 文档 URL |
|---|---|
| IDA Pro 帮助 | https://hex-rays.com/products/ida/support/idadoc/ |
| Ghidra 文档 | https://ghidra-sre.org/CheatSheet.html |
| Binary Ninja 文档 | https://docs.binary.ninja |
| LLVM IR 参考 | https://llvm.org/docs/LangRef.html |

### 文件格式参考

| 格式 | 文档 |
|---|---|
| ELF | https://refspecs.linuxfoundation.org/elf/elf.pdf |
| PE/COFF | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format |
| Mach-O | https://developer.apple.com/documentation/kernel/mach_header |
| DWARF 调试信息 | https://dwarfstd.org/doc/DWARF5.pdf |

### 加密算法参考规范

| 算法 | 规范来源 |
|---|---|
| AES | NIST FIPS 197 — https://csrc.nist.gov/publications/detail/fips/197/final |
| SHA-2 | NIST FIPS 180-4 — https://csrc.nist.gov/publications/detail/fips/180/4/final |
| SHA-3 | NIST FIPS 202 — https://csrc.nist.gov/publications/detail/fips/202/final |
| ChaCha20/Poly1305 | RFC 8439 — https://www.rfc-editor.org/rfc/rfc8439 |
| RSA | RFC 8017 (PKCS#1) — https://www.rfc-editor.org/rfc/rfc8017 |
| RC4 | RFC 6229 — https://datatracker.ietf.org/doc/html/rfc6229 |
