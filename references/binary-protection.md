# 二进制保护绕过（binary-protection，pwn 向）

目标：绕过编译期安全缓解机制，为漏洞利用铺路。**这是 pwn 方向，不是软件破解。**

## 一、安全标志识别

```bash
# ELF
readelf -l target | grep -E "GNU_STACK|GNU_RELRO"
readelf -d target | grep -E "BIND_NOW|FLAGS"
# r2 一键
r2 -q -c 'i~nx; i~pie; i~relro; i~canary; i~cfi' target
# pwntools
python3 -c "from pwn import *; print(ELF('./target'))"
```

| 标志 | 含义 | 绕过思路 |
|---|---|---|
| NX | 栈不可执行 | 用 ROP / 泄漏+JOP，不直接执行栈上 shellcode |
| PIE | 地址随机化 | 泄漏基址（info leak / 格式化串）后算偏移 |
| Canary | 栈保护 | 泄漏 canary / 绕过检测 / 用其他洞 |
| RELRO | GOT 只读 | Full RELRO 无法改 GOT；Partial RELRO 改 GOT 函数指针 |
| CFI | 控制流完整性 | 找合法调用路径 / 利用间接调用 |
| CET/IBT | 影子栈 | 找未启用 IBT 的间接跳转 |

## 二、各机制绕过要点

### NX 绕过
- 不能直接执行栈/堆 shellcode → 用 **ROP**（泄漏 libc 地址，拼 `system("/bin/sh")` 链）。
- 或用 **JOP** / ret2libc / srop。

### PIE 绕过
```bash
# 泄漏基址：格式化串 / info leak / 侧信道
# 拿到 leak 后算出目标函数在 libc/二进制中的偏移
python3 -c "
from pwn import *
leak = 0x7f...   # 泄漏值
base = leak - offset
print(hex(base))
"
```

### Canary 绕过
- 泄漏 canary 值（通过格式化串或未过滤的报错），再原样写回。
- 或找不触发 canary 检查的漏洞（堆溢出改返回地址前先覆写 canary 为已知值）。

### RELRO 绕过
- **Partial RELRO**：`.got.plt` 可写，改 GOT 函数指针（如 `printf` → `system`）。
- **Full RELRO**：GOT 只读，改用 ROP / 堆喷 / 修改其他可写结构。

## 三、利用开发流程

```
1. 找漏洞    溢出/格式化串/UAF/类型混淆
2. 定原语    能控制什么（地址/长度/指针）
3. 绕过缓解   按上表处理 NX/PIE/Canary/RELRO
4. 构造链    ROP/JOP/shellcode，生成 payload
5. 验证       本地复现 + 稳定化（坏字符、地址对齐）
```

## 四、工具

- `pwntools`：ROP 链、格式化串、shellcode、泄露计算
- `ropgadget`：搜 gadget
- `one_gadget`：一键找单字节跳转 gadget
- `checksec`：看安全标志

```bash
python3 -c "from pwn import *; print(cyclic(200))"   # 找崩溃偏移
python3 -c "from pwn import *; print(one_gadget(libc))"  # 单 gadget
```

## 五、验证

- [ ] payload 能稳定触发漏洞（多次发送均命中漏洞点，无随机失败）
- [ ] 拿到预期权限（`id`/`whoami` 确认 shell 或代码执行）
- [ ] 多轮运行不崩溃（连续 20+ 次触发，成功率 ≥ 95%）
- [ ] 绕过的防护标志已确认失效（NX 执行、canary 检测、ASLR 泄露均验证）
- [ ] ROP 链栈对齐正确（`rsp` 8 字节对齐，无段错误）

## 五·五、代码骨架：NX 绕过 ROP 执行 shellcode 模板

> 可编译运行的 NX 绕过骨架，用 ROP 调 mmap 创建可执行页，再跳转 shellcode。关键地址按样本替换。

```c
// nx_bypass_rop.c — NX 绕过 ROP 骨架（64 bit Linux）
// 原理：栈不可执行时，用 ROP 调 mmap(PROT_EXEC) 创建可执行页，跳过去执行 shellcode
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// 占位：从泄露/ROPgadget 获取
unsigned long mmap_addr   = [MMAP_ADDR];      // libc mmap
unsigned long mmap_prot   = 0x7;              // PROT_READ|PROT_WRITE|PROT_EXEC
unsigned long mmap_flags  = 0x22;             // MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK
unsigned long mmap_len    = 0x1000;
unsigned long mmap_fd     = -1;
unsigned long mmap_offset = 0;
unsigned long pop_rdi     = [POP_RDI_GADGET]; // "pop rdi; ret"
unsigned long ret_gadget  = [RET_GADGET];     // "ret"

// 构造 ROP 链：mmap(0, len, prot, flags, fd, offset) → 跳 shellcode
unsigned long rop[] = {
    pop_rdi, 0,                    // rdi = 0 (addr)
    [POP_RSI_GADGET], 0x1000,     // rsi = len（占位）
    [POP_RDX_GADGET], mmap_prot,  // rdx = prot
    [POP_RCX_GADGET], mmap_flags, // rcx = flags
    mmap_addr,                    // 调 mmap
    [RET_GADGET], [RET_GADGET], [RET_GADGET],  // 对齐
    [SHELLCODE_ADDR],             // 跳 shellcode（mmap 返回地址填这里）
};

int main() {
    char payload[512];
    unsigned long *p = (unsigned long*)payload;
    int off = [OFFSET];  // 溢出到返回地址的偏移

    memset(payload, 'A', off);
    // 填 ROP 链
    for (size_t i = 0; i < sizeof(rop)/sizeof(unsigned long); i++)
        p[off/8 + i] = rop[i];

    // 发送 payload（stdin/管道/socket 按场景）
    write(1, payload, sizeof(payload));
    return 0;
}
```

编译：`gcc -o nx_bypass_rop nx_bypass_rop.c`。验证：触发后 mmap 创建可执行页，shellcode 执行，`id` 显示 uid=0 或拿到 shell。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §一 NX 绕过原理使用

## NX/DEP 绕过全表与 mprotect 链

| 绕过方法 | 说明 |
|---|---|
| ROP | 拼现有 ret gadget 链 |
| ret2libc | 直接调 libc 函数（system/execve） |
| ret2csu | 用 `__libc_csu_init` gadget 可控调函数 |
| ret2dlresolve | 伪造动态链接器结构解析任意函数 |
| SROP | 用 sigreturn 从假信号帧设置所有寄存器 |
| mprotect ROP | 调 mprotect 设页可执行 → 跳 shellcode |
| JIT spray | JIT 环境（V8 等）用 JIT 编译器造可执行代码 |

**mprotect 链：**
```python
rop = b'A' * offset
rop += p64(pop_rdi) + p64(stack_page)     # 页对齐地址
rop += p64(pop_rsi) + p64(0x1000)         # 大小
rop += p64(pop_rdx) + p64(7)              # PROT_READ|WRITE|EXEC
rop += p64(mprotect_addr)
rop += p64(shellcode_addr)                 # 跳到已可执行栈上的 shellcode
```

**Full RELRO 替代目标**（GOT 只读无法写）：
- 覆盖其他可写结构：堆上的函数指针、vtable、栈上的返回地址
- 泄漏 libc 基址后用 one_gadget / ret2libc
- 覆盖 `__malloc_hook` / `__free_hook`（老版本 glibc）

## ASLR 绕过全表与熵值

| 绕过方法 | 所需原语 | 说明 |
|---|---|---|
| 信息泄漏 | 任意读原语（格式化串/OOB/UAF） | 泄漏 libc/栈/堆地址 → 算基址 |
| 部分覆写 | 写原语（限长） | 覆写最后 1-2 字节（页内偏移固定） |
| 暴力破解（32 位） | 可重连/重试 | 约 256–4096 次（8–12 bit 熵） |
| Return-to-PLT | 栈溢出 | 无 PIE 时 PLT 地址相对基址固定 |
| ret2dlresolve | 栈溢出 + 写原语 | 无需 libc 基址解析任意函数 |
| 格式化串泄漏 | 格式化串漏洞 | `%N$p` 读栈/libc/堆地址 |
| 栈逐字节读 | fork server | 通过崩溃 oracle 逐字节读栈 |

**x86-64 Linux ASLR 熵值：**

| 区域 | 熵（bit） | 位置数 |
|---|---|---|
| 栈 | 22 | ~4M |
| mmap / libc | 28 | ~256M |
| 堆（brk） | 13 | ~8K |
| PIE 二进制 | 28 | ~256M |

## PIE 部分覆写细节

```
PIE 加载于 0x555555554000（示例），函数偏移 0x1234 → 0x555555555234
覆写返回地址最后 2 字节：0x?234 → 0x?XXX
未知位：bit 12-15（一个 nibble = 4 bit = 16 种可能）
成功率：每次 1/16
```

## Canary 绕过补充

| 方法 | 条件 | 说明 |
|---|---|---|
| 格式化串泄漏 | `printf(user_input)` | `%N$p` 读栈上 canary |
| 暴力破解 | fork() server（canary 在子进程保留） | 逐字节：256 × (canary_size-1) 次 |
| 栈读 | 部分覆写 / info leak | 覆写 canary 的 null 字节后经输出泄漏 |
| 线程 canary 覆写 | 溢出可达 TLS | canary 在 `fs:[0x28]`，溢出越过缓冲区覆写为已知值 |
| canary 相对覆写 | 溢出在 canary 之后、返回地址之前 | 跳过 canary，只覆写返回地址（少见布局） |
| 堆漏洞 | 漏洞在堆上 | canary 只保护栈 |
| `__stack_chk_fail` GOT 覆写 | Partial RELRO | 把 `__stack_chk_fail@GOT` 指向无害函数 → canary 检查通过 |

**Canary 格式：**
```
x86:    0x00XXXXXX（4 字节，前导 null）
x86-64: 0x00XXXXXXXXXXXXXX（8 字节，前导 null）
```
前导 `\x00` 防止字符串操作误读 canary。

## FORTIFY_SOURCE 绕过

`_FORTIFY_SOURCE=2` 增加缓冲区大小检查并限制格式化串。

| 加固函数 | 限制 | 绕过 |
|---|---|---|
| `__printf_chk` | 禁止带位置参数的 `%n`（`%N$n`） | 用非位置 `%n` 或 `%hn` 链 |
| `__memcpy_chk` | 检查目标缓冲区大小 | 改用堆溢出而非栈 |
| `__strcpy_chk` | 同上 | |
| `__read_chk` | 读大小对缓冲区校验 | |

```python
# %1$n 被 __printf_chk 拦截
# 但顺序（非位置）%n 可能仍可用：精确打印字节数后接 %hn，必须非常精确
# 或：在二进制/libc 中用 ROP 找未加固的 printf
```

## CET（Control-flow Enforcement Technology）

Intel CET 两个机制：

**影子栈（Shadow Stack）**
- CPU 硬件维护返回地址副本；`ret` 时校验影子栈与实际栈一致，不符 → `#CP` 异常。
- 影响：ROP 被阻断（返回地址覆写在 `ret` 时被检出）；JOP 可能（`jmp [reg]` 不受影子栈检查）；COP 可能（`call [reg]` 压影子栈但目标由 IBT 校验）。

**间接分支追踪（IBT）**
- 间接 `jmp`/`call` 必须落在 `ENDBR64` 指令上，否则 `#CP` 异常。

**绕过：**
- 数据流攻击（不改控制流）。
- 找合法 `ENDBR` gadget 链入有用操作。
- 用带 `ENDBR` 前缀的 gadget 做 JOP。
- 攻击 CFI 范围外结构（`modprobe_path`、函数指针数组）。

## MTE（Memory Tagging Extension，ARM）

ARM MTE 给内存指针和分配打 4-bit 标签，标签不匹配即异常。

| 方面 | 说明 |
|---|---|
| 标签位 | 指针 bit 56-59，共 16 种标签 |
| 粒度 | 16 字节（每个 16 字节粒度一个标签） |
| 检查 | Load/Store：指针标签须匹配内存标签 |
| 概率 | 随机标签 → 攻击者猜对概率 1/16 |

**绕过：**

| 方法 | 成功率 |
|---|---|
| 暴力破解 | 每次 1/16（6.25%） |
| 标签 oracle | 侧信道确定标签（时序、错误信息） |
| 界内利用 | 留在同标签区域（用相对偏移） |
| 标签绕过 gadget | 若可访问 `LDGM`/`STGM` 指令 |
| 推测执行 | Spectre 式绕过标签检查 |

## Full RELRO 替代目标（GOT 只读时）

| 目标 | 条件 | 方法 |
|---|---|---|
| `__malloc_hook` | glibc < 2.34 | 覆写为 one_gadget |
| `__free_hook` | glibc < 2.34 | 覆写为 `system`，触发 `free("/bin/sh")` |
| `_IO_FILE` vtable | 任意 glibc | FSOP / vtable 劫持 |
| `__exit_funcs` | 任意 glibc | 覆写退出处理链表 |
| `TLS_dtor_list` | glibc ≥ 2.34 | 线程局部析构链（需指针保护） |
| `.fini_array` | 若可写 | 覆写析构函数指针 |
| 栈返回地址 | 直接栈写 | 覆写返回地址做 ROP |

## 决策树

```
checksec 输出
├── NX 关闭？→ 栈/堆上直接 shellcode（最简）
├── NX 开启（现代标准）
│   ├── 需代码执行 → ROP / ret2libc
│   ├── Canary？
│   │   ├── fork server？→ 逐字节暴力
│   │   ├── 格式化串？→ %p 泄漏 canary
│   │   ├── 堆漏洞？→ canary 不保护堆
│   │   └── Partial RELRO？→ 覆写 __stack_chk_fail@GOT
│   ├── PIE？
│   │   ├── 格式化串？→ 泄漏 .text → PIE 基址
│   │   ├── 部分覆写 → 末 12 bit 固定（1/16 暴力）
│   │   └── OOB 读？→ 泄漏代码指针
│   ├── ASLR？
│   │   ├── 有泄漏 → 泄漏 libc 基址
│   │   ├── 无泄漏 → ret2dlresolve 或 SROP
│   │   ├── 32 位？→ 可暴力（~4096 次）
│   │   └── Return-to-PLT（PLT 调用无需 libc 基址）
│   ├── RELRO 级别？
│   │   ├── None/Partial → GOT 覆写
│   │   └── Full → 替代目标（见上表）
│   └── FORTIFY_SOURCE？
│       ├── 拦截位置 %n → 用顺序 %n 或堆利用
│       └── 拦截加固函数溢出 → 走未加固路径
├── CET 影子栈？
│   ├── ROP 被阻断 → 数据流攻击或 JOP
│   └── ENDBR gadget 链
└── MTE（ARM）？
    ├── 1/16 暴力
    └── 界内相对覆写
```
