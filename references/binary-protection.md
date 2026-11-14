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

- payload 能稳定触发漏洞
- 拿到预期权限（shell / 代码执行）
- 多轮运行不崩溃（稳定化）
