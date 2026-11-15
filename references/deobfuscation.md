# 去混淆（deobfuscation）

目标：把控制流平坦化、字符串加密、SMC、虚假控制流、间接调用等混淆还原成可读代码。**先识别类型，按顺序处理。**

## 一、算法特征速查（先认算法）

| 类别 | 算法 | 关键特征 |
|---|---|---|
| 流密码 | RC4 | 256B S 盒、KSA 双指针、PRGA XOR |
| 流密码 | ChaCha20 | 魔数 `0x61707865`、旋转 16/12/8/7 |
| 分组 | AES | S-box `0x63...` 或 `aesenc` 指令 |
| 哈希 | MD5 | 常数 `0xd76aa478`、4×16 步 |
| 哈希 | SHA-256 | `0x428a2f98`、`sha256rnds2` |
| 哈希 | CRC32 | `0xEDB88320` 或 `crc32` 指令 |
| 编码 | Base64 | 64 字符查表 |
| 混淆 | XOR | 固定密钥循环 + 可打印输出 |

## 二、混淆类型识别决策树

```
熵值 > 7.0？
  是 → 加壳（转 unpacking.md）
  否 → 代码混淆识别：
    CFG 菊花状（所有块收束于一点） → OLLVM 平坦化
    大量 switch(state) + 状态更新 → OLLVM 平坦化
    大量 call [reg+offset] → 间接调用混淆
    VM 解释器主循环（取字节码→跳 handler 表） → VM 保护（转 vm-bytecode.md）
    大量不可能为真的分支 → 虚假控制流
    静态 strings 为空、运行时才有串 → 字符串加密
```

## 三、各类型处理

### 1. OLLVM 控制流平坦化
- **识别**：`r2 VV` 看 CFG，dispatcher 块入度 > 总块数 50%。
- **定位 dispatcher**：最高入度块；汇编特征 `cmp+je` 链或 `jmp [table]`。
- **找 state 变量**：dispatcher 的 switch 条件操作数；GDB watchpoint / Frida Stalker 追踪。
- **去平坦化**：Frida Stalker 记录真实执行块（过滤 dispatcher），多输入合并覆盖率；angr Veritesting 枚举剩余路径。
- **输出**：按真实顺序重排基本块，去除 state 赋值与 dispatcher 跳转，输出线性化伪代码。

```bash
# r2 一行评估 CFG 健康度
r2 -A -q -c "agfj @ <func> | python3 -c \"
import json,sys
b=json.load(sys.stdin)
ind={x['offset']:0 for x in b}
[ind.__setitem__(s,ind.get(s,0)+1) for x in b for s in x.get('successors',[])]
mx=max(ind.values()) if ind else 0; n=len(b)
print('blocks',n,'max_indeg',mx,'ratio',round(mx/n,2) if n else 0)\"" target
```

### 2. 字符串加密
- **识别**：静态 `r2 iz` 极少（<5 个），运行时有可打印输出。
- **找解密函数**：`r2 axt @ <string_ref>`，解密函数通常 `decrypt(enc_ptr) → char*`。
- **提取**：GDB 断解密函数出口，`x/s $rax` 拿明文；Frida hook 出口收集所有明文。
- **还原**：把加密串 + 解密算法还原，生成可搜索明文池。

### 3. 虚假控制流 / 不透明谓词
- **识别**：大量短条件分支 + 孤立小块；不透明谓词如 `X² & 3 != 3`（永真）。
- **清理**：Frida Stalker 覆盖率，标记从未执行的块为 dead code，`r2 afb- <addr>` 移除；angr 符号执行确认分支可达性。
- **patch**：永假分支处 `r2 -w: wa nop @ <addr>`。

### 4. 间接调用混淆
- 大量 `call [reg+offset]`、`jmp [table]`。
- **解析**：找跳转表，`r2 pxq 256 @ <table>`，记录每项目标；Frida 追踪实际调用目标。
- **还原**：把间接调用替换为直接调用（仅当目标静态确定）。

### 5. SMC（自修改代码）
- 代码在运行时被改写。**动态优先**：GDB 在改写后读内存，或 Frida hook 改写函数。
- 记录改写前后的字节，还原原始代码。

## 四、处理顺序（多种混淆叠加）

```
1. 加壳 → 先脱壳
2. 反调试 → 先绕过
3. 字符串加密 → 先提取（降噪声）
4. 虚假控制流 → 清理 CFG
5. OLLVM 平坦化 → 恢复控制流
6. 间接调用 → 解析目标
7. VM 保护 → 最后处理
```

## 五、验证

- 去混淆后 CFG 恢复线性/正常结构
- 字符串可搜索、算法可复现
- 去混淆产物与原程序行为等价（多输入跑通）

## 六、自动化去混淆工具代码

### Z3 证明不透明谓词
```python
import z3
x = z3.BitVec('x', 32)
s = z3.Solver()
s.add(x * (x + 1) % 2 != 0)   # 不透明谓词示例
print(s.check())  # unsat → 永真，该分支可移除
```

### unicorn 引擎 SMC 自动解包
```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, binary_code)
mu.emu_start(decrypt_entry, decrypt_end)   # 跑解密循环
decrypted = mu.mem_read(code_start, code_length)  # 读解密后代码
```

### angr 符号执行去平坦化
```python
import angr, claripy

proj = angr.Project('./obfuscated')
cfg = proj.analyses.CFGFast()

# 找 dispatcher（最高入度基本块）
dispatcher = max(cfg.graph.nodes(), key=lambda n: cfg.graph.in_degree(n))

# 对每个 case 块，符号求解 state 变量找真实后继
for block in case_blocks:
    state = proj.factory.blank_state(addr=block.addr)
    # ... 求解 state 变量确定真实后继
```

### 去混淆工具对照
| 技术 | 工具 | 效果 |
|---|---|---|
| 符号执行去平坦化 | angr / Triton / miasm | 高，覆盖所有状态转移 |
| SMC 解包 | unicorn | 自动跑解密循环 dump |
| 不透明谓词 | Z3 | 证明永真/永假分支 |
| 控制流平坦化 | D-810 (IDA 插件) | 专为 CFF 设计 |
| movfuscator | demovfuscator | 从 mov 模式还原原始操作 |

## 加密算法 Python 复现速查

```python
import hashlib, hmac, base64
from Crypto.Cipher import AES, DES, DES3, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# 哈希
hashlib.md5(b'text').hexdigest()
hashlib.sha256(b'text').hexdigest()
hmac.new(b'key', b'msg', hashlib.sha256).hexdigest()

# AES-CBC
aes = AES.new(b'16bytekey123456', AES.MODE_CBC, b'16byteiv12345678')
base64.b64encode(aes.encrypt(pad(b'plaintext', 16))).decode()
unpad(AES.new(b'16bytekey123456', AES.MODE_CBC, b'16byteiv12345678').decrypt(base64.b64decode('密文')), 16).decode()
# AES-ECB 无 IV: AES.new(key, AES.MODE_ECB)

# RSA
key = RSA.import_key(open('pub.pem').read())
base64.b64encode(PKCS1_v1_5.new(key).encrypt(b'plaintext')).decode()

# 国密 SM2/SM4 (pip install gmssl)
from gmssl import sm2, sm4
# SM2: sm2.CryptSM2(public_key=pub, private_key='').encrypt(plain)
# SM4: sm4.CryptSM4().set_key(key, sm4.SM4_ENCRYPT); crypt.crypt_ecb(plain)

# 编码检测
# Base64: A-Za-z0-9+/=，长度 4 的倍数
# Hex: 0-9a-f，长度偶数
# URL 编码: %XX 格式
```

## 七、垃圾代码与不透明谓词（补充）

### 1. 垃圾代码插入（Junk Code）
死代码，不影响程序输出，只为增加分析时间。

**识别：**
- 写寄存器/内存但后续从不读取的指令
- 返回值被丢弃且无副作用的函数调用
- 边界不变、结果不使用的循环

**移除策略：**
1. 计算 def-use 链（IDA/Ghidra 数据流分析）
2. 把无下游使用的指令标记为 dead
3. 验证移除后行为不变（trace 对比）

### 2. 不透明谓词类型表
条件分支恒真/恒假，但不直观。

| 类型 | 示例 | 恒值 |
|---|---|---|
| 算术 | `x² ≥ 0` | 真 |
| 数论 | `x*(x+1) % 2 == 0` | 真（连续整数乘积） |
| 指针 | 别名后 `ptr == ptr` | 真 |
| 哈希 | `CRC32(常数) == 已知值` | 真 |

**去混淆：**
- 抽象解释：证明条件为常量
- 符号执行：Z3 证明 `∀x: predicate(x) = True`
- 模式匹配：识别已知不透明谓词族
- 动态：trace 观察分支从不走/总走

```python
import z3
x = z3.BitVec('x', 32)
s = z3.Solver()
s.add(x * (x + 1) % 2 != 0)
print(s.check())  # unsat → 恒真，该分支可移除
```

## 八、SMC 补充：XOR 解密循环与自动解包

### XOR 解密循环（最常见）
```asm
lea esi, [encrypted_code]
mov ecx, code_length
mov al, xor_key
decrypt_loop:
    xor byte [esi], al
    inc esi
    loop decrypt_loop
    jmp encrypted_code  ; 已解密
```

### 分析策略
```
1. 找解密例程（.text 写入循环中的 XOR/ADD/SUB）
2. 在循环结束后设断点
3. 断点处 dump 已解密内存区
4. 在 IDA/Ghidra 中重新分析 dump 代码
5. 多层解密：对每层重复
```

## 九、字符串加密模式表

| 模式 | 示例 | 恢复 |
|---|---|---|
| XOR 循环 | `for(i=0;i<len;i++) s[i]^=key;` | hook 或仿真 XOR 函数 |
| 栈字符串 | `mov [esp+0],'H'; mov [esp+1],'e';...` | IDA FLIRT / Ghidra 脚本重组 |
| RC4 加密 | 加密块 + 二进制内 RC4 密钥 | 提取密钥，离线解密 |
| AES 加密 | 加密块 + 运行时派生 AES 密钥 | hook 解密后 |
| 自定义编码 | Base64+XOR+反转 | trace 解码函数并复现 |

### Ghidra 自动字符串解密脚本
```python
# 找 XOR 解密调用并仿真
from ghidra.program.model.symbol import SourceType

decrypt_func = getFunction("decrypt_string")
refs = getReferencesTo(decrypt_func.getEntryPoint())
for ref in refs:
    call_addr = ref.getFromAddress()
    # 提取参数（加密缓冲区指针、密钥、长度）
    # 仿真解密，用明文加注释
```

## 十、导入隐藏（Import Hiding）

### GetProcAddress + 哈希查找
```c
FARPROC resolve(DWORD hash) {
    // 遍历 PEB → LDR → InMemoryOrderModuleList
    // 对每个 DLL 遍历导出表
    // 哈希每个导出名，与目标哈希比较
    // 返回匹配的函数指针
}
```

### 恢复步骤
1. 识别哈希算法（常见 CRC32、djb2、ROR13+ADD）
2. 对所有已知 API 名计算哈希
3. 构建 hash → API 名查找表
4. 在 IDA/Ghidra 中标注解析出的调用

### 常见哈希算法

| 名称 | 算法 | 使用者 |
|---|---|---|
| ROR13 | `hash = (hash >> 13 \| hash << 19) + char` | Metasploit shellcode |
| djb2 | `hash = hash * 33 + char` | 各类恶意代码 |
| CRC32 | 函数名标准 CRC32 | 复杂加壳器 |
| FNV-1a | `hash = (hash ^ char) * 0x01000193` | 现代恶意代码 |

## 十一、反反汇编技巧

| 技巧 | 机制 | 修复 |
|---|---|---|
| 重叠指令 | `jmp $+2; db 0xE8`（假 call 前缀） | 从正确偏移手动重新分析 |
| 错位跳转 | 跳到多字节指令中间 | 强制 IDA 在目标处重新分析 |
| 条件跳转对 | `jz $+5; jnz $+3`（恒跳转，扰乱线性反汇编） | 转为无条件 jmp |
| 返回地址操纵 | `push addr; ret` 代替 `jmp addr` | 识别 push+ret 为跳转 |
| 异常流 | 触发异常，真实代码在 handler | 分析异常处理链 |
| call+add [esp] | `call $+5; add [esp], N; ret`（计算跳转） | 计算真实目标 |

### IDA 修复
```
右键 → Undefine (U)
右键 → Code (C) 于正确偏移
Edit → Patch → Assemble（永久修复）
```

## 十二、混淆识别速查与决策树

**IDA/Ghidra 症状 → 混淆类型 → 首选：**

| 症状 | 疑似混淆 | 起步 |
|---|---|---|
| 平坦 CFG、单一巨型 switch | 控制流平坦化 | 符号执行恢复 CFG |
| 只有 mov 指令 | movfuscator | demovfuscator / trace 提升 |
| pushad/pushfd → VM 入口 | VM 保护 | handler 表提取 |
| 代码执行前 XOR 循环 | SMC/字符串加密 | 动态分析，解码后断点 |
| 不可能条件（不透明谓词） | 垃圾代码插入 | 模式化移除 |
| 所有字符串不可读 | 字符串加密 | hook 解密或仿真 |
| IAT 无导入 | 导入隐藏 | trace GetProcAddress/哈希解析 |

### 决策树
```
能运行？
├─ 能 → 动态优先：BP 关键 API、trace、dump 解密代码/字符串
└─ 不能（固件/异构）→ 静态：按症状识别类型
代码形态？
├─ 巨型平坦 switch/dispatcher → CFF（D-810 / 符号去平坦化）
│   或取指-译码-执行 → VM（提取 handler、写反汇编器）
├─ 只有 mov → movfuscator（demovfuscator）
├─ .text 写入 XOR/ADD 循环 → SMC（解码后断点 dump）
├─ 分支不可能条件 → 不透明谓词（Z3 证明 / 模式移除）
├─ 反汇编错乱/函数重叠 → 反反汇编（正确偏移重分析）
├─ 无可读字符串 → 字符串加密（hook 解密 / 仿真）
├─ IAT 无导入 → 导入隐藏（识别哈希、建查找表）
└─ pushad/pushfd→复杂代码→popad/popfd → VM 保护（完整 VM 分析）
```

## 十三、去混淆工具箱

| 工具 | 用途 | 适用 |
|---|---|---|
| IDA Pro + Hex-Rays | 反汇编、反编译、脚本 | 通用分析 |
| Ghidra | 免费替代，Java/Python 脚本 | 预算有限 |
| D-810（IDA 插件） | 自动 CFF 去平坦化 | OLLVM 式混淆 |
| miasm | IR 分析框架 | 符号去混淆 |
| Triton | 动态符号执行 | 不透明谓词、CFF |
| REVEN | 全系统 trace 记录回放 | VM 保护分析 |
| demovfuscator | movfuscator 还原 | 纯 mov 二进制 |
| x64dbg + 插件 | 动态分析脚本 | Windows RE |
| Unicorn | CPU 仿真 | SMC 解包、shellcode |
| Capstone | 反汇编库 | 自定义工具 |
| IDA FLIRT | 函数签名匹配 | 识别 stripped 库代码 |
| Binary Ninja | MLIL/HLIL 反汇编 | 自动化分析 |
