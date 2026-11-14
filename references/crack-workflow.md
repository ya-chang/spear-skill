# 完整破解链路（crack-workflow）

目标：从拿到目标到交付 patch/注册机的**端到端标准流程**。这是 `spear` 技能的核心串联，把脱壳、反调试、VM、去混淆串成一条可执行链路。

## 一、标准链路

```
拿到目标程序
  ↓
① 识别保护类型（熵值/段名/字符串/CFG）
  ↓
② 脱壳（UPX 直接脱；商业壳动态 dump OEP）
  ↓
③ 反调试绕过（ptrace/PEB/时间/TLS，先入口级再运行中）
  ↓
④ 字符串提取（解密运行时字符串，降噪声）
  ↓
⑤ 控制流清理（虚假控制流 → OLLVM 平坦化 → 间接调用）
  ↓
⑥ VM 字节码逆向（若校验在 VM 里，最后处理）
  ↓
⑦ 定位 CHECK_FN（校验/激活/注册入口）
  ↓
⑧ 还原算法（加密/哈希/签名，写成独立实现）
  ↓
⑨ 交付：打补丁 或 写注册机
  ↓
⑩ 验证：校验通过 + 行为等价 + 可复现
```

## 二、分步要点

### ① 识别
```bash
python3 -c "import math,collections,sys; d=open(sys.argv[1],'rb').read(); f=collections.Counter(d); h=-sum((c/len(d))*math.log2(c/len(d)) for c in f.values()); print('entropy',round(h,4),'PACKED' if h>7 else 'normal')" target
strings -a target | grep -iE "upx|vmprotect|themida|vmp|ollvm"
readelf -S target | grep -iE "upx|vmp|themida"
```

### ② 脱壳
- UPX：`upx -d target -o unpacked`
- 商业壳：mprotect 断点 + 单步到 OEP，dump 内存（见 `unpacking.md`）
- Android 壳：Frida 抓运行时 DEX（见 `unpacking.md`）

### ③ 反调试绕过
先绕入口级（ptrace/BeingDebugged），再绕运行中（时间/TLS/VEH），最后处理内存完整性校验。见 `anti-debug.md`。

### ④ 字符串提取
静态 strings 少但运行时有串 → 找解密函数，GDB/Frida hook 出口收集明文。见 `deobfuscation.md`。

### ⑤ 控制流清理
顺序：虚假控制流 → OLLVM 平坦化 → 间接调用。用 Frida Stalker 覆盖率 + angr 恢复真实块。见 `deobfuscation.md`。

### ⑥ VM 逆向
若校验逻辑在 VM 里，按 dispatcher → opcode → 反汇编器还原。见 `vm-bytecode.md`。

### ⑦ 定位 CHECK_FN
线索：字符串 "register/license/key/激活/注册"、`strcmp`/`memcmp` 热点、返回值分支、`perf` 热点函数。

### ⑧ 还原算法
识别算法（见 `deobfuscation.md` 算法特征表），还原成独立 Python/C 实现，能复现原程序的校验结果。

### ⑨ 交付
**打补丁**：
- 记录 `OFFSET` + `PATCH_BYTE` + 原始字节。
- 只改目标校验分支，保留其他逻辑。
- 用 r2/capstone 写字节，保留回滚。

**写注册机**：
- 用还原的算法独立实现，生成有效序列号/卡密。
- 回填原程序验证通过。

```python
# keygen 骨架（按还原的算法填）
def generate_key(user):
    # 还原的算法：从用户信息算出校验码
    return serial
```

### ⑩ 验证
- 校验通过（patch 后 / 注册机生成的 key 能通过）
- 行为等价（正常功能不受影响）
- 可复现（独立实现 + 验证命令）
- 多输入稳定

## 三、常见保护组合的快速路径

| 保护组合 | 路径 |
|---|---|
| 仅 UPX | ② 直接脱 → ⑦ 定位 → ⑨ 交付 |
| UPX + 反调试 | ② 脱 → ③ 反调试 → ⑦ → ⑨ |
| 商业壳 + 反调试 + 字符串加密 | ② 动态脱 → ③ 反调试 → ④ 字符串 → ⑦ → ⑨ |
| + OLLVM 平坦化 | ⑤ 去平坦化 → ⑦ → ⑨ |
| + VM 保护 | ⑥ VM 逆向 → ⑦ → ⑨ |
| Android 壳 | ② Frida 抓 DEX → 重组签名 → ⑦ → ⑨ |
| .NET + 混淆器 | dnSpy 反编译 → 去混淆 → ⑦ → ⑨ |

## 四、铁律

1. **原样本只读**，产物记哈希，保留回滚。
2. **证据优先**，不硬编码地址/偏移/密钥。
3. **两层确认**，关键结论双工具交叉验证。
4. **不破坏业务**，只改目标校验，保留正常路径。
5. **完成标准**：校验通过 + 行为等价 + 可复现，不是"能安装"。
