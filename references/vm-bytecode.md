# VM / 字节码逆向（vm-bytecode）

目标：还原自定义虚拟机保护。把 VM 解释器、字节码、opcode 语义逐步还原成等价高级代码。**成本最高，放最后处理。**

## 一、识别 VM 保护

特征：
- 主循环：`movzx eax, byte [rsi]` → `jmp [rax*8 + handler_table]`
- 高熵段（`.vmp0/.vmp1`）+ 大量 `pushfd/popfd`
- handler 表是连续函数指针数组
- 静态看不到正常函数边界，全是 dispatcher

```bash
r2 -q -c 'iS~entropy; afl~vm; afl~interp' target
# 找 handler 表：连续有效代码地址数组
r2 -q -c 'pxq 256 @ <handler_table>' target
```

## 二、还原步骤

### 1. 找 VM 主循环（dispatcher）
定位取指-译码-执行的循环体。汇编特征：读字节码 → 索引 handler 表 → 跳转。

```gdb
# 断在 handler 表跳转处，记录每次迭代的字节码
(gdb) b *<dispatcher_addr>
(gdb) run
# 每次停下，记录 [rsi]（字节码）和跳到的 handler
```

### 2. 采集字节码序列
Frida Stalker 追踪 VM 主循环每次迭代，记录字节码值序列：

```javascript
// vm_trace.js
Stalker.follow(Process.id, {
  events: { call: true },
  onReceive: (ev) => {
    // 解析事件，记录 VM 取指与 handler 跳转
  }
});
```

多输入运行，合并字节码序列，提升覆盖率。

### 3. 统计 opcode 频率
高频 = 基本指令（mov/add/jmp），低频 = 复杂指令。据此推断 opcode 表。

### 4. 逐 handler 还原语义
对每个 handler：
- 记录它操作的寄存器/内存
- 反汇编 handler，写等价 C 伪代码
- 标注 opcode 编号

### 5. 写反汇编器/解释器
把字节码序列 + opcode 语义，写成可独立运行的反汇编器或解释器：

```python
# vm_disasm.py 骨架
OPCODES = {0x01:"mov", 0x02:"add", 0x03:"jmp", ...}
def disasm(bytecode, base=0):
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        name = OPCODES.get(op, f"unknown_{op}")
        # 按该 opcode 的 operand 长度读取参数
        print(f"{base+i:04x}: {name} ...")
        i += operand_len(op)
```

### 6. 等价验证
用还原的解释器跑原始字节码，与原程序同输入对比输出，逐条对齐。

## 三、VM 与去混淆的分工

- VM 保护是**最内层**，先去外层混淆（见 `deobfuscation.md`）再处理 VM。
- VM 内的算法（校验、加密）还原后，再定位 CHECK_FN。

## 四、验证

- 反汇编器能完整覆盖字节码，无 unknown 残留（或已标注）
- 还原解释器输出与原程序一致
- 能用高级代码等价替换 VM 校验

## 完整反汇编器示例

```python
OPCODES = {
    0x00: ("nop",  0),    # (助记符, 操作数字节数)
    0x01: ("push", 1),
    0x02: ("pop",  0),
    0x03: ("add",  0),
    0x04: ("sub",  0),
    0x05: ("xor",  0),
    0x06: ("cmp",  0),
    0x07: ("jmp",  2),
    0x08: ("je",   2),
    0x09: ("jne",  2),
    0x0A: ("mov",  2),
    0x0B: ("load", 1),
    0x0C: ("store",1),
    0x0D: ("print",0),
    0x0E: ("read", 0),
    0xFF: ("halt", 0),
}

def disassemble(bytecode):
    pc = 0
    while pc < len(bytecode):
        op = bytecode[pc]
        if op not in OPCODES:
            print(f"  {pc:04x}: UNKNOWN {op:#04x}")
            pc += 1
            continue
        mnemonic, operand_size = OPCODES[op]
        operands = bytecode[pc+1:pc+1+operand_size]
        operand_str = ' '.join(f'{b:#04x}' for b in operands)
        print(f"  {pc:04x}: {mnemonic:8s} {operand_str}")
        pc += 1 + operand_size

# 从二进制提取字节码
import struct
with open('challenge', 'rb') as f:
    f.seek(bytecode_offset)
    bytecode = f.read(bytecode_length)

disassemble(bytecode)
```

反汇编后按标准逆向分析：定位输入读取（read opcode）→ 追踪数据流到比较 → 确定成功/失败条件 → 提取校验逻辑（常为输入经 XOR/ADD 变换后与常数比较）。
