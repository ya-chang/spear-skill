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

## 五、VM 类型识别速查

| 二进制模式 | 疑似 VM | 起步 |
|---|---|---|
| `while(1){ switch(bytecode[pc]) }` | switch 型 dispatcher | 映射每个 case 到操作 |
| `jmp [table + opcode*8]` | 表型 dispatcher | dump 跳转表，分析 handler |
| 字节值嵌套 if-else | if 链 dispatcher | 同 switch，语法不同 |
| 栈 push/pop 为主 | 栈式 VM | 识别 push/pop/算术 |
| `reg[X] = ...` 数组操作 | 寄存器式 VM | 映射寄存器索引到操作 |
| 2D 网格 + 方向输入 | 迷宫题 | 提取网格，BFS/DFS |

## 六、VM 结构组成

```
┌─────────────────────────────────┐
│  字节码程序（数据段）              │
├─────────────────────────────────┤
│  程序计数器 pc/ip                  │
│  寄存器文件 / 栈                   │
│  内存 / 数据区                     │
├─────────────────────────────────┤
│  Dispatcher 循环                  │
│  ├─ 取指：opcode = code[pc]       │
│  ├─ 译码：查 handler               │
│  └─ 执行：跑 handler               │
└─────────────────────────────────┘
```

## 七、dispatcher 签名（IDA/Ghidra）

**switch 型（CTF 最常见）：**
```c
while (running) {
    unsigned char op = bytecode[pc++];
    switch (op) {
        case 0x00: /* nop */       break;
        case 0x01: /* push imm */  stack[sp++] = bytecode[pc++]; break;
        case 0x02: /* add */       stack[sp-2] += stack[sp-1]; sp--; break;
        case 0xFF: /* halt */      running = 0; break;
    }
}
```

**表型（更优化）：**
```c
typedef void (*handler_t)(vm_ctx_t*);
handler_t handlers[256] = { handle_nop, handle_push, handle_add, ... };
while (running) handlers[bytecode[pc++]](&ctx);
```

## 八、opcode 映射属性

对每个 case/handler 确定：

| 属性 | 识别方法 |
|---|---|
| opcode 值 | case 号或表索引 |
| 操作类型 | 寄存器/栈修改 |
| 操作数个数 | opcode 后消费的字节数 |
| 操作数类型 | 立即值、寄存器索引、内存地址 |
| 副作用 | 输出、内存写、标志修改 |

## 九、常见 VM 模式

### 栈式 VM（如 JVM/Python 字节码）

| Opcode | 操作 | 栈效应 |
|---|---|---|
| PUSH imm | 压立即值 | `[...] → [..., imm]` |
| POP | 丢弃栈顶 | `[..., a] → [...]` |
| ADD | 栈顶两数相加 | `[..., a, b] → [..., a+b]` |
| SUB | 相减 | `[..., a, b] → [..., a-b]` |
| MUL | 相乘 | `[..., a, b] → [..., a*b]` |
| XOR | 异或 | `[..., a, b] → [..., a^b]` |
| CMP | 比较 | `[..., a, b] → [..., (a==b)]` |
| JMP addr | 无条件跳转 | 无变化 |
| JZ addr | 栈顶为零则跳 | `[..., a] → [...]` |
| PRINT | 栈顶输出为字符 | `[..., a] → [...]` |
| READ | 读字符入栈 | `[...] → [..., input]` |
| HALT | 停止 | - |

### 寄存器式 VM（如 x86/ARM）

| Opcode | 格式 | 操作 |
|---|---|---|
| MOV r, imm | `0x01 RR II II` | reg[R] = imm16 |
| MOV r1, r2 | `0x02 R1 R2` | reg[R1] = reg[R2] |
| ADD r1, r2 | `0x03 R1 R2` | reg[R1] += reg[R2] |
| SUB r1, r2 | `0x04 R1 R2` | reg[R1] -= reg[R2] |
| XOR r1, r2 | `0x05 R1 R2` | reg[R1] ^= reg[R2] |
| CMP r1, r2 | `0x06 R1 R2` | flags = compare(r1, r2) |
| JMP addr | `0x07 AA AA` | pc = addr |
| JE addr | `0x08 AA AA` | 相等则 pc = addr |
| LOAD r,[addr] | `0x09 RR AA` | reg[R] = mem[addr] |
| STORE [addr],r | `0x0A AA RR` | mem[addr] = reg[R] |
| SYSCALL | `0x0B` | 依 reg[0] 做 I/O |
| HALT | `0xFF` | 停止 |

### Brainfuck 式 / 异构 VM

| BF 命令 | VM 等价 | 说明 |
|---|---|---|
| `>` | INC ptr | 数据指针右移 |
| `<` | DEC ptr | 数据指针左移 |
| `+` | INC [ptr] | 指针处字节递增 |
| `-` | DEC [ptr] | 指针处字节递减 |
| `.` | OUTPUT [ptr] | 输出指针处字节 |
| `,` | INPUT [ptr] | 输入字节到指针 |
| `[` | JZ forward | 字节为零则跳到 `]` 后 |
| `]` | JNZ back | 字节非零则跳回 `[` |

## 十、迷宫题（Maze Challenge）

### 识别
- 二进制读方向输入（WASD、方向键、UDLR）
- 数据段 2D 数组（墙、路、起点、终点）
- 位置跟踪（x,y 坐标）
- 特定坐标获胜

### 地图提取
```python
MAZE_ADDR = 0x601060
WIDTH, HEIGHT = 20, 15
maze = []
for row in range(HEIGHT):
    line = ""
    for col in range(WIDTH):
        cell = bytecode[MAZE_ADDR + row*WIDTH + col - base_addr]
        line += "." if cell == 0 else "#" if cell == 1 else "S" if cell == 2 else "E" if cell == 3 else "?"
    maze.append(line)
    print(line)
```

### 自动求解（BFS）
```python
from collections import deque
def solve_maze(maze, start, end):
    rows, cols = len(maze), len(maze[0])
    directions = {'U': (-1,0), 'D': (1,0), 'L': (0,-1), 'R': (0,1)}
    queue = deque([(start, "")])
    visited = {start}
    while queue:
        (r,c), path = queue.popleft()
        if (r,c) == end: return path
        for name,(dr,dc) in directions.items():
            nr, nc = r+dr, c+dc
            if (0 <= nr < rows and 0 <= nc < cols and
                maze[nr][nc] != '#' and (nr,nc) not in visited):
                visited.add((nr,nc))
                queue.append(((nr,nc), path + name))
    return None
```

### 方向编码对照

| 编码 | 上 | 下 | 左 | 右 |
|---|---|---|---|---|
| WASD | W | S | A | D |
| UDLR | U | D | L | R |
| 方向键 | ↑(0x48) | ↓(0x50) | ←(0x4B) | →(0x4D) |
| 数字 | 1 | 2 | 3 | 4 |
| Hex opcode | 0x01 | 0x02 | 0x03 | 0x04 |

## 十一、真实 VM 保护器

### VMProtect 分析路径
```
1. 找 VM 入口：搜 pushad/pushfd 序列
2. 识别 VM 上下文结构（寄存器、标志、字节码指针）
3. 定位 handler 表（常被不透明谓词混淆）
4. 逐 handler：去垃圾代码/不透明谓词 → 识别核心操作 → 记录语义
5. 指令级 trace 字节码执行
6. 从 trace 重建原始代码
```

### Tigress 混淆器
学术 VM 混淆器，可配置保护层。

| 特性 | 方法 |
|---|---|
| 单 dispatch VM | 标准 handler 提取 |
| 拆分 handler | handler 分散在多个函数 |
| 嵌套 VM | 外层 handler 调内层 VM |
| 加密字节码 | 每次取指前动态解密 |
| 多态 handler | 每次构建同操作不同代码 |

### 常见 VM 保护器模式

| 保护器 | dispatcher 风格 | 难度 |
|---|---|---|
| VMProtect | 表 + 不透明谓词 | 高 |
| Themida（Code Virtualizer） | CISC 式，大 handler 集 | 高 |
| Tigress | 可配置，学术 | 中高 |
| 自定义 CTF VM | 简单 switch | 低中 |
| Movfuscator | 全 mov 计算 | 中 |

## 十二、工具与 Ghidra Sleigh 处理器

| 工具 | 用途 | 用法 |
|---|---|---|
| IDA Pro | 识别 dispatcher、还原 handler | F5 反编译、xref |
| Ghidra | 免费替代，Sleigh 处理器模块 | 为 VM ISA 写自定义处理器 |
| angr | 符号执行穿过 VM | 整个 VM 作约束系统 |
| Pin / DynamoRIO | 动态插桩 trace | 记录 opcode handler 执行序列 |
| REVEN | 全系统 trace | 回放分析 VM 执行 |
| Unicorn | 仿真 VM | 快速 handler 仿真 |
| Miasm | IR 分析 | 提升 VM handler 到 IR |
| 自定义 Python | 写反汇编/反编译器 | 逐题定制工具 |

### Ghidra Sleigh 处理器模块（可复用 VM 架构）
```
define space ram      type=ram_space      size=2  default;
define space register type=register_space  size=1;

define register offset=0 size=1 [ R0 R1 R2 R3 FLAGS PC SP ];

define token opcode(8)
    op = (0,7)
;

:NOP    is op=0x00 { }
:PUSH   imm is op=0x01; imm { SP = SP - 1; *[ram]:1 SP = imm; }
:POP    is op=0x02 { SP = SP + 1; }
:ADD    is op=0x03 { local a = *[ram]:1 (SP+1); *[ram]:1 (SP+1) = a + *[ram]:1 SP; SP = SP + 1; }
```

## 十三、决策树与 CTF 求解流程

### 决策树
```
含自定义字节码解释器？
├─ 能识别 dispatcher？
│  ├─ 能（switch/表/if 链）
│  │  ├─ opcode 少（<20）→ 简单 CTF VM
│  │  │  ├─ 栈式 → 映射 push/pop/算术
│  │  │  ├─ 寄存器式 → 映射 mov/add/cmp
│  │  │  └─ 写反汇编器 → 分析程序 → 求解
│  │  └─ opcode 多（50+）→ 商业保护
│  │     ├─ 已知保护 → 专用去保护工具
│  │     └─ 自定义 → trace 执行、模式匹配 handler
│  └─ 无明确 dispatcher
│     ├─ 全 mov → movfuscator
│     ├─ 加密字节码 → 找解密、解码后 dump
│     └─ 拆分/分布式 handler → trace 找
├─ 迷宫题？
│  ├─ 数据段提取网格
│  ├─ 识别方向编码
│  ├─ BFS/DFS 找最短路径
│  └─ 路径转期望输入格式
├─ VM 内有输入校验？
│  ├─ 输入空间小 → Unicorn 仿真暴力
│  ├─ 已知格式 → angr 约束求解
│  └─ 复杂校验 → 写反汇编器、分析校验逻辑
└─ 多层 VM（VM 套 VM）？
   ├─ 先分析外层 VM
   ├─ 提取内层字节码
   ├─ 对内层重复分析
   └─ 考虑：符号执行可直处理嵌套 VM
```

### CTF 求解工作流
```
1. 运行二进制 — 理解 I/O 行为
   └─ 期望什么输入？成功/失败输出？
2. IDA/Ghidra 打开 — 找主循环
   └─ 找 while/for + switch 或间接跳转
3. 识别 VM 组件：
   ├─ 字节码位置（程序数据在哪）
   ├─ PC/IP 变量（当前位置如何跟踪）
   ├─ 寄存器/栈（VM 状态存哪）
   └─ I/O handler（哪些 opcode 读输入/写输出）
4. 映射全部 opcode（建 ISA 规范）
   └─ 每个 case/handler：opcode 号、操作、操作数
5. Python 写反汇编器
   └─ 输出字节码的可读汇编
6. 分析反汇编程序：
   ├─ 找输入读取
   ├─ 跟踪输入的变换
   ├─ 找与期望值的比较
   └─ 反推变换求有效输入
7. 求解：
   ├─ 简单变换（XOR/ADD）→ 手工反推
   ├─ 复杂 → 作约束喂给 Z3
   └─ 迷宫 → 提取网格、跑寻路
```
