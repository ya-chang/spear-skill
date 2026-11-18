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

- [ ] 反汇编器能完整覆盖字节码，无 unknown 残留（或已标注待确认的 opcode）
- [ ] 还原解释器输出与原程序一致（同一输入，VM 输出与原生执行结果逐字节相等）
- [ ] 能用高级代码等价替换 VM 校验（替换后原程序校验逻辑仍通过）
- [ ] VM 字节码 IR 提升后无死代码（编译器优化后控制流无断裂）
- [ ] 重新生成的可执行代码能独立运行（不依赖原 VM 解释器）

## 四·五、代码骨架：VM 字节码解释器模板

> 可编译运行的最小 VM 解释器骨架，对应 common-techniques.md §8 四要素。关键 opcode 按样本扩展。

```c
// vm_interpreter.c — 最小 VM 字节码解释器骨架
// 四要素：values[] 存储、虚拟寄存器映射、操作码、PC 偏移
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define VM_REG_COUNT 32
#define OP_ADD 1
#define OP_SUB 2
#define OP_MUL 3
#define OP_LOADI 4   // 写常量
#define OP_JMP 5     // 跳转
#define OP_HALT 6    // 停止

typedef struct {
    uint32_t regs[VM_REG_COUNT];  // 虚拟寄存器文件
    const uint8_t *code;          // 字节码
    size_t code_size;
    size_t pc;                    // 虚拟 PC（字节偏移）
} VM;

// 解释主循环
void vm_run(VM *vm) {
    while (vm->pc < vm->code_size) {
        uint8_t op = vm->code[vm->pc];
        uint8_t dst = vm->code[vm->pc + 1];
        uint8_t lhs = vm->code[vm->pc + 2];
        uint8_t rhs = vm->code[vm->pc + 3];
        vm->pc += 4;  // 每条指令 4 字节

        switch (op) {
            case OP_ADD:
                vm->regs[dst] = vm->regs[lhs] + vm->regs[rhs];
                break;
            case OP_SUB:
                vm->regs[dst] = vm->regs[lhs] - vm->regs[rhs];
                break;
            case OP_MUL:
                vm->regs[dst] = vm->regs[lhs] * vm->regs[rhs];
                break;
            case OP_LOADI:
                // LOADI: [op, dst, imm(低), imm(高)] 写常量
                vm->regs[dst] = (vm->code[vm->pc - 2] | (vm->code[vm->pc - 1] << 8));
                vm->pc += 2;  // LOADI 额外读 2 字节立即数
                break;
            case OP_JMP:
                vm->pc = (vm->code[vm->pc - 2] | (vm->code[vm->pc - 1] << 8));
                break;
            case OP_HALT:
                return;
            default:
                printf("unknown opcode %u at pc=%zu\n", op, vm->pc - 4);
                return;
        }
    }
}

int main() {
    // 示例字节码：R2 = R0 + R1; halt
    uint8_t code[] = {
        OP_ADD, 2, 0, 1,   // R2 = R0 + R1
        OP_HALT, 0, 0, 0,
    };

    VM vm = {0};
    vm.code = code;
    vm.code_size = sizeof(code);
    vm.regs[0] = 10;  // a
    vm.regs[1] = 4;   // b
    vm.pc = 0;

    vm_run(&vm);
    printf("result = %u (expected 14)\n", vm.regs[2]);
    return 0;
}
```

编译：`gcc -o vm_interpreter vm_interpreter.c`。验证：运行输出 `result = 14`，与原生 `a+b` 一致。扩展 opcode 后用多组输入对比 VM 与原生执行。

> 更新：2026-11-17 · 来源：骨架为通用模板，对应 common-techniques.md §8

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

## 十四、AI 辅助代码虚拟化（VMP）分析流水线

> 来源：看雪帖《代码虚拟化面对AI时代的冲击即将彻底被击溃》（KimoHex，2026-08），
> IDA + Grok 4.5 + Rust 骨架（执行侧参考 momo5502/sogen）。**人定方向 + AI 写流水线。**

### 定位与结论
- 虚拟化不会被一句 prompt 直接秒掉；真正被击穿的是「纯手工跟流、手写 handle 语义、
  把优化后空壳汇编当还原成功」的老路子。**人肉门槛被拆，语义门槛刚开始对轰。**
- 把按周按月抠 handle 的活压到按天迭代，产出物是 `.ll`/`.s`/`.obj` 的「量产」流水线。

### 前备知识（先给 AI 讲清概念，否则它一本正经输出错误内容）
- 必须讲清：`VmContext`（上下文）、`handle`（混淆代码入口）、堆栈机语义。
- 名词对齐：**VIP**＝虚拟机读「哪一行假代码」的指针；**VSP**＝虚拟机自己的小栈（存中间结果）；
  **handle**＝一小步真正干活的混淆代码入口；**FDE**＝取指—译码—派发循环入口；
  **MicroOp**＝语义标签（跳转/存数/未知）。

### 四阶段流程
1. **先 Python 模拟冒烟**：先让 AI 用 Python 写模拟执行跑通（改得快、错了马上重来），
   确认它真懂步骤后，再进 plan、搭 Rust/LLVM 重框架。让 AI 优先搞清：VmContext 放哪、
   VIP/栈/标志位怎么转、前几个 handle 的汇编语义。
2. **选最大 VM 函数**：**别看 IDA 函数方块大小**（常是假象）；用模拟器批量扫——
   谁进虚拟机分发次数最多、扫过混淆代码点最多、指令跑得最长，谁才是真最大。
   样本量级：近 200 圈分发循环、两百多步虚拟指令流、六十来个不同 handle 入口。
   **最大的是「虚拟机干活多」，不是「优化完 IR 还很长」**——语义没钉死，优化器一删只剩空 call，
   那是没还原到位，不是函数小。
3. **流水线串联**：模拟执行跑分发圈 → 静态规则补缺口 → 整理成虚拟指令流（跳转/存数/派发）
   → 抬成 **LLVM IR** → 要完整过程出 full 版；要真系统调用再叠 IAT。
   工程分模块：decode / 模拟 / lift / 签名。
4. **IR 与回编译**：LLVM 定位为**中转站和工程化出口**；虚拟机语义脏时优化会帮倒忙，
   完美还原最终靠**自己的语义表 + 数据流**。

### 踩坑四则（与既有方法论互证）
- **优化完只剩 call**：三因叠加——① 流上标了条件跳转，decode 只认 handler 地址表，
  **JSON 里双沿信息被吃丢**；② VIP 地址窗口写死旧样本范围，新样本双沿全被过滤；
  ③ 为好优化跳过真实内存写，优化器合法删光。修好后 IR 长出 `icmp`/`br i1`，
  汇编落 `je` + `call MessageBoxA`——**中间表示写对，后端自然吐正常跳转与 API 调用**。
- **假 cmp、假 jcc**：`vmp_vjcc_cond` 假函数当条件、空标志位槽乱 cmp 都是错的；
  很多「双沿」只是历史见过两个后继地址，**不等于 CPU 零标志置位就跳**。
  铁律：有真实运算留下的标志才生成真条件跳，没有就注释「有两条边」，
  **宁可短得真实，不长得假**。
- **full 模式**：要完整过程别迷信 `-O3`（优化器删「没用」的，语义没钉死删得越狠越像还原失败）；
  full 模式一步 handle 不丢、每步留痕；还原不了的用 **`unk_iat_func` 占位**
  （参数带 handler 地址和 VIP，不是导入表真 API）。
  两套答案：优化器眼里还剩啥 → hybrid/O3 小文件；完整 handle 过程 → full 大文件。
- **命名**：占位函数别叫 `vmp_step`（像官方探针），用 `unk_iat_func` 一眼即知未知体/占位。

### 系统调用识别（handle 地址 ≠ 导入函数）
- full 里的 `unk_iat_func(0x1406…)` 是「虚拟机跳进某块 handler」，**不是调 ZwXxx**。
- 先静态扒导入表（内核驱动常见 `Mm*`/`Ps*`/`Ke*`/`Flt*`），但「可能用」≠「这条路径真调了」；
  再把导入表槽绑**空桩**，模拟器跑最大桩抓**真实 call 顺序**
  （样本路径：查时间粒度→初始化事件→初始化字符串→创建通知事件→初始化互斥→创建系统线程
  →按句柄引用对象→关闭句柄，即起线程弄同步对象，并非每个 handle 都捅系统调用）。
- 写回 IR **分两截**：上半截真名真姓的系统 API（动态抓到的），下半截完整 handle 流（未知用 unk 占位）。

### 与 AI 协作钉死的清单
```text
1. 先 Python 模拟冒烟，确认真的进了虚拟化区
2. 批量扫，按「分发有多勤」选最大目标，别只看函数方块
3. 动态轨迹 + 静态补洞 → 虚拟指令流
4. decode 一定要吃双沿信息；VIP 范围按当前样本标，别抄旧样本
5. 看结果要分层：要过程 → full；要真 API → 动态 IAT；O3 空壳只当「副作用还剩啥」
6. 没真标志位就别造 jcc
7. handle 地址永远别直接当成导入函数名
```

> 关联：本节是上方「二、还原步骤」传统人肉流程的 AI 加速版，两者互为补充；
> 处理顺序仍遵循「VM 保护最后处理」的铁律。

---

## 十六、VMP 结构识别与指令语义拼接（实战）

### 一、先分清"三种东西"，别混着打

| 名称 | 本质 | 打法 |
|---|---|---|
| **压缩壳** | 只是压缩 + 解压，OEP 后原样 | 找 OEP、dump、修 IAT（→ 详见 `unpacking.md`） |
| **虚拟化（VMP/Themida）** | 把 x86 翻译成自定义 pcode，靠 handler 解释 | 理解 VM 结构，或**只针对被虚拟化的那个函数**做等价替换 |
| **反调试/反虚拟机** | 一堆环境检测，命中就改行为 | **按层整体拆除**，不是逐点 nop（→ 详见 `anti-debug.md` §十） |

**成本判断**：反调试是 O(1) 单点防御（一个开关），虚拟化是 O(n)。先拆反调试，再谈虚拟化——顺序反了会在"程序行为诡异"上浪费几天。

### 二、VMP 的四个构成

```
┌─ 派发器 (dispatcher) ── 读出下一条 pcode，跳到对应 handler
├─ handler ───────────── 每条 pcode 一个（或合并）
├─ 虚拟栈 (VM stack) ─── handler 从栈上取操作数、写回结果
└─ 虚拟寄存器 (regfile) ─ 映射真实寄存器，通常一个基址 + 偏移
```

`cmPush` / `cmPop` / `cmAdd` 这类伪指令是"人给 handler 起的名字"，不是官方术语——但它们抓住了本质：**每个 handler 只做一件事，操作数来自虚拟栈**。

### 三、识别指令的方法（最实用的技巧）

> **本行（handler）的栈顶，必须出现在下一行的操作数里。**

因为 VM 是栈式的：一条指令把结果压栈，下一条指令从栈顶取。所以：

1. 记录每个 handler 出口时虚拟栈的变化（压了几个、弹了几个）；
2. 下一条 handler 入口读的是哪个栈槽；
3. 两者对上 → 这两条指令有数据依赖 → 可以拼出语义。

配套：观察 handler 的**形状分类**（长度、是否有内存访问、是否有除法指令、是否读 `flags`），同一类形状往往对应同一族运算。

### 四、VMP2 的实测上限

- VMP1：一条派发链，纯栈式，容易看出"两条指令一组"。
- VMP2：**最多同时存在两台虚拟机**——壳一台、被保护函数一台。看到"两套派发器"不代表有两个函数被虚拟化，而是壳自己也在 VM 里跑。

这条上限很省时间：如果以为有第三台，通常是误读了"壳的 VM 在给函数的 VM 解密"。

### 五、不要从第一个字符开始追

真实教训：想找出被比较的字符串，从第一位开始追变换，会被几十轮移位/乘加淹没。

**正确做法**：直接在**比较指令处**读两个操作数。VM 无论怎么绕，最终一定要把结果和期望值比较——那里是唯一的必读点。

> 中间那串"循环移位 + 乘常数 + 加常数 + 异或"看起来像某个公开哈希的收尾，拿去对常见哈希通常对不上。**不要在这里猜算法名字。**

### 六、五个角色寄存器（读 handler 时的定位锚）

VMP handler 里通常有固定的角色分工（x86 例子，真实案例）：

| 角色 | 典型寄存器 | 作用 |
|---|---|---|
| **pcode 指针** | esi | 指向当前字节码 |
| **虚拟栈指针** | edi | 指向 VM 栈顶 |
| **跳转目标暂存** | eax / ebp | 下一个 handler 地址 |
| **加密密钥** | **ebx** | 用于滚动解密 handler 地址 |
| **虚拟寄存器文件** | **esp** | 用真实栈当 regfile（"栈"和"寄存器"是一回事） |

认出这五个，handler 就能读了。**识别方法**：看哪个寄存器在所有 handler 里都被赋相同类型的值（密钥寄存器会被 `xor`/`add` 常数）。

### 七、加壳程序的 dump（WinLicense/Themida 类）

真实案例（GlassWire 逆向）的可复现配方：

```
1. 逐节算熵：< 6.8 的节通常已经是解压后的原始映像（壳已解完）
2. 运行到"壳解完、OEP 还没执行完"的时机（常见判据：某节熵突然下降）
3. NtSuspendProcess 挂起所有线程（比 SuspendThread 可靠，避免线程池绕过）
4. Scylla dump + 修复 IAT + 重建区段
5. 用 dump 出的文件离线分析（此时算法是明文的）
```

**判据**：dump 出来的文件能独立运行 / 能被 IDA 正常分析（F5 不出垃圾），才算成功。

**熵的误读**：`熵 < 6.8` 不等于"没加壳"，只是"这一节现在是明文"。要结合"壳代码所在节熵很高 + 目标节熵突然降低"一起看。`.sys` 的 INIT 段在初始化后会被释放，看起来像"被壳压缩了"，其实是编译器行为——不要把编译器行为误读成加壳。

### 八、成本视角（决定投入多少）

| 保护 | 攻击成本 | 现实结论 |
|---|---|---|
| 单点反调试 | O(1) | 一个 hook 就全废——不要为它设计复杂方案 |
| 多层反调试 | O(n) 但同质 | 找汇聚点后仍接近 O(1) |
| VMP 保护关键函数 | O(n) 且异质 | 只对"那一个函数"做等价替换，不要整体脱壳 |
| VMP + 自校验 + 反调试 + 云校验 | 耦合级 | 找"没有虚拟化、没有校验"的那条缝（数据层/协议层） |

> 评估保护强弱只有一个尺子：**它把攻击成本抬到了哪一级**。招数多但全押在一点上，仍是 O(1)。

### 验证

- [ ] VM 类型已区分（压缩壳/虚拟化/反调试），按"先反调试后虚拟化"顺序处理
- [ ] 用"栈顶出现在下一行操作数"法拼接出指令语义，拼不出的不硬猜
- [ ] VMP2 上限已确认（最多壳+函数两台），未误把壳的 VM 当成第三台
- [ ] 被比较的值直接从比较指令处读取，未从第一位字符追变换、未猜哈希名
- [ ] 五个角色寄存器已识别，dump 时机按熵下降判定，dump 产物可独立运行/分析

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）
