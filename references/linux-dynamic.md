# Linux 动态分析协同（linux-dynamic）

目标：GDB / r2 / Frida / angr / strace / ltrace 多工具协同，静态看不清的用动态补。**每个关键发现至少两个工具交叉确认。**

## 一、环境探测

```bash
for t in gdb lldb r2 objdump readelf nm strings strace ltrace perf valgrind bpftrace; do
  which $t >/dev/null 2>&1 && echo "$t: OK" || echo "$t: MISSING"
done
python3 -c "import frida,angr" 2>/dev/null && echo "frida/angr OK" || echo "frida/angr MISSING"
cat /proc/sys/kernel/randomize_va_space   # ASLR
cat /proc/sys/kernel/yama/ptrace_scope    # ptrace 限制
```

## 二、工具分工

| 工具 | 擅长 | 盲点 |
|---|---|---|
| GDB | 精确控制、寄存器/内存快照 | 不看系统调用全貌 |
| strace | 完整系统调用 | 不看库函数 |
| ltrace | 库函数参数 | 不看内联代码 |
| r2/静态 | 不受反调试影响 | 看不到运行时值 |
| Frida | 灵活 hook | 注入可被检测、开销大 |
| angr | 路径完整、约束求解 | 路径爆炸 |

## 三、核心命令

### GDB（+pwndbg）
```gdb
vmmap                      # 内存映射
telescope $rsp 20          # 栈递归
context                    # 寄存器+栈+反汇编一屏
checksec                   # 安全标志
rop --grep "pop rdi; ret"  # 找 gadget
heap / bins                # 堆状态
```

### strace
```bash
strace -tt -T ./target 2>&1 | tee /tmp/strace.log
strace -e trace=file,network,memory ./target
strace -f -p <pid>         # 附加运行中进程
strace -c ./target         # 统计
```

### ltrace
```bash
ltrace -e strcmp,memcmp,EVP_*,AES_* ./target
ltrace -tt -T -n 2 ./target
```

### Frida
```javascript
// hook 函数参数与返回值
Interceptor.attach(Module.findExportByName(null, "target_func"), {
  onEnter(args) { console.log("arg0", args[0]); },
  onLeave(ret) { console.log("ret", ret.toInt()); }
});
```

### angr
```python
import angr
proj = angr.Project("./target", auto_load_libs=False)
cfg = proj.analyses.CFGFast()
# 符号执行 / 路径枚举
```

## 四、结构体 / vtable 恢复

```bash
r2 -A -q -c 'avj' target    # 所有 vtable
```

结构体字段推断规则：
- `[base + N]` 反复访问 → 字段 N
- 访问大小推断类型：b=uint8 / w=uint16 / d=uint32 / q=uint64
- `malloc(M)` 后多字段初始化 → 结构体大小 M
- 相邻偏移间隙 → padding

置信度：动态验证(GDB/Frida 实读)+30，跨函数一致+15，仅一处访问-10。≥90% 标 CONFIRMED。

## 五、动态-静态交替节奏

```
[静态] r2 aaa → 函数列表 + CFG 骨架
  ↓
[动态-宽] strace + ltrace 全量 → 找热点和关键行为
  ↓
[静态] 对热点函数详细反汇编，推断算法/结构体
  ↓
[动态-精] GDB 断点 + Frida hook → 验证静态推断
  ↓
[自动化] angr/bpftrace → 补 GDB 难追踪的部分
  ↓
[更新] 动态结果写回结构体推断卡 + 算法置信度
  ↓ 循环
```

## 六、常见错误处理

| 错误 | 原因 | 处理 |
|---|---|---|
| `ptrace: Operation not permitted` | ptrace_scope=1 | `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 或 `gdb -f ./target` |
| `no debugging symbols` | stripped | r2 `aaa`、GDB `b *addr`、angr CFGFast |
| `Cannot access memory` | PIE+ASLR | pwndbg `vmmap` 算基址，或 `set disable-randomization on` |
| strace EPERM | 权限 | `sudo strace` |
| perf Permission denied | perf_paranoid>0 | `echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid` |

## 七、LD_PRELOAD 注入（绕过校验示例）

```c
// hook_strcmp.c — 拦截 strcmp，伪造返回 0（密码绕过示例）
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
int strcmp(const char *s1, const char *s2) {
    typedef int (*fn_t)(const char*, const char*);
    fn_t orig = dlsym(RTLD_NEXT, "strcmp");
    int ret = orig(s1, s2);
    fprintf(stderr, "[strcmp] %s vs %s -> %d\n", s1, s2, ret);
    return ret;
}
```
```bash
gcc -shared -fPIC -o hook_strcmp.so hook_strcmp.c -ldl
LD_PRELOAD=./hook_strcmp.so ./target
```

## vtable 继承关系推断

**推断规则：**
1. 子类 vtable 前 N 个条目与父类 vtable 相同（N = 父类虚函数数量）
2. 子类 vtable 在父类基础上追加新虚函数
3. 多继承：子类对象包含多个 vptr，排列按继承顺序

**识别多继承：** 构造函数中对 this 的不同偏移分别写入 vptr：
```asm
mov [rdi + 0x00], vtable_A    ; 第一个基类 vptr
mov [rdi + 0x20], vtable_B    ; 第二个基类 vptr（偏移 = 第一个基类大小）
```

**r2pipe 继承分析：**
```python
import r2pipe, json
r = r2pipe.open('./target', flags=['-A', '-2'])
vtables = json.loads(r.cmd('avj') or '[]')
# 对每对 vtable 检查前缀关系（疑似继承）
for vt_a in vtables:
    for vt_b in vtables:
        # 比较 vt_a 前 N 个条目是否与 vt_b 匹配 → 推断继承
```

## 记忆机制（上下文快照）

### 上下文快照
每 10 轮对话自动生成一份上下文快照，保存分析进度，下次对话可无缝继续。

**快照内容：**
- 目标信息：文件、架构、编译器、安全标志
- 工具确认：GDB/r2/Frida/angr 等版本
- 混淆状态：clean/upx/olllvm/vmprotect
- 算法发现：名称、置信度、函数地址、验证状态
- 结构体恢复：字段布局
- 函数分析：已完成/待分析
- 动态分析：strace/ltrace/Frida 结论
- 待办任务、未解决点

### P0-P3 优先级
- **P0（突破性发现）**：密钥、密码、核心算法、绕过验证——永不丢弃
- **P1（重要进展）**：结构体确认、函数完整分析、反调试绕过——优先保留
- **P2（中间结论）**：疑似算法、结构体疑似字段——可压缩
- **P3（常规记录）**：已完成函数、工具记录——可截断

### STAGED → COMMITTED 两阶段门控
- **STAGED（暂存）**：单工具单次观测，标注 `[STAGED]`，不写入正式发现
- **COMMITTED（提交）**：两个独立工具交叉验证 + 无矛盾证据，正式写入
- 防止未验证结论在下次对话中被当作事实，避免幻觉传播

## 八、多线程调试

### GDB 多线程核心命令
```gdb
info threads              # 所有线程
thread <N>               # 切换到线程 N
thread apply all bt      # 所有线程调用栈
thread apply all continue # 所有线程继续
```

```bash
# 只暂停特定线程（其他继续）
gdb -p <pid> -ex "thread 2" -ex "continue"
# 对特定线程设断点
(gdb) thread 3
(gdb) break *0xADDR
```

```bash
# 监控线程创建/销毁
(gdb) set detach-on-fork on
(gdb) set follow-fork-mode child
```

### strace 多进程/线程追踪
```bash
strace -f -p <pid>          # 跟踪所有子进程和线程（-f 跟随 fork/thread）
strace -ff -p <pid>         # 每个线程单独文件 /tmp/strace_t.<pid>/<tid>
```

### 竞态条件定位（Helgrind + GDB）
```bash
helgrind ./target 2>&1 | grep -A5 "Possible data race"
```
在竞态点设 watchpoint：
```gdb
rwatch *(volatile int*)0xADDR
```

## 九、信号处理调试

```gdb
info handle               # 当前所有信号处理设置
handle SIGALRM stop print # 修改信号处理方式
kill -SIGALRM <pid>       # 手动发信号
```

```bash
# 调试自定义信号处理函数
(gdb) break sighandler
(gdb) run
(gdb) signal SIGALRM
# 追踪信号注册（sigaction 调用）
(gdb) break sigaction
```

```bash
# strace 追踪信号
strace -e trace=rt_sigaction,rt_sigprocmask ./target
# 查看进程当前信号掩码（/proc/<pid>/status）
# SigPnd 挂起 / SigBlk 屏蔽 / SigIgn 忽略 / SigCgt 捕获
```

## 十、ASLR 交互与地址计算

### 运行时基址获取
```gdb
# 方法 1：pwndbg vmmap
vmmap
# 方法 2：info proc mappings
info proc mappings
# 方法 3：从 /proc 读取（程序暂停时）
cat /proc/<pid>/maps
```

### PIE 地址实时换算（gdb 辅助脚本）
```python
# gdb_pie_helper.py — source 到 GDB
import gdb
def bp_pie(offset):
    base = int(gdb.parse_and_eval("(unsigned long)&_start") & ~0xfff)
    # 对静态偏移设断点
    gdb.execute(f"break *{base + offset:#x}")
gdb.define_function("bp_pie", bp_pie)
```
```gdb
(gdb) python bp_pie(0x1234)   # 在静态偏移 0x1234 设断点
```

### ASLR 暴力复现（调试用）
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # 关闭 ASLR
# 或在 GDB 内（默认已开启）
(gdb) set disable-randomization on
```

## 十一、/proc 深度集成

### 实时内存分析
```bash
# 方法 1：dd 从 /proc/pid/mem 读（需权限）
dd if=/proc/<pid>/mem bs=1 skip=$((0x400000)) count=256 2>/dev/null
# 方法 2：GDB Python API（更安全）
(gdb) python
inf = gdb.selected_inferior()
mem = inf.read_memory(0x400000, 0x100)
```

### /proc/pid/maps 解析脚本
```python
import re
with open(f"/proc/{pid}/maps") as f:
    for line in f:
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S{4}) (\S+)', line)
        if m:
            start, end, perms, path = m.groups()
            print(f"{start}-{end} {perms} {path}")
```

### 文件描述符追踪
```bash
ls -l /proc/<pid>/fd/          # 实时监控打开的文件
cat /proc/<pid>/net/tcp        # 网络连接（本地/远端/状态）
# 状态：06=TIME_WAIT 0A=LISTEN 01=ESTABLISHED
```

## 十二、core dump 完整分析

```bash
# 步骤 1：准备环境
ulimit -c unlimited
echo '/tmp/core.%e.%p.%t' | sudo tee /proc/sys/kernel/core_pattern
# 步骤 2：触发 core（或用已有 core）
# → 生成 /tmp/core.target.<pid>.<timestamp>
# 步骤 3：验证 core 文件
file /tmp/core.target.*
# 应输出：ELF 64-bit LSB core file x86-64 ... from 'target'
# 步骤 4：GDB 基础分析
gdb ./target /tmp/core.target.*
(gdb) bt          # 调用栈
(gdb) info registers
(gdb) x/20i $pc   # 崩溃点反汇编
# 步骤 5：深度分析
(gdb) thread apply all bt
(gdb) info locals
# 步骤 6：eu-stack（快速）
eu-stack -p <pid>
```

## 十三、LD_PRELOAD 深度工作流

### 通用 Hook 模板库
```c
// hook_common.c — 拦截指定函数，记录参数并可篡改返回值
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// 示例：拦截 strcmp，伪造返回 0（校验绕过）
int strcmp(const char *s1, const char *s2) {
    typedef int (*fn_t)(const char*, const char*);
    static fn_t orig = NULL;
    if (!orig) orig = (fn_t)dlsym(RTLD_NEXT, "strcmp");
    int ret = orig(s1, s2);
    fprintf(stderr, "[strcmp] %s vs %s -> %d\n", s1, s2, ret);
    return ret;   // 需要绕过时改为 return 0;
}

// 示例：拦截 fopen，过滤 /proc/self/status 的 TracerPid
FILE *fopen(const char *path, const char *mode) {
    typedef FILE* (*fn_t)(const char*, const char*);
    static fn_t orig = NULL;
    if (!orig) orig = (fn_t)dlsym(RTLD_NEXT, "fopen");
    if (strstr(path, "/proc/self/status")) {
        // 返回伪造句柄或过滤内容
    }
    return orig(path, mode);
}
```
```bash
gcc -shared -fPIC -o hook_common.so hook_common.c -ldl
LD_PRELOAD=./hook_common.so ./target
```

## 十四、跨架构调试（ARM64 on x86）

### QEMU user mode（最简单）
```bash
sudo apt-get install -y qemu-user qemu-user-static
# 直接运行 ARM64 ELF
qemu-aarch64 ./target_arm64
# 带 GDB stub 运行
qemu-aarch64 -g 1234 ./target_arm64
# GDB multiarch 连接
gdb -q ./target_arm64 -ex "set architecture aarch64" -ex "target remote :1234"
```

```bash
# strace 跨架构追踪
strace -c qemu-aarch64 ./target_arm64
# r2 静态分析 ARM64
r2 -A -q -c 'iI; aaa; afl' ./target_arm64
```

## 十五、动态工具协调（自动附加与事件联动）

### 进程自动发现与附加
```bash
# auto_attach.sh — 监控目标进程启动，立即附加 GDB
while true; do
  pid=$(pgrep -f './target')
  if [ -n "$pid" ]; then
    gdb -p "$pid" -ex "continue" -batch
    break
  fi
  sleep 0.1
done
```

### 事件驱动多工具联动
```
strace 事件 → 自动触发 GDB 检查
  ├─ open(密钥/配置) → GDB 断 read 返回 dump 内容
  ├─ mprotect(EXEC) → bpftrace 追踪后续首条指令
  └─ strcmp/memcmp → Frida hook 同函数取完整参数

GDB 断点触发 → 自动启动 Frida 深度 dump
Frida 事件 → 自动触发 bpftrace 内核追踪
```

### GDB non-stop 并发分析
```gdb
set non-stop on
set target-async on
# 断点触发只暂停当前线程，其他线程继续
b sym.target_func
commands
  printf "[hit] rdi=%p rsi=%p\n", $rdi, $rsi
  x/32xb $rdi
  continue &    # 异步继续
end
attach <pid>
```

## 十六、结构体恢复细节补充

### r2 pf（print format）命令（无需 td 类型系统）
```bash
# 基本格式字符：b=uint8 w=uint16 d=uint32 q=uint64 p=指针 s=字符串 S=宽字符串 f=float F=double
r2 -q -c 'pf qp @ 0x602000' target       # 打印地址处结构体
r2 -q -c 'pfq qpq @ 0x602000' target      # 命名字段
```

### r2 td 类型定义（高级）
```bash
r2 -q -c 'td obj_X=Q+4i+Q' target         # 定义 C 风格结构体
r2 -q -c 'tdL' target                      # 查看已定义类型
r2 -q -c 'afv obj_X @ 0x602000' target     # 在反汇编中应用
```

### GDB 自定义 pretty-printer
```python
# gdb_printers.py — 加载：source gdb_printers.py
import gdb
class SessionCtxPrinter:
    def __init__(self, val): self.val = val
    def to_string(self):
        vptr = self.val['vptr']
        return f"SessionCtx(vptr={vptr})"
gdb.pretty_printers.append(SessionCtxPrinter)
```

### angr 辅助结构体分析
```python
# 追踪所有 malloc 分配大小，统计最常见大小（可能即主结构体大小）
proj = angr.Project('./target', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
# 对函数做值集分析，找可能越界访问
```

### 常见运行时结构体

**std::string（libstdc++ ABI）：**
```c
struct std::string {
    char* _M_dataplus;   // 0x00 数据指针
    size_t _M_string_length;  // 0x08 长度
    // 小字符串优化：局部缓冲区
};
```

**glibc malloc chunk：**
```c
struct malloc_chunk {
    size_t prev_size;   // 0x00
    size_t size;        // 0x08（含标志位）
    // fd/bk（非 fastbin）
};
```

## 十七、angr 符号执行工作流

### 找到达目标地址的输入
```python
import angr, claripy
proj = angr.Project('./target', auto_load_libs=False)
# 创建符号化输入（64 字节）
flag = claripy.BVS('flag', 64)
state = proj.factory.full_init_state(args=['./target'], stdin=angr.SimPackets(flag))
# 探索：找到 0x401234，避开 0x401500（失败路径）
mgr = proj.exploration(state=state,
    avoid=0x401500, target=0x401234,
    strict_addresses=True)
print(mgr.stashes['target'][0].solver.eval(flag, extra_constraints=[flag != 0]))
```

### 序列号/密码验证绕过
```python
# 方案 A：argv 输入
flag = claripy.BVS('flag', 32)
state = proj.factory.full_init_state(args=[flag], stdin=angr.SimPackets(flag))
# 约束：可打印字符
constraints = [flag >= 0x20, flag <= 0x7e]
# 找到打印 "Correct"/"Success" 的路径
mgr = proj.exploration(state=state, avoid=0x401500, target=0x401234)
```

### 路径探索策略
```python
# 深度优先（避免路径爆炸）
mgr = proj.exploration(state=state, avoid=0x401500, target=0x401234,
    num_find=1, max_depth=10)
# 循环限制（处理循环多的代码）
mgr = proj.exploration(state=state, avoid=0x401500, target=0x401234,
    max_steps=10000)
# Veritesting（合并路径，提升效率）
mgr = proj.exploration(state=state, avoid=0x401500, target=0x401234,
    veritesting=True)
```

### 约束求解（不运行二进制）
```python
import claripy
x = claripy.BVS('x', 32)
s = claripy.Solver()
# 已知变换：result = (x * 0x1337) ^ 0xdeadbeef = 0xcafebabe
s.add((x * 0x1337) ^ 0xdeadbeef == 0xcafebabe)
print(s.eval(x))
```

### 内存约束（验证解密数据）
```python
# 创建符号密钥（16 字节 AES key）
key = claripy.BVS('key', 16)
state = proj.factory.full_init_state()
# 将符号 key 写入 rdi 指向位置
state.memory.write(rdi_addr, key)
# 运行到解密完成，检查输出
```

### Hook 系统函数
```python
# Hook malloc — 返回符号化堆地址
@proj.hook
def malloc_hook(state):
    return state.solver.BVV(0x7fff0000, 64)
# Hook strcmp — 强制返回相等
@proj.hook
def strcmp_hook(state):
    return 0
```

### 调优
```python
# 路径爆炸处理：给未知函数返回符号值（避免 hang）
proj.set_plugin_option('syscall', 'ignore_memory_errors', True)
# 内存与性能优化：禁用不需要的分析
cfg = proj.analyses.CFGFast(force_complete_scan=False)
```

## 十八、Frida 脚本库补充

### 内存 dump 到文件
```javascript
// dump 指定范围到文件
var fs = require('fs');
var start = 0x400000, size = 0x200000;
var mem = Memory.readByteArray(ptr(start), size);
fs.writeFile('/tmp/dump.bin', mem);
```

### 内存权限修改
```javascript
// 改页可执行（脱壳/SMC 常用）
var addr = ptr(0x401000);
Memory.protect(addr, 0x1000, 'rwx');
```

### 加密算法专项追踪（RC4 提取 key）
```javascript
// RC4 完整追踪：提取 key + 加密前后数据
Interceptor.attach(Module.findExportByName(null, "rc4_crypt"), {
  onEnter(args) {
    this.keyPtr = args[0];
    this.dataPtr = args[2];
    this.len = args[3].toInt32();
  },
  onLeave(ret) {
    console.log("key:", Memory.readUtf8String(this.keyPtr));
    console.log("plain:", Memory.readByteArray(this.dataPtr, this.len));
  }
});
```

### AES 密钥提取
```javascript
Interceptor.attach(Module.findExportByName(null, "AES_set_encrypt_key"), {
  onEnter(args) {
    console.log("AES key:", Memory.readByteArray(args[0], 16));
  }
});
```

### Frida Stalker 代码追踪
```javascript
Stalker.follow(Process.id, {
  events: { call: true, ret: true },
  onReceive: (ev) => {
    // 解析事件，记录执行流
    ev.events.forEach(e => console.log(e.type, e.address));
  }
});
```

### 脱壳与 OEP 检测（mprotect 监控）
```javascript
Interceptor.attach(Module.findExportByName(null, "mprotect"), {
  onEnter(args) {
    var prot = args[2].toInt32();
    if (prot & 0x4) {  // PROT_EXEC
      console.log("mprotect EXEC at", args[0]);
      // 此处 dump 内存或设硬件断点
    }
  }
});
```

### Android Java 层 Hook
```javascript
Java.perform(function() {
  var Activity = Java.use("com.example.MainActivity");
  Activity.onCreate.implementation = function(bundle) {
    console.log("onCreate called");
    this.onCreate(bundle);
  };
});
```

### 字符串解密自动提取
```javascript
// hook 解密函数出口，收集所有明文
Interceptor.attach(Module.findExportByName(null, "decrypt_string"), {
  onLeave(ret) {
    var plain = Memory.readUtf8String(ret);
    console.log("decrypted:", plain);
  }
});
```

## 十九、编译器优化模式识别

### GCC 版本与优化级别
```bash
strings ./target | grep -E "(GCC|clang|MSVC): [0-9]"
# 示例：GCC: (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0
```

**各优化级别特征：**

| 级别 | 特征 |
|---|---|
| -O0 | 无优化，保留临时变量、完整栈帧、大量符号 |
| -O1 | 基础优化，删除部分临时变量 |
| -O2 | 最常见发布级：循环优化、函数内联、向量化 |
| -O3 | 更激进：循环展开、向量化、IPO |
| -Os/-Oz | 大小优化：牺牲速度换体积 |

**安全标志特征：**
- `-fstack-protector`：`__stack_chk_fail` 调用
- PIE/PIC：`readelf -h` Type=DYN

### Clang/LLVM 与 GCC 差异
```bash
# Clang 版本识别
strings ./target | grep -i "clang"
# 或 .comment 段
readelf -p .comment ./target
```
Clang 特有：更激进的向量化、`llvm.*` intrinsic、与 GCC 不同的内联决策。

### MSVC 特征
```bash
strings ./target | grep -i "Microsoft"
```
- x86-32 调用约定：`__cdecl`/`__stdcall`（尾部 `_name@N`）
- `/O2` 特征：高度优化、`__security_check_cookie`
- PDB 符号：`.debug$S` 段

### 快速判断表

| 特征 | 判断 |
|---|---|
| `GCC:` 字符串 | GCC 编译 |
| `clang` 字符串 | Clang/LLVM |
| `Microsoft` 字符串 | MSVC |
| 高 SIMD 密度 | -O2/-O3 向量化 |
| 大量内联小函数 | -O2/-O3 内联 |

## 二十、算法汇编特征库（详细）

### RC4
**KSA（密钥调度）特征：** S 盒 256 字节初始化，双指针交换，`for i in 0..255`。
**PRGA 特征：** 双指针 `i/j`，`i=(i+1)&0xff`、`j=(j+S[i])&0xff`，交换 `S[i]/S[j]`，XOR 输出。

### ChaCha20/Salsa20
- 状态矩阵常数：`0x61707865`（"expa"）、`0x3320646e`、`0x79622d32`、`0x6b206574`
- Quarter Round 旋转常量：16/12/8/7
- x86：`rotl` 指令序列

### AES
- 软件实现：4 个 256 字节查表（T0-T3）+ 轮常数
- 硬件加速：`aesenc`/`aesdec` 指令
- ARM：`aes` 指令

### SHA-256
- 轮常数前 8 个：`0x428a2f98`、`0x71374491`、`0xb5c0fbcf`、`0xe9b5dba5`...
- 初始哈希值 H[0..7]
- x86：`sha256rnds2` 指令

### MD5
- 四轮常数（K 值，由 sin 派生）：`0xd76aa478`、`0xe8c7b756`、`0x242070db`、`0xc1bdceee`...
- 典型结构：4 轮 × 16 步

### RSA / 大数运算
- Montgomery 乘法：`mulx`/`adcx` 指令，模约减
- 平方-乘法（Square and Multiply）：条件分支 + 平方/乘

### CRC32
- 查表版本：256 字节表 + `0xEDB88320` 多项式
- 硬件指令：`crc32` 指令

### Base64
- 64 字符编码表
- 编码逻辑：每 3 字节 → 4 字符

### XOR 混淆 / 字符串解密
- 单字节 XOR：固定密钥循环
- 多字节轮转 XOR：密钥递增

### 反调试/混淆模式
- RDTSC 时序：`0F 31` 双调用时间差
- INT3 / IsDebuggerPresent
- SEH/VEH 异常混淆（x86 Windows）

## 二十一、上下文快照 YAML 模板（记忆机制，每 10 轮生成）

每 10 轮对话自动生成一份快照，保存分析进度，下次对话粘贴即可无缝继续。

**优先级说明：**

| 级别 | 含义 | 是否写入快照 | 示例 |
|---|---|---|---|
| P0 | 突破性发现 | **必须写入，永不截断** | 真实密钥材料、确认算法、隐藏功能 |
| P1 | 重要进展 | 写入，优先保留 | 函数签名确认、结构体恢复、反调试绕过 |
| P2 | 有价值的中间结论 | 写入，空间不足时压缩 | 疑似算法（未验证）、字段偏移推测 |
| P3 | 常规分析记录 | 仅摘要，空间不足省略 | 已反汇编函数列表、工具运行记录 |

**完整快照 YAML 模板：**

```yaml
# ════════════════════════════════════════════════
# 上下文快照
# ════════════════════════════════════════════════
snapshot_version: 2
generated_at_turn: 10          # 第几轮生成
resume_from_turn: 11           # 下次从第几轮继续
target_name: "target_binary"

# ── 目标基本信息 ─────────────────────────────────
target:
  file: "./target"
  arch: "x86-64"               # x86-64 | aarch64 | arm | mips
  format: "ELF64"              # ELF64 | PE64 | Mach-O
  compiler: "GCC 11.3 -O2"
  stripped: true
  pie: true
  endian: "little"
  security_flags:
    nx: true
    canary: true
    pie: true
    relro: "full"              # none | partial | full
    fortify: false
  aslr_base_last: "0x555555554000"

# ── 工具环境确认 ──────────────────────────────────
tools_confirmed:
  gdb: "13.2 + pwndbg"
  r2: "5.8.8 + r2ghidra"
  strace: "6.1"
  ltrace: "0.7.3"
  frida: "16.2.1"
  angr: "9.2.90"
  valgrind: "3.21.0"
  bpftrace: "0.18.0"
  ptrace_scope: 0
  aslr_disabled: true

# ── 白皮书加载状态 ────────────────────────────────
whitepaper:
  loaded: true
  documents:
    - "Intel SDM Vol.2 (A-M)"

# ── 混淆/加壳状态（P0/P1 优先）────────────────────
obfuscation:
  status: "partial"            # clean | upx | ollvm | vmprotect | custom | partial
  entropy_global: 6.82
  packer_detected: "none"
  ollvm_functions: []
  string_encryption: true
  string_decrypt_func: "0x401800"
  antidebug_detected:
    - type: "ptrace_self"
      addr: "0x401050"
      status: "patched"        # patched | bypassed | pending
    - type: "rdtsc_timing"
      addr: "0x4018cc"
      status: "pending"
  notes_p1: "程序在 0x401900 处有 mprotect(EXEC)，疑似内联自解码"

# ── P0 突破性发现（最高优先级，永不截断）────────────
breakthroughs_p0:
  - id: "BT-001"
    turn_found: 7
    title: "RC4 密钥在 /etc/app/key.bin 文件中"
    detail: |
      strace 第23行: open("/etc/app/key.bin", O_RDONLY) = 3
      Frida 在 rc4_init 入口 dump arg1: key = "abcdefghijklmnop"
      动态验证：Frida hook rc4_crypt 输出与预期一致。
    confidence: "confirmed"
    tools_used: ["strace", "frida"]

# ── P1 重要进展 ───────────────────────────────────
important_findings_p1:
  - id: "P1-001"
    turn_found: 5
    title: "SessionCtx 结构体完整恢复"
    struct: |
      struct SessionCtx {
        /* 0x00 */ void*    vptr;
        /* 0x08 */ int32_t  state;
        /* 0x0c */ uint32_t flags;
        /* 0x10 */ void*    handler;
        /* 0x18 */ char     key[16];
        /* 0x28 */ uint32_t counter;
      };  // sizeof=0x30
    confidence: "high"
    tools_used: ["r2", "gdb", "frida"]

# ── P2 有价值的中间结论 ───────────────────────────
intermediate_p2:
  - "0x402000 疑似 MD5，发现常数 0xd76aa478，未动态验证"
  - "0x403000 sym.verify_token：疑似 HMAC-MD5"

# ── 算法识别状态 ──────────────────────────────────
algorithms:
  - name: "RC4"
    status: "confirmed"
    confidence: 1.0
    function: "0x401234"
    dynamic_validated: true
  - name: "MD5"
    status: "suspected"
    confidence: 0.75
    function: "0x402000"
    dynamic_validated: false
    next_action: "bpftrace uprobe 验证 or GDB dump state"

# ── 函数分析状态 ──────────────────────────────────
functions:
  completed:
    - addr: "0x401100"
      name: "sym.init_session"
      summary: "SessionCtx 构造函数，malloc(0x30)"
  in_progress:
    - addr: "0x402000"
      name: "sym.hash_password"
      progress: "30%"
  pending:
    - addr: "0x403000"
      name: "sym.verify_token"
      priority: "high"

# ── 动态分析汇总 ──────────────────────────────────
dynamic_summary:
  strace:
    total_syscalls: 312
    key_findings:
      - "open('/etc/app/key.bin') → 读取16字节密钥 [P0]"
      - "mprotect(PROT_EXEC) 在运行约500ms后触发"
  ltrace:
    key_findings:
      - "strcmp 硬编码密码 [P0]"
  frida:
    hooks_active: ["sym.encrypt_data", "sym.init_session"]
    dumps_collected: 2

# ── 待解决的不确定点 ──────────────────────────────
unresolved:
  - id: "UNR-001"
    priority: "P1"
    desc: "0x401298 vpxor xmm0,xmm0,xmm1 — SIMD 宽度待 SDM 确认"
    action: "web_fetch Intel SDM Vol.2 VPXOR 章节"
  - id: "UNR-002"
    priority: "P1"
    desc: "mprotect(EXEC)@0x401900 — OEP 自解码还是 JIT？"
    action: "bpftrace 监控 or GDB hb 在 mprotect 返回后首条指令"

# ── 下次对话行动计划 ──────────────────────────────
next_session_plan:
  immediate:
    - "GDB 验证 0x402000 MD5 常数（动态 dump state）"
    - "bpftrace 追踪 mprotect 后执行流，确认 OEP"
  secondary:
    - "分析 0x403000 verify_token"
  optional:
    - "分析 0x404500 network_send 数据格式"

# ── 快照元数据 ────────────────────────────────────
meta:
  total_turns: 10
  p0_count: 2
  p1_count: 2
  p2_count: 3
  completion_estimate: "35%"
  most_important_next: "BT-002 验证完成后继续 verify_token"
```

**快照生成检查清单：**
- [ ] `breakthroughs_p0` — 所有 P0 发现已写入，detail 完整
- [ ] `important_findings_p1` — P1 发现摘要已写入
- [ ] `algorithms` 每项均有 `status` 和 `dynamic_validated`
- [ ] `functions.pending` 按优先级排序
- [ ] `unresolved` 每项均有 `action`
- [ ] `next_session_plan.immediate` 只含 P0/P1 相关任务
- [ ] 快照总行数 < 120 行（超过时截断 P3 内容）

**快照加载后恢复话术：**
```
📂 已加载上下文快照（第 10 轮 → 第 11 轮继续）
目标   : ./target (x86-64 ELF, stripped, PIE)
进度   : ~35% | 5 个函数已完成 | 2 个 P0 突破性发现已确认
工具   : GDB+pwndbg / r2 / strace / Frida / angr（均已就绪）
⭐ P0 突破性发现（已确认）：
  1. RC4 密钥来源：/etc/app/key.bin（16字节）
  2. 硬编码密码：'S3cr3t_K3y_2024'
⚠️  待解决 P1 问题：
  1. mprotect(EXEC) OEP 未追踪
  2. SIMD 指令 VPXOR 宽度待白皮书确认
📋 立即开始：
  → 动态验证 0x402000 疑似 MD5
  → 追踪 mprotect 后的首条指令
当前轮次：第 11 轮（距下次快照还有 9 轮）
```

## 二十二、vtable 检测与类层级重建（详细）

### vtable 汇编特征

**x86-64 构造函数写入 vtable 指针：**
```asm
; 模式 1：RIP 相对寻址（PIE/PIC）
lea  rax, [rip + 0x2b3c]       ; rax = &vtable_for_MyClass
mov  [rdi], rax                 ; this->vptr = &vtable_for_MyClass

; 模式 2：直接地址（非 PIE）
mov  rax, 0x405678              ; vtable 绝对地址
mov  [rdi], rax
```

**虚函数调用：**
```asm
mov  rax, [rdi]                 ; rax = this->vptr
call [rax + 0x0]                ; 调用 vfunc[0]
call [rax + 0x8]                ; 调用 vfunc[1]
call [rax + N*8]                ; 调用 vfunc[N]
```

**ARM64 虚函数调用：**
```asm
ldr  x8, [x0]                   ; x8 = this->vptr
ldr  x9, [x8, #0x10]            ; x9 = vfunc[2]
blr  x9
```

### r2 自动 vtable 扫描

```bash
# 自动分析并列出所有 vtable
r2 -A -q -c 'av; avj' ./target

# 查看某个 vtable 的所有条目
r2 -A -q -c 'av @ 0x405678' ./target
```

```python
import r2pipe, json
r = r2pipe.open('./target', flags=['-A', '-2'])
vtables = json.loads(r.cmd('avj') or '[]')
print(f"Found {len(vtables)} vtables:")
for vt in vtables:
    print(f"\n  vtable @ {hex(vt['offset'])} ({vt.get('name','unnamed')})")
    for i, fn in enumerate(vt.get('methods', [])):
        print(f"    [{i}] {hex(fn['offset'])}  {fn.get('name','?')}")
r.quit()
```

### 继承关系推断脚本

```python
import r2pipe, json
r = r2pipe.open('./target', flags=['-A', '-2'])
vtables = json.loads(r.cmd('avj') or '[]')

# 对每对 vtable 检查前缀关系（疑似继承）
for vt_a in vtables:
    for vt_b in vtables:
        if vt_a is vt_b: continue
        methods_a = [m['offset'] for m in vt_a.get('methods', [])]
        methods_b = [m['offset'] for m in vt_b.get('methods', [])]
        n = min(len(methods_a), len(methods_b))
        if n > 0 and methods_a[:n] == methods_b[:n]:
            print(f"疑似继承: {hex(vt_b['offset'])} 继承自 {hex(vt_a['offset'])} (共享 {n} 个虚函数)")
r.quit()
```

**推断规则：**
1. 子类 vtable 前 N 个条目与父类 vtable 相同（N = 父类虚函数数量）
2. 子类 vtable 在父类基础上追加新虚函数
3. 多继承：子类对象包含多个 vptr，排列按继承顺序

**识别多继承：** 构造函数中对 `this` 的不同偏移分别写入 vptr：
```asm
mov [rdi + 0x00], vtable_A    ; 第一个基类 vptr
mov [rdi + 0x20], vtable_B    ; 第二个基类 vptr（偏移 = 第一个基类大小）
```

## 二十三、结构体布局恢复方法论

### 识别结构体实例
- 找 `malloc(M)` / `operator new(M)` 调用，M 即结构体大小
- 找对同一基址的多个 `[reg + offset]` 访问模式
- 相邻偏移间隙 → padding

### 字段偏移表构建
```bash
# 反汇编目标函数，收集所有 [reg + offset] 访问模式
r2 -q -c 'pdf @ <func>' ./target
```

### 字段类型推断规则
| 访问大小 | 类型 |
|---|---|
| b (1 字节) | uint8 / char |
| w (2 字节) | uint16 |
| d (4 字节) | uint32 / float |
| q (8 字节) | uint64 / 指针 |

### Padding 对齐计算
- 结构体按最大成员对齐
- 成员间按自身对齐填充
- 末尾填充到整体对齐的倍数

### r2 pf（print format）命令
```bash
# 基本格式字符：b=uint8 w=uint16 d=uint32 q=uint64 p=指针 s=字符串 f=float F=double
r2 -q -c 'pf qp @ 0x602000' target       # 打印结构体
r2 -q -c 'pfq qpq @ 0x602000' target      # 命名字段
```

### r2 td 类型定义（高级）
```bash
r2 -q -c 'td obj_X=Q+4i+Q' target         # 定义 C 风格结构体
r2 -q -c 'tdL' target                      # 查看已定义类型
r2 -q -c 'afv obj_X @ 0x602000' target     # 在反汇编中应用
```

### GDB 自定义 pretty-printer
```python
# gdb_printers.py — 加载：source gdb_printers.py
import gdb
class SessionCtxPrinter:
    def __init__(self, val): self.val = val
    def to_string(self):
        return f"SessionCtx(vptr={self.val['vptr']})"
gdb.pretty_printers.append(SessionCtxPrinter)
```

### 常见运行时结构体

**std::string（libstdc++ ABI）：**
```c
struct std::string {
    char* _M_dataplus;        // 0x00 数据指针
    size_t _M_string_length;  // 0x08 长度
    // 小字符串优化：局部缓冲区
};
```

**glibc malloc chunk：**
```c
struct malloc_chunk {
    size_t prev_size;   // 0x00
    size_t size;        // 0x08（含标志位）
    // fd/bk（非 fastbin）
};
```

**输出格式：重建 C 头文件**
```c
struct obj_X {
    /* 0x00 */ void*    vptr;
    /* 0x08 */ int32_t  state;
    /* 0x0c */ uint32_t flags;
    /* 0x10 */ void*    handler;
};  // sizeof = 0x18
```
