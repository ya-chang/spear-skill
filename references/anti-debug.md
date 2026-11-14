# 反调试绕过（anti-debug）

目标：让调试器能正常附着、单步、断点。**先识别检测类型，再针对性绕过。**

## 一、常见反调试检测与绕过

### 1. ptrace 自附加（Linux）
程序调用 `ptrace(PTRACE_TRACEME)`，导致后续调试器附着被拒。

```gdb
catch syscall ptrace
commands
  set $rax = 0        # 伪造 ptrace 成功返回 0
  continue
end
```

### 2. PEB.BeingDebugged（Windows）
检查 PEB 标志位。

```gdb
# 直接 patch 内存中的 PEB.BeingDebugged
(gdb) set *(char*)(peb_base+0x2) = 0
# 或断在检测点，直接改返回值
```

### 3. /proc/self/status 的 TracerPid（Linux）
读取 `/proc/self/status` 检查 TracerPid != 0。

```gdb
# 断在读取该文件的函数，伪造读取失败
b fgets
commands
  silent
  set $rax = 0
  return 0
end
handle SIGTRAP nostop noprint pass
```

```bash
# Frida 方案
Interceptor.replace(getModuleExport("libc.so", "fgets"), new NativeFunction(...));
// 或直接 hook open("/proc/self/status") 返回 -1
```

### 4. 时间检测（RDTSC / gettimeofday）
两条时间戳差值过大 → 判定被单步。

```gdb
# 断在 RDTSC，直接推进时间戳（或 patch 掉时间差比较）
catch syscall clock_gettime
```

```javascript
// Frida：hook RDTSC/时间函数，返回合理值
Interceptor.replace(Module.findExportByName(null, "clock_gettime"), ...);
```

### 5. TLS 回调（Windows）
回调在调试器附着前执行检测。**必须在进程启动早期注入**：

```javascript
// Frida：用 early injection 绕 TLS 回调
Interceptor.attach(Module.findExportByName(null, "RtlRegisterThread"), {...});
// 或直接 patch TLS 回调地址为 nop
```

### 6. VEH / 异常处理检测（Windows）
通过异常处理链判断调试器。patch 异常分发或直接改检测返回值。

### 7. 硬件断点/调试寄存器检测
检测 DR0-DR7。Frida 用 `Thread.setBacktrace` 前先清空，或用反反调试脚本。

## 二、通用反调试 patch 思路

**原则：不改逻辑，只改检测结果。** 找到检测函数的返回值分支，把"检测到调试器"的路径改成"未检测到"。

```gdb
# 找检测函数，看它的比较与分支
(gdb) disas check_debugger
# 在返回 1（检测到）的指令处，patch 为返回 0
(gdb) set *(unsigned char*)0xADDR = 0xC3   # ret 0
```

**Frida 通用反调试脚本骨架：**

```javascript
// anti_debug.js
const exports = Module.enumerateExports("target.exe");
// 1. patch BeingDebugged
const peb = Process.findModuleByName("target.exe");
// 2. hook 常见检测函数，强制返回"未调试"
const checks = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"];
checks.forEach(name => {
  const f = Module.findExportByName("target.exe", name);
  if (f) Interceptor.replace(f, new NativeFunction(f, "int", [], function(){ return 0; }));
});
```

## 三、反反调试顺序

1. 先绕过 ptrace/BeingDebugged 这类**入口级**检测（否则进不去）
2. 再绕过**运行中**检测（时间、TLS、VEH）
3. 最后处理**内存完整性校验**（检测代码是否被 patch）

## 四、验证

- GDB 能正常附着、设断点、单步
- 程序不退出、不弹"调试检测"提示
- Frida 能正常 hook 目标函数

## 附：PEB 偏移表与 NtQueryInformationProcess

### PEB 标志偏移（x64）
| 字段 | 偏移 | 调试时值 | 正常值 |
|---|---|---|---|
| `BeingDebugged` | `PEB+0x02` | 1 | 0 |
| `NtGlobalFlag` | `PEB+0xBC` | `0x70` (FLG_HEAP_*) | 0 |
| `ProcessHeap.Flags` | Heap+0x40 | `0x40000062` | `0x00000002` |
| `ProcessHeap.ForceFlags` | Heap+0x44 | `0x40000060` | 0 |

```asm
mov rax, gs:[0x60]    ; PEB
movzx eax, byte [rax+0x02]  ; BeingDebugged
test eax, eax
jnz debugger_detected
```
绕过：将四个字段全部清零，ScyllaHide 可自动完成。

### NtQueryInformationProcess 检测
| InfoClass | 值 | 调试时返回 |
|---|---|---|
| `ProcessDebugPort` | 0x07 | 非零端口 |
| `ProcessDebugObjectHandle` | 0x1E | 有效句柄 |
| `ProcessDebugFlags` | 0x1F | 0（反转） |

绕过：Hook `ntdll!NtQueryInformationProcess`，按 info class 返回干净值。

### 硬件断点检测
```c
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
// 检查 DR0-DR7 是否非零 → 检测到硬件断点
```
绕过：清空 DR0-DR7，或用无痕 Hook。

## 五、补充检测类型与绕过（Linux/Windows 高级）

### 8. 信号检测（SIGTRAP，Linux）
程序 `signal(SIGTRAP, handler)` 后 `raise(SIGTRAP)`：调试器会吞掉该信号导致 handler 不触发，从而判定被调试。

```c
volatile int caught = 0;
void handler(int sig) { caught = 1; }
signal(SIGTRAP, handler);
raise(SIGTRAP);
if (!caught) exit(1);   // 被调试器吞掉 → 退出
```

绕过：GDB 转发信号，让 handler 正常触发。
```gdb
handle SIGTRAP nostop noprint pass
```

### 9. /proc/self/maps 与 LD_PRELOAD 检测（Linux）
扫描 `/proc/self/maps`，命中 `frida`、`LD_PRELOAD`、注入库即退出。

```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(buf, sizeof(buf), f))
    if (strstr(buf, "frida") || strstr(buf, "LD_PRELOAD")) exit(1);
```

绕过：
- Frida 重命名 agent 库文件名，避开字符串匹配。
- `LD_PRELOAD` 注入的 shim 库改名，避免 maps 中出现可识别名。
- Frida hook `fopen("/proc/self/maps")` 返回过滤后的内容。

### 10. 环境变量检测（Linux）
检查 `LD_PRELOAD`、`LINES`、`COLUMNS`（GDB 终端会设置）、调试器相关环境变量。

绕过：启动前 `unset` 可疑变量，或 hook `getenv()` 对指定键返回 NULL。

### 11. INT 2D / INT 3 / UD2 异常技巧（Windows）
`INT 2D` 是内核调试服务中断。无调试器时抛 `STATUS_BREAKPOINT`；有调试器时行为不同（跳过下一字节），造成执行路径分叉。

```asm
xor eax, eax
int 2dh
nop          ; 调试器可能跳过此字节
; ... 分叉路径 ...
```

绕过：在 VEH 中处理该异常，或直接 patch 掉中断指令；`UD2`（`0x0B0F`）触发非法指令，用异常处理链接管。

### 12. NtSetInformationThread(ThreadHideFromDebugger)（Windows）
调用后线程对调试器不可见，断点和单步静默失效。

```c
NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
```

绕过：hook `NtSetInformationThread`，当 `ThreadInfoClass == 0x11`（ThreadHideFromDebugger）时 NOP。

### 13. 自调试（fork + ptrace，Linux）
进程 fork 子进程对父进程 `ptrace(ATTACH)`，外部调试器已附着时子进程 ptrace 失败 → 杀父。

```c
pid_t child = fork();
if (child == 0) {
    if (ptrace(PTRACE_ATTACH, getppid(), 0, 0) == -1)
        kill(getppid(), SIGKILL);
    else ptrace(PTRACE_DETACH, getppid(), 0, 0);
    _exit(0);
}
wait(NULL);
```

绕过：patch `fork()` 返回值（强制走父分支），或先 kill 掉 watchdog 子进程，或用 GDB `set follow-fork-mode child` + `detach`。

### 14. 多进程互检（Linux/Windows）
父子进程互相检查对方调试状态，形成互watch。绕过：GDB `follow-fork-mode` 同时附着两个进程，或两个调试器实例分别挂载。

### 15. 多检查点时序检测
时序检查分散在多个函数，累计漂移超阈值才判定，单点 patch 无效。

绕过：Frida `Interceptor.replace` 所有时序源（`rdtsc`、`clock_gettime`、`QueryPerformanceCounter`、`GetTickCount`），统一返回受控值。

### 16. Nanomite / INT3 补丁
原始条件跳转被替换为 `INT3`(0xCC)，由父调试进程处理每个 INT3、评估条件、设置子进程 EIP。

绕过：追踪所有 INT3 处理器重建原始跳转表，再对二进制打补丁恢复条件跳转。

## 六、反调试工具对照

| 工具 | 平台 | 能力 |
|---|---|---|
| ScyllaHide | Windows（x64dbg/IDA/OllyDbg） | 自动 patch PEB、hook NtQuery*、隐藏线程、修时序 |
| TitanHide | Windows（内核驱动） | 内核级隐藏所有用户态检测 |
| Frida | 跨平台 | 脚本 hook 任意函数、时序伪造 |
| LD_PRELOAD shim | Linux | 加载期替换 ptrace/getenv/fopen |
| GDB 脚本 | Linux | `catch syscall`、条件断点、寄存器修正 |
| Qiling | 跨平台 | 全系统仿真，绕过所有硬件级检查 |

## 七、系统化绕过方法论

```
Step 1 静态识别：搜 ptrace / IsDebuggerPresent / NtQuery / rdtsc /
        GetTickCount / SIGTRAP / INT 2D / TLS directory
Step 2 分类：API 型→hook/patch；标志型→patch PEB/proc 字段；
        时序型→伪造时间源；异常型→正确转发/处理；多进程→双附着
Step 3 应用（顺序重要）：
  1. 加载 ScyllaHide / 设 LD_PRELOAD（覆盖约 80% 检测）
  2. 处理 TLS 回调（在 main 前打断）
  3. patch 剩余自定义检测（Frida 或二进制 patch）
  4. 验证：带断点运行，确认无提前退出
Step 4 完整性校验：在 ExitProcess/exit/_exit 设断，
        若意外命中说明漏了某个检测 → 从退出调用反查
```

## 八、快速参考（One-liner）

```bash
# Linux LD_PRELOAD 反 ptrace
echo 'long ptrace(int r, ...) { return 0; }' > /tmp/ap.c
gcc -shared -o /tmp/ap.so /tmp/ap.c
LD_PRELOAD=/tmp/ap.so ./target
```

```javascript
// Frida：hook IsDebuggerPresent / ptrace / 时序
Interceptor.replace(
  Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'),
  new NativeCallback(() => 0, 'int', [])
);
Interceptor.replace(
  Module.getExportByName(null, 'ptrace'),
  new NativeCallback(() => 0, 'long', ['int','int','pointer','pointer'])
);
```

```text
# x64dbg + ScyllaHide 快速设置
Plugins → ScyllaHide → Options
勾选：PEB BeingDebugged / NtGlobalFlag / HeapFlags
勾选：NtQueryInformationProcess（全部 class）
勾选：NtSetInformationThread（HideFromDebugger）
勾选：GetTickCount / QueryPerformanceCounter
Apply → 重启调试会话
```
