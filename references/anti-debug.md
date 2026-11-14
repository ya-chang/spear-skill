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
