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

- [ ] GDB 能正常附着、设断点、单步（`gdb -p <pid>` 后 `b *addr`、`si` 无异常退出）
- [ ] 程序不退出、不弹"调试检测"提示（运行目标功能，无闪退/弹窗/自杀）
- [ ] Frida 能正常 hook 目标函数（`frida -p <pid> -l hook.js` 后 hook 回调触发）
- [ ] 绕过后反调试检测函数返回预期值（如 TracerPid hook 后返回 0）
- [ ] 内存完整性校验不报篡改（CRC/Hash 校验通过）

## 四·五、代码骨架：Frida 绕过 TracerPid 反调试

> 可运行的 Frida 骨架，hook `/proc/self/status` 读取使 TracerPid 返回 0，绕过基于 TracerPid 的反调试。

```javascript
// anti_debug_tracerpid.js — Frida 绕过 TracerPid 反调试骨架
// 原理：目标读 /proc/self/status 的 TracerPid 字段判断是否被调试
// Hook open/read 拦截对 status 文件的访问，返回伪造内容

Java.perform(function () {
    // Hook libc open，拦截 "/proc/self/status"
    var libc = Module.findBaseAddress("libc.so");
    var open = Module.findExportByName(libc, "open");
    if (open) {
        Interceptor.replace(open, new NativeFunction(open, 'int', ['pointer', 'int', 'pointer']) {
            // 简化骨架：实际需判断路径参数是否为 /proc/self/status
            // 命中则返回伪造 fd 或在 read 阶段替换内容
            return this.apply(null, arguments);
        });
    }

    // 更直接：Hook read，当读取 status fd 时替换 TracerPid
    var read = Module.findExportByName(libc, "read");
    if (read) {
        Interceptor.attach(read, {
            onEnter: function (args) {
                // args[0]=fd, args[1]=buf, args[2]=count
                // 判断 fd 是否指向 /proc/self/status（通过 /proc/self/fd 映射）
                // 命中则在 onLeave 中替换 TracerPid 字段为 0
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function (retval) {
                // 读取缓冲区内容，搜索 "TracerPid:" 行，将数值改为 0
                var content = Memory.readUtf8String(this.buf, this.count);
                if (content && content.indexOf("TracerPid:") !== -1) {
                    var patched = content.replace(/TracerPid:\s*\d+/, "TracerPid:0");
                    Memory.writeUtf8String(this.buf, patched);
                    console.log("[anti-debug] TracerPid patched to 0");
                }
            }
        });
    }
});
```

运行：`frida -U -f com.target.app -l anti_debug_tracerpid.js`。验证：目标反调试检测函数不再触发，程序正常运行。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §二反调试绕过方法论使用

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

## 九、VMProtect handler 层反调试实战

适用：VMProtect（Ultra：Mutation + Virtualization）加壳的 32 位 Windows 样本，WOW64 环境。分析层级：handler 层。

**VM 两层结构**：① 伪指令层——一条 x86 指令译成一组伪指令（`add eax,03` → `cmPush imm`+`cmPush reg`+`cmAdd`+`cmPop`×2，命名取自 `core/intel.h` 的 `IntelCommandType` 枚举：cmPush/cmPop/cmMov/cmAdd/cmXor/cmTest/cmNor/cmNand/cmCall/cmJmp…）；② handler 层——每条伪指令编译成一组原生汇编（handler）。逆向路径：原生汇编 → 伪指令 → 伪指令组 → 原生指令，可在 handler 层或伪指令层突破。

**5 个角色寄存器（分析 handler 先定寄存器）**：

| 寄存器 | 32 位下 | 作用 |
|---|---|---|
| 字节码寄存器 pcode_registr | 不固定，每 handler 确认 | 指向**加密**字节码（存下一 handler 相对偏移 + 常数，解密密钥由上一 handler 传下，**不能单独 patch 字节码单元**） |
| 操作数栈寄存器 stack_registr | 不固定 | 指向操作数栈顶，cmEnter 用 `mov xxx,esp` 初始化，压栈可向高/低扩展 |
| 派发寄存器 jmp_registr | 不固定 | handler 用 `jmp xxxreg` 或 `push xxxreg+ret` 派发；**找到这两种结构即定 jmp_registr 也定 handler 结尾** |
| 密钥寄存器 crypt_registr | **固定 ebx** | 解密字节码 |
| VM 寄存器基址 regfile_base_reg | **固定 esp** | VM 寄存器 = esp+0xXX 物理槽位（cmEnter 用 `lea esp,[esp-0C0h]` 预留） |

**cmEnter/cmRet**：cmEnter 三件事——初始化角色寄存器、压栈保存 8 原生寄存器现场（ebx/edi/eax/edx/ecx/eflags/ebp/esi，次序不固定）、进入 handler 序列；cmRet 逆操作。每个 cmEnter 内部有 `lea XXXreg, loc_X` 载入"起始地址"（非 handler 开始地址），下一 handler 地址 = 起始地址 + 解密偏移。

**条件跳转定位定式**：handler 流找**相邻两个 cmAdd**（位屏蔽选择公式）→ 往前追溯**右移 6 位**归约指令（标志位搬 bit0）→ 追溯被移位操作数来源即比较源。cmNor 两次取反模拟 `test al,al` 的 eflags。

**五类检测与 patch 落点**：

**① PEB.BeingDebugged**：`cmPush [fs:[0x30]]` 读 PEB → cmAdd 算 +2 → `cmPush [mem]` 读标志。**绕过**：PEB 基址+2 下**硬件读写断点**，断下后 cx 清 0。

**② WOW64 远门调 NtQueryInformationProcess**：32 位进程经远门（`jmp far`）调 API。要点：

- 入口校验：调前先 cmEnter/cmRet 校验远门入口前 2 字节（`0E 68`，即 `push cs; push offset`），**INT3 断点把首字节改成 0xCC 会致校验失败**——避开或对齐后再下断。
- 入参走操作数栈：`0x03008019`(ssn，0x19=NtQueryInformationProcess)、`0xFFFFFFFF`(ProcessHandle)、`7`(ProcessDebugPort) / `0x1E`(DebugObjectHandle)、ProcessInformation 指针、长度 4、ReturnLength。
- 远门出口 `mov cx,ss; mov ss,cx`（字节 `66 8C D1 66 8E D1`）利用 Intel 特性**吃掉单步异常 #DB**反硬件断点——**搜索 `66 8E D1` 找所有远门出口**，硬件断点延后到下一条 `push`。
- 软件断点校验：读下一 handler 首 2 字节，与断点字节（0xCC/0x03CD/0x0B0F，即常数 0x34/0xFC33/0xF4F1 取负）做减法提 ZF，有断点算非法地址跑飞。
- **定位远门**：二进制搜索 `0e 68 ?? ?? ?? ?? ea`（本样本 21 个），第二个 push 的值即出口；出口 `push` 处下断，**ESI=返回值地址，ESI-8=ProcessInformation**。
- **Patch**：ProcessDebugPort(7)——将 ESI-8 处 `FF FF FF FF` 改 `00 00 00 00`（返回值不用改，查询必成功）；DebugObjectHandle(0x1E)——**只改返回值**为 `0xC0000353`，**不动 ProcessInformation**（改 0 会被判为函数被跳过）。

**③ NtSetInformationThread（Class=0x11 隐藏 debugger）**：绕过——入口远跳指令（`push cs; push offset; jmp far`）设断 → ESP+8 调平 → EIP 设到出口跳转指令，跳过远门。

**④ BADC0DE（CloseHandle 非法句柄）**：`CloseHandle(0xDEADC0DE)`，调试环境下抛 0xC0000008，异常处理执行即判定。绕过：`cmCall` 内 `call eax` 处设断 → ESP+4 调平 → EIP 跳过 call → eax 置 0。

**⑤ TFCheck（单步异常）**：handler 用 `cmNor(eflags,0x100)` 再 cmNand 自反 = **eflags|0x100（设 TF）**，cmRet 执行 `popf`（eflags=0x346）→ 下条 `rdtsc` 触发单步。两种判定：调试器吃掉异常→执行到 `nop`→判定；异常派发回样本→SEH filter 检查 `ContextRecord.Dr0-Dr3`（**在 VM 内执行**，数百条 handler）。**绕过**：清硬件断点 + 单步异常交还样本；或在 except_handler3 的 filter 返回处（`0x0042320B`）设断，或入口断下后把 pContextRecord 的 Dr0-Dr3 清 0。

**验证**：硬件断点断 PEB+2、远门入口校验、TFCheck 双分支（吃异常/派发异常）分别实测；patch 后程序继续运行不再报 debugger。仅针对开源样本/授权目标。

## 十、快速参考（VMProtect）

- 角色寄存器：32 位下 crypt=ebx、regfile_base=esp 固定，其余每 handler 确认
- 远门入口字节 `0e 68`；远门出口字节 `66 8E D1`
- 条件跳转：两 cmAdd + Shr 6 + 追溯来源
- 断点字节组：0xCC / 0x03CD / 0x0B0F（对应常数 0x34 / 0xFC33 / 0xF4F1）
- TF 设置等价式：`NAND(NOR(eflags,0x100), NOR(eflags,0x100)) = eflags|0x100`

---

## 十、VMP handler 层反调试：按层整体拆除（实战）

> 前置：VMP 的检查分布在 handler 里，**每个 handler 只查一项**。逐点 nop 不现实，要找到"所有检查的汇聚点"。反调试是 O(1) 单点防御（一个开关），虚拟化是 O(n)——**先拆反调试，再谈虚拟化**，顺序反了会在"程序行为诡异"上浪费几天。

### 1. 常见检查项与识别

| 检查 | 实现 | 特征字节/行为 |
|---|---|---|
| **PEB.BeingDebugged** | `mov eax, fs:[0x30]` → `movzx eax, byte [eax+2]` | `64 A1 30 00 00 00` / `64 8B 05 30...`，随后读 `+2` |
| **NtQueryInformationProcess 7**（DebugPort） | `push 7` + `call NtQueryInformationProcess` | 立即数 `7` 出现在 syscall 前 |
| **NtQueryInformationProcess 0x1E**（DebugObjectHandle） | `push 0x1E` | 同上（Win8+ 语义） |
| **NtSetInformationThread 0x11**（HideFromDebugger） | `push 0x11` | 会让调试器"断不下来" |
| **BADC0DE** | 读 `fs:[0x30]+0xBC`（或 `TEB+0xFCA`）比较 `0x0BAD`/`0xC0DE` | 特征常量 |
| **TFCheck / SingleStep** | 设 `EFLAGS.TF` 后检查是否触发异常 | 会导致单步即崩 |
| **WOW64 远门** | 32 位进程在 64 位系统上远跳转进入 64 位代码，异常码 `0x4000001F` | 只出现在 WOW64 |

注意：`NtQueryInformationProcess` 的 class 号在不同 Windows 版本语义不同。判断时以"类号 + 后续比较逻辑"为准，不要只看类号。

### 2. 拆除策略（按优先级）

1. **找汇聚点**：所有检查最终都产生一个"是否调试"的 bool，走同一个分支。找到那个 bool 的存放位置（栈变量或寄存器），把它改成常量。
2. **改返回值**：hook `NtQueryInformationProcess` 返回 `STATUS_PORT_NOT_SET`，PEB 手动清 `BeingDebugged`。
3. **跳到出口**：在 handler 层面找到"检测失败 → 走异常路径"的跳转，直接跳到 handler 的正常出口（栈平衡由 handler 自己保证，比手工 nop 安全）。
4. **让检查失效而不是让它通过**：某些检查失败会导致"静默改行为"（不崩，但功能不对），这时必须让它**通过**而不是"跳过"。

> 关键判断：**这是"检测"，还是"检测 + 后果"？** 只 nop 检测、不清后果，程序会带着错误状态继续跑——这是最常见的"改了没崩但不对"。

### 3. 滚动解密（BL 反调试）

VMP 会用 `BL`（ARM）或 `call`（x86）做滚动密钥解密：每次调用前改一段立即数，执行后还原。特征：`bl` 目标在同一小段区域内反复出现，且该区域字节在调试器里"单步就变"。

应对：**不要单步**，用硬件断点或"跳到目标后不返回"的方式绕过；或直接把该区域的最终状态 dump 下来。

### 验证

- [ ] 每个反调试检查项都按"类号 + 比较逻辑"确认，未只凭类号下结论
- [ ] 所有检查汇聚到统一 bool，按"改 bool / hook 返回 / 跳 handler 出口"拆除，未逐点 nop
- [ ] 对"检测+后果"型检查，确认让检查**通过**后功能正常，而非仅跳过检测
- [ ] 滚动解密区未单步（用硬件断点/dump 终态），拆完后程序行为与原版对照无"改了没崩但不对"现象

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）
