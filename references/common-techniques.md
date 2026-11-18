# Spear 通用技术库（Common Techniques）

> 更新：2026-11-17
> 用途：跨多个 playbook 共享的通用技术原语，统一在此展开。各 playbook 遇到相关技术时只写引用行（`→ 详见 common-techniques.md §X`），不重复展开，避免内容重复与措辞不一致。
> 主责分配见 `INDEX.md`「通用技术主责分配」表。

---

## §1 Windows 全架构 Hook 技术

> 更新：2026-11-17 · 来源：看雪帖 291370（编程技术）、291859（NPT Hook）、292876（Win11 异常）、287185（iOS Hook）

按隐蔽性从低到高排列，各 playbook 按需引用。

### 1.1 用户态 Hook（Ring 3）

- **IAT Hook**：改 PE 导入地址表函数指针，让调用跳自定义函数。检测★（遍历 IAT 对比地址或 CRC 即暴露）。局限：只能 Hook 经 IAT 调用的函数，GetProcAddress 动态获取不经过 IAT。实现：遍历 IAT 找到目标 DLL 的目标函数，VirtualProtect 改页为可写，替换指针，恢复页保护。
- **Inline Hook**：改函数开头机器码，写入 `jmp rel32`（5 字节）跳到自定义函数，执行后经 trampoline（跳板）执行被覆盖原始字节再跳回。比 IAT Hook 隐蔽（不改表指针，只改代码字节），但 CRC/Hash 校验代码段可发现。ARM64 下 `b` 跳 ±128MB，超范围用 `adrp+br`。
- **VEH/Page Guard Hook**：改页属性为 PAGE_GUARD 触发异常，异常处理器中重定向执行流。异常链可遍历检测，性能开销大。
- **硬件断点 Hook**：用 CPU DR0-DR3 调试寄存器设执行断点，不修改内存。寄存器仅 4 个，GetThreadContext 可检测。

### 1.2 内核态 Hook（Ring 0）

- **SSDT Hook**：改系统服务描述符表指针，SSDT 类。
- **IDT Hook**：改中断描述符表。
- **对象回调 Hook**：利用 Windows 回调机制（进程创建、注册表、对象）做监控，数量有限。
- **HAL Hook**：劫持 HAL 内部回调地址全局变量，间接调用接管。

### 1.3 虚拟化 Hook（Ring -1）

- 详见 §2 NPT/EPT/SLAT 虚拟化 Hook。

### 1.4 移动端 Hook

- **iOS 四层能力栈**：①OC 层 Method Swizzling（SEL→IMP 交换）；②C 层 fishhook 重绑 Mach-O GOT；③地址层 Inline Hook（Dobby/litehook）；④硬件级 hwbphook（ARM 硬件断点）。iOS 15 分水岭：dyld4 用 `LC_DYLD_CHAINED_FIXUPS` 替换 `LC_DYLD_INFO`。PAC 绕过：ARM64e 下 Inline Hook 需处理 PAC 签名与 BTI。
- **Android**：Frida Interceptor（Java/Native hook）、Stalker（指令级追踪）、inline hook。

### 验证
各 Hook 技术在目标函数上验证拦截生效，检测手段（CRC/扫描/调试寄存器读取）确认隐蔽性。

---

## §2 NPT/EPT/SLAT 虚拟化 Hook

> 更新：2026-11-17 · 来源：看雪帖 291859（NPT Hook）、292825（VT 调试器）、292588（VT-D 对抗）

### 2.1 原理

Intel VT-x 的 EPT（Extended Page Tables）与 AMD-V 的 NPT（Nested Page Tables）是硬件辅助虚拟化的二级地址翻译（SLAT）特性。Hypervisor 通过 EPT/NPT 控制 Guest 物理地址到 Host 物理地址的映射，**在 CPU 硬件层面控制每个物理页的读/写/执行权限，Guest 完全看不见**。

核心优势：代码页零修改（任何读取见原始字节）、PatchGuard 无感知、NPT 页表 Hypervisor 持有 Guest 不可读、Ring -1 特权级、不依赖未文档化接口。

### 2.2 Hook 四代演进

1. **表项替换**（改 SSDT/IDT 指针，易检测）
2. **Inline Hook**（改代码字节，CRC 可发现）
3. **绕过修改**（硬件断点有限/VEH 可遍历/回调受限）
4. **硬件虚拟化 Hook**（SLAT，Hypervisor 控制物理页权限，Guest 不可见）

### 2.3 EPT Hook 三种实现

- **无痕 Hook**：整页读写无效只留可执行，P2 改绝对跳转。读写触发 EPT Violation 切换权限。缺点：自读自跳无限 MTF 卡死。
- **仿内存执行断点**：全程可读写不可执行，MTF Handler 恢复。4KB 页高频访问巨卡。
- **MTF 置位全程可执行**（最适合）：读写触发 Violation 设 MTF，MTF VM Exit 判断后恢复。适合 Hook 内核函数，高频 CRC 校验函数不太适合。

核心：**读与执行分离**——读出正常、执行另一套代码，绕内存检测/PatchGuard/CRC。

### 2.4 NPT Hook 实现步骤

1. 把系统塞进虚拟机（SVM/AMD-V）
2. 构建完全掌控的 NPT 页表
3. 利用 NX 位制造"取指陷阱"
4. 影子页——让"读"和"执行"看到不同内容（读见 original、执行见 shadow）
5. 跳板——从 Hook 点安全跳到自定义代码
6. NPF 与 #BP 联动
7. Hook 执行完后复位与卸载
8. Hypervisor 反侦察
9. 处理多核/TLB/中断（蓝屏坑）

### 验证
Hook 后被 Hook 函数内存字节不变，PatchGuard 不报篡改，任何读取见原始代码。

---

## §3 VT-D 对抗与 DMA 防护

> 更新：2026-11-17 · 来源：看雪帖 293258（VT-D 对抗）

### 3.1 DMA 防护原理

VT-D 在设备访问内存路径上加硬件控制。自定义 Hypervisor 建转换表，规定设备请求地址对应物理内存及读写权限，启用 DMA 重映射后请求受规则约束。

**三步**：
1. **确定保护范围**：记录 Hypervisor 映像和内部数据池占用的物理内存范围
2. **配置映射权限**：普通内存原址映射；受保护范围映射到 0xFF 填充替代页，设只读
3. **硬件执行保护**：设备读受保护地址得替代页内容；写被 VT-D 权限不足阻止

### 3.2 关键组件

- **VTD 单元**：一对多绑定 DMA 设备，上限推荐 4。含控制状态寄存器、转换表查询逻辑、地址转换/读写权限检查、转换缓存。
- **MMIO**（Memory-Mapped I/O）：寄存器映射到内存，统一操控硬件的底层接口。通过 MMIO 读写控制 VTD 物理硬件。
- **DMAR 表**：存 VTD 信息，每条 DRHD 记录描述一个 VT-d 单元。经 ACPI/EDK2 `EfiLocateFirstAcpiTable` 获取。

### 3.3 DMA 旧时代对抗

- **CR3Fix**：混淆 CR3，执行时回调回填，配合异常接管。EPROCESS.Pcb.DirectoryTableBase 存页表根。
- **HAL HOOK**：劫持 HAL 回调地址全局变量，间接调用接管。

### 验证
DMA 设备读受保护地址得替代页（0xFF），写被阻止，真实组件内存得到保护。

---

## §4 Win11 内核异常体系与接管

> 更新：2026-11-17 · 来源：看雪帖 292876（Win11 26H1 异常体系）

### 4.1 KVA Shadow（内核页表隔离）

开启后进程有 **2 套 CR3**（KPROCESS.DirectoryTableBase 存内核态 CR3）。R3 用残缺页表（映射完整用户态 + KVASCODE 节区小部分内核态落脚点），进内核后切完整页表。防 Meltdown 类侧信道。

### 4.2 异常派发链

`#DE`（向量号 0）→ IDT 第 0 项 → `KiDivideErrorFaultShadow`（KVA 开启时）→ `KiDivideErrorFault` → `KiExceptionDispatch` → `KiDispatchException`（构造 Context、内部错误码转换、R0/R3 FirstChance/SecondChance 路径）。

### 4.3 三种提前接管异常利用点

1. **用户态异常**：`ntdll!KiUserExceptionDispatcher` / `ntdll!Wow64PrepareForException`
2. **PicoProvider**：`nt!PsPicoDispatchException` + 注册 PicoProvider + WSL 子进程 → 用户态异常 + 反调试 + 进程保护
3. **Hal 函数指针**（Win11 25H2 及以下）：特征码定位 HalpPerformanceCounter → 替换 Hal 函数指针 → 堆栈回溯筛选异常派发调用 → 恢复丢失异常信息 → 构造中断返回帧恢复异常派发流程

### 4.4 无痕 Hook 实验（影子模块）

制造影子模块（ShadowModule）→ 向目标函数页面注入异常（隐藏不可执行页面）→ 修复 CFG → 修复全局变量不一致 → 给影子模块挂 Inline Hook。

### 验证
三种接管点分别实现无痕 Hook / 反调试 / 进程保护。

---

## §5 PEB 遍历 / ntdll 基址 / KnownDlls 劫持

> 更新：2026-11-17 · 来源：看雪帖 292791（内核免杀）、292539（KnownDlls 劫持）

### 5.1 PEB 遍历取模块基址（免杀原语）

EDR 在 ntdll Nt* 入口插 inline hook 或 hook kernel32，走 GetProcAddress 必被检测。绕过：从 PEB 直接取模块基址，自己算函数地址直接调，不经任何可被 hook 的 API。

**x64 偏移链**：
- `gs:[0x60]`（`__readgsqword(0x60)`）取 PEB（TEB+0x30）
- `PEB.Ldr` 指向 PEB_LDR_DATA，选 `InMemoryOrderModuleList`（Ldr+0x20）
- `InMemoryOrderModuleList` 是**哨兵头节点**（不对应真实模块），Flink 指向第一个真实模块节点
- `LDR_DATA_TABLE_ENTRY.DllBase` 从 curr 算 **+0x20**（+0x08 是 Blink 后向指针，易错）

遍历：从哨兵 Flink 出发，逐个节点读 DllBase + 模块名，匹配目标模块。

### 5.2 KnownDlls Section 劫持

KnownDlls 是 Windows 缓存机制，启动时为常用系统 DLL 各建 SEC_IMAGE 类型 Section 放 `\KnownDlls\`，加载器查此目录直接映射。

**劫持思路**：驱动关掉原 Section，在 `\KnownDlls\` 建同名 Section，让加载器从自建 Section 加载。

**关键**：`\KnownDlls` 里的 Section 是**永久对象**（OBJ_PERMANENT），ZwClose 只减句柄计数，永久属性顶着的指针计数不归零，对象不删。解法：先 `ZwMakeTemporaryObject` 降级为临时对象，再 ZwClose，句柄归零后系统删名称并调整指针计数，然后建同名 Section。

### 验证
PEB 遍历：代码输出 ntdll 基址。KnownDlls：WinObjEx 确认原 Section 关闭、自建同名 Section 生效。

---

## §6 page cache 写入类漏洞原语

> 更新：2026-11-17 · 来源：看雪帖 291662（Dirty Pipe）、291784（Copy Fail）

Linux 内核中，通过 splice() 零拷贝机制将文件 page cache 页引用传入管道，若管道缓冲区标志位处理不当，可直接写入底层 page cache，修改任意只读文件。

### 6.1 Dirty Pipe（CVE-2022-0847）

`pipe_buffer.flags` 未正确初始化，`splice()` 引入的 page cache 被错误标记 `PIPE_BUF_FLAG_CAN_MERGE`，后续 `write()` 直接写入 page cache。

**利用步骤**：
1. **prepare_pipe**：建管道、写满（内核自动设 CAN_MERGE）、读空 drain（**flags 没清零**，残留 CAN_MERGE）
2. **splice()**：`splice(fd,&offset,p[1],NULL,1,0)` 将只读文件 page cache 引入管道，`copy_page_to_iter_pipe()` 未设 flags=0
3. **write()**：因残留 CAN_MERGE，直接写入 page cache

### 6.2 Copy Fail

经 AF_ALG（User Space Crypto API）调 authencesn（AEAD+ESN），ESN 高 32 位临时写到认证标签预留空间（ESN scratch write），加密/认证失败时流程提前退出，4 字节残留 dst buffer。splice() 零拷贝将文件 page cache 页引用传管道，错误当可修改缓冲区。

### 验证
修改只读文件（如 /etc/passwd）内容，提权至 root。

---

## §7 ROP / 线程池注入 / Egg Hunter

> 更新：2026-11-17 · 来源：看雪帖 293304（ROP）、293254（PoolParty）、289666（Egg Hunter）

### 7.1 ROP（Return-Oriented Programming）

ROP 链布局在栈内存中，形如 8 字节数组，成员是 gadget 地址（实时获取填入）和立即数，**栈被赋予控制执行流程的重任**。区别于 ShellCode（代码控制流程、栈传参互不干扰）。

**实战布局**（弹 MessageBox）：1MB 远程内存自高地址向低分三区——A 区 4KB ROP 主链（控制中心）、B 区 4KB 数据区（字符串）、C 区剩余目标函数专用栈及返回主链预留。

**入口 gadget**：`push rcx; pop rsp; ret`（chain entry pivot），CreateRemoteThread 的 lpStartAddress 指向该 gadget、lpParameter 传 A 区基址。

### 7.2 PoolParty 线程池注入

Windows 线程池复用工作线程执行短生命周期任务，恶意软件利用此机制执行代码，避免直接调 `CreateRemoteThread()` 降低被检测。

**默认 vs 自定义线程池**：默认池由系统管理直接提交；自定义池用 `CreateThreadpool()` 创建，经 `TP_CALLBACK_ENVIRON` 关联任务。`TrySubmitThreadpoolCallback()` 第三参数 NULL=默认池，传 cbe=自定义池。

**WorkerFactory 注入**：向目标默认线程池灌阻塞任务占满工作线程，迫使目标用自定义池执行回调，回调中跳转恶意代码。PoolParty 共 8 种变体（工作线程工厂、工作项、I/O 完成队列、定时器等）。

### 7.3 Egg Hunter

解决溢出后 shellcode 位置不确定或距离远无法直接跳转。原理：远程内存（堆/全局段）放"蛋"（8 字节标记如 `w00tw00t` + shellcode），溢出点写精简"猎人"（约 32 字节）遍历内存页搜索标记，找到则 JMP。

**猎人逻辑**：遍历内存页（syscall/SEH 判可读）→ 比较是否 w00tw00t → 不是继续找 → 是则 JMP 到该位置。适用栈溢出空间小、shellcode 在远处、写入偏移因系统而异。

### 验证
ROP：弹 MessageBox 安全退出。PoolParty：目标进程执行注入代码。Egg Hunter：跨内存页找到蛋并跳转执行 shellcode。

---

## §8 VM 字节码通用结构

> 更新：2026-11-17 · 来源：看雪帖 293353（ARM64 VMP 手写）、292925（七神 VMP）、293277（TVM 去虚拟化）、292890（64位 VMP3.5）

### 8.1 VMP 四要素

1. **存储位置**：`values[]` 存实际数值，数组下标代替名字查找
2. **虚拟寄存器**：`R0=values[0]` 等，寄存器名映射下标
3. **操作码**：`[opcode,dst,lhs,rhs]`，opcode 是约定数字（无语义），执行器按 opcode 分支
4. **PC**：字节码每条固定 4 字节，`pc` 是偏移量，`while(pc<code_size)` 取指-执行-`pc+=4`

新指令 `LOADI [LOADI,目标位置,直接数值,空]` 把常量写进指定位置。

### 8.2 VM 解释器结构

- **dispatcher/handler**：解释器核心，从 ByteCode 取指令，查 handler 分发表，执行对应 handler
- **handlerTables**：定数据流转和跳转边界
- **虚拟寄存器文件**：ctx+偏移定位，如 32×8B
- **VM 入口**：从 `ByteCode**` 取实际字节码指针，初始化 IP=0，经 VM 健壮检测（栈/指针边界校验）进 vmOneHandler

### 8.3 去虚拟化方法

- **WOOT 2009 六步法则**：逆向 VM 解释器（找 dispatcher/handler）→ 找控制流入口 → 写字节码反汇编器 → 反汇编出 IR → 编译器式优化去样板 → 重新生成可执行代码
- **Unicorn 模拟执行去混淆**：IPC 从调试器读寄存器/内存 → Unicorn cb_code 记录每指令地址/寄存器/栈快照，cb_unmapped 按需加载 → 翻译为 PCode 原子操作 → 反向活跃性分析+死代码消除
- **代数化简去虚拟化**（tvm-recover）：不用 SMT，跟踪 guest 寄存器/内存变化，化简可抵消计算，恢复控制流，LLVM 编译写回 PE+PDB

### 验证
mini VMP 跑算术表达式与原函数结果一致；去虚拟化后与解释器差分检查通过。

## §9 安全软件引擎静态分析原语

> 场景：对杀毒/安全软件套件做静态情报——不运行、不加载驱动，靠字符串分类、接口面枚举、信任链分析还原引擎结构与防护能力。主责在 re-methodology §19（全量画像），本节收编跨模块通用原语。

### 9.1 字符串分类法（CATS 正则表）

把引擎模块的字符串按语义分类，是理解模块职责的钥匙。核心正则：

```
verdict（判定名）   : (Trojan|Worm|Backdoor|Rootkit|Virus|Adware|Riskware|
                       HackTool|Spyware|PUA|Exploit|Ransom|Dropper|Downloader)[A-Za-z0-9._/-]{2,44}
engine_tag（引擎标签）: \b(AVE|QVM|QEX|PATT|VDB|MDB|CLOUD|PACK|SCAN)[A-Za-z0-9_.-]{1,24}
db_container（库容器）: (VDB|PATT|EMV|SIGDAT|MAGIC|HEADER|VERSION)[A-Za-z0-9_]{0,14}（忽略大小写）
filetype（文件类型） : \b(exe|dll|sys|doc[xm]?|xls[xm]?|pdf|js|jse|vbs|vbe|ps1|lnk|
                       scr|bat|cmd|wsf|hta|zip|rar|7z|apk|elf|so|jar|msi|reg)\b
behavior_api（行为API）: (CreateRemoteThread|SetWindowsHookEx|WriteProcessMemory|RegSetValueEx|
                       CreateService|ShellExecute|LoadLibrary|QueueUserAPC|
                       NtMapViewOfSection|VirtualAllocEx|SetThreadContext)[A-Za-z]*
trust_cert（信任证书）: (whitelist|white_list|trusted|trust|signer|signature|revoke|...)
cloud（云查）        : (cloud|query|update|...)
url（网络端点）      : http(s)?://...
```

**方法局限**：只做字符串匹配，不验证用途——`behavior_api` 抓到 `LoadLibraryA` 只说明字符串里有这个名字，不代表模块真的执行危险行为（很多是防御逻辑加载自身组件）。分类是「语义线索」，不是「行为判定」。处理原则：照录、标注「情报级」、不下结论。

### 9.2 RPC 服务端 / 客户端桩判定

接口面提取的核心问题：**哪些模块是服务端（能接受调用 = 攻击入口），哪些只是客户端桩（发起调用 = 工具）**。

```
服务端（fuzz 入口）：出现 RpcServerRegisterIf*（注册接口）
                    RpcServerUseProtseqEpW（绑定协议序列与端点）
                    NdrServerCall*（服务器桩调度）
客户端桩（工具复用）：只出现 NdrClientCall2 / NdrAsyncClientCall
opnum 规模 ≈ capstone 数出的 Ndr* 桩调用点数量
```

绑定串两种来源：硬编码（`ncalrpc` / `ncacn_np` / `\RPC Control\`）与运行时拼装（`RpcStringBindingComposeW` 按参数拼接，静态拿不到完整端点，只记录协议序列类型，如实标注不猜）。

### 9.3 IOCTL 权限门与无条件放行码

设备控制接口（如 `\\.\XXX` 自我保护设备）的码表逆出来后，注意权限门：

```
权限门：
├── IoGetDeviceObjectPointer → 需要设备符号链接权限
├── 调用进程需管理员/系统权限
└── ★ 无条件放行码：不受「调用进程受信」门限制（可先打这几条做探测）
```

长度校验的松紧差异是漏洞面：多数码要求 `== 4` 或 `>= 4`；部分码只校验 `!= 0`（wcslen 越界面提示）；个别码同时设上下界（校验最完整）。IOCTL 参数约定（METHOD_BUFFERED）：`Options = InputBufferLength`，`Read.Length = OutputBufferLength`；返回码如 `0xC000000D` 长度不符、`0xC0000022` 未受信进程发非白名单码、`0xC0000010` 未知码、`0xC0000023` 缓冲太小。

### 9.4 签名信任链与签名主体识别

签名面统计时区分「有效签名」的三种来源：

```
厂商自有 EV 证书 —— 用户态主程序与多数 DLL
微软 WHQL / ELAM —— 内核驱动（微软签名通道）
第三方内嵌 —— 无独立签名，作为已签名 DLL 的一段存在
                （例：某 DLL 内嵌整套 sqlite3，243 个导出全是 sqlite3_*，
                 导出表被「借」给宿主，统计时必须折叠，否则误判）
```

- ELAM（Early Launch Anti-Malware）驱动须微软专门签名，在系统启动最早阶段加载——安全软件「早于其他驱动启动」的技术基础。
- 时间戳 CA 两代共存（旧/新 TSA 同时出现在字符串表）说明增量更新残留历史签名模块引用。
- 结论：任何字节改写 → 签名失效；私钥在 HSM 不在样本里 → 「静态改引擎」在信任层被封死，patch 策略必须考虑重签/绕过验签模块。

### 9.5 hook 框架识别（SSDT/Inline Hook 驱动）

从导入表识别成熟 hook 框架的特征：

```
hookport 类驱动导入特征：
├── NtCreateProcess/Ex、NtCreateThread/Ex、NtQueueApcThread/Ex
├── NtSetContextThread、NtDebugActiveProcess、NtSystemDebugControl
├── NtReadVirtualMemory / NtProtectVirtualMemory
├── NtUser* 系列（内核直接做窗口/输入防护判定）
├── DPC：KeInitializeDpc / KeInsertQueueDpc / KeSetTargetProcessorDpc
└── 安全启动：InitSafeBootMode
```

- `KeInitializeDPC` + 多处理器 DPC 设置 = 跨核同步的成熟 hook 框架标配。
- 调试字符串（如 `[HPPM]HookPort Time Out...`）暴露性能自监控机制与日志格式。
- 服务引用（如 win32k.sys / win32kbase.sys / win32kfull.sys）可确认 hook 覆盖范围随系统版本演进。

### 9.6 导出表「公共味」统计反推防护能力

按导出数排序 + 「公共味」比例（`Create*/Init*/Query*/Set*` 等像 API 的命名）识别配置/规则下发 API：

```
规则下发 API 命名模式：AddAntiInject* / AddBlack* / AddClientRule /
                         AddExceptionRule / AddInjectBlockRule / AddKernelRule /
                         AddProtectedFile / AddRule
→ 从导出名反推引擎防护能力矩阵：反注入 / 黑名单 / 内核规则 /
   文件保护 / 例外管理 / 客户端规则
```

纯数字编号导出（如 `safemon_115/117/118/119`）是内部接口编号习惯，真实函数名被抹去，外部难猜用途。

### 9.7 验证

- [ ] CATS 分类脚本对目标模块输出分类清单，抽样人工核对 5 条归类正确
- [ ] RPC 角色判定：服务端模块都含 RpcServer* / NdrServerCall* 特征，客户端桩仅 NdrClient*
- [ ] IOCTL 码表含权限门标注，无条件放行码已标出
- [ ] 签名主体按「EV/WHQL/ELAM/第三方内嵌」四类统计，内嵌组件导出已折叠
- [ ] hook 框架驱动导入特征匹配，DPC/安全启动特征确认
- [ ] 公共味导出清单能反推出至少 3 类防护能力

> 更新：2026-11-18 · 来源：看雪帖 2138217《某杀毒引擎逆向(很久之前)》（脱壳破解区）
