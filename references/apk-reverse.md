# APK 逆向（apk-reverse）

目标：在 CLI 环境对 Android APK 做解包、反编译、smali 修改、重打包、Frida 动态 Hook。**先 triage，再改包，最后 Hook。**

## 一、工具分工

| 工具 | 用途 |
|---|---|
| `jadx` | Java 反编译阅读，先从高层逻辑理解 |
| `apktool` | 解包/改 smali/改资源/重建 |
| `frida` | Java/native 动态 Hook |
| `adb` | 设备连接、安装、日志、拉取 |
| `baksmali`/`smali` | Dalvik 字节码修改 |
| `radare2`/IDA | `.so` native 分析 |

## 二、推荐工作流

### 1. Triage（先摸清构成）
```bash
jadx -d jadx_out app.apk
apktool d app.apk -o apktool_out
# 先看：AndroidManifest.xml、主 package、application/activity/service/receiver、lib/ 里的 .so
```

### 2. Java 逻辑观察
从 `jadx_out` 读：
- `MainActivity`、`Application`
- 登录、网络、加密、风控相关类
- 第三方 SDK 初始化类

常见关键词：`login` `sign` `encrypt` `cipher` `token` `root` `certificate` `trust` `okhttp` `retrofit` `webview`

### 3. Smali 与资源层确认
jadx 结果不完整、混淆重、或需实际 patch 时切到 `apktool_out`：
- 看 `smali*/`、`res/values/strings.xml`、`AndroidManifest.xml`
- 优先 patch：`android:exported`、调试标记、root 检测返回值、登录验证、证书校验分支

### 4. 重建与安装
```bash
apktool b apktool_out -o rebuilt.apk
zipalign -p 4 rebuilt.apk aligned.apk
apksigner sign --ks release.keystore --ks-key-alias release --out signed.apk aligned.apk
apksigner verify signed.apk
adb install -r signed.apk
```

### 5. 动态 Hook
静态不足时用 Frida：
- Hook 登录函数、OkHttp/Retrofit/WebView 关键点
- Hook `javax.crypto`、`MessageDigest`
- Hook root 检测、SSL pinning 逻辑

原则：先 Hook Java 层，再考虑 native；先打印参数返回值，再决定是否改返回值。

```bash
frida-ps -U
frida -U -f com.example.app -l hook.js
frida-trace -U -f com.example.app -j '*!*certificate*'
```

### 6. Native `.so` 分流
遇到这些信号尽快切 native：Java 层只是 JNI 包装、核心签名不在 Java、`System.loadLibrary()` 后关键逻辑消失、证书校验/风控在 `.so`。

- 快速 triage：`rabin2 -I lib.so`、`strings`、`r2 aaa`
- 深度分析：IDA/Ghidra

## 三、Frida Java Hook 骨架

```javascript
Java.perform(function() {
    // Hook 登录校验，强制返回 true
    var Login = Java.use("com.example.LoginActivity");
    Login.check.implementation = function() { return true; };

    // Hook Cipher 获取算法和密钥
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log("[Cipher] algo: " + algo);
        return this.getInstance(algo);
    };
});
```

## 四、输出要求

最终至少说明：入口组件与关键类、关键逻辑在 Java/smali/`.so`、已确认敏感点（登录/签名/root/SSL/WebView/JNI）、patch 改了什么、Hook 了哪个类/方法。

## 五、禁止事项

- 不要一开始就盲目改 smali
- 没看 manifest 和主入口前不要写 Hook
- Java 反编译不完整 ≠ 逻辑不可分析
- `.so` 承载核心逻辑时不要死磕 Java 层

## 六、动调调试方法论（运行时观测与数据面插桩）

适用：补环境静态面走死后转向挂进程实时观测。**关键约束：注入越重、扫描越广，越容易触发运行时防护。**

**方法分层（侵入度从低到高）**：

1. 零注入：读进程内存镜像（`/proc/<PID>/maps` 挑候选 rw- 段 → 逐段 dd 落盘 → 本地扫字节码头），不加载 agent
2. 只读插桩：枚举模块/段、读缓冲、抓帧、记录 IO，不改行为
3. 数据面插桩：挂分配/拷贝等数据函数，只观测不改写
4. 代码面插桩：挂静态地址、改指令——**ARM 库在 x86_64 模拟器经翻译层执行时判死路**（冷启动 0 CALL，静态偏移处原指令不命中）

**证据强度三级**：S = 产物可直接反编译/可读且规模可复算；A = 通道验证成功但产出局部；B = 仅通道自检。只认"有落地产物+可复算证据"为成功，其余写明根因不混算。

**核心转向：memcpy → malloc（数据面 hook 选型）**：

- 原问题"密钥是什么"静态穷尽 → **改问"脚本执行时解密后的缓冲必然在内存里存在过，明文在哪一瞬间、哪个缓冲里可读"**
- memcpy hook 弃：高频函数，onLeave 时目标缓冲**仍是密文**（★**解密非原地**：密文拷贝到目标后，解密输出在别处），且必崩 agent
- malloc hook 采用：低频，onLeave 得缓冲首址，**延时后读（解密已完成）**。Frida 要点：`Module.findGlobalExportByName('malloc')` + Interceptor.attach，onLeave 里 setTimeout 延时 8 s，判缓冲头魔数（如 Lua `0x1b 0x4c`）后落盘（`L_idx_size.bin` 命名，上限控制数量）
- 旁路：memcpy hook 抓**源指针**指向的加密块（判密文层类型与 key 长度）；零注入读段抓碎片（稳但不全）

**运行时防护纪律**：存在进程级看门狗时（全内存扫描存活约 30 s 后被检测、进程终止、不弹窗、累积式上报）：离线分析为主、动调只做定向观测、单次观测控制在首扫时间窗内、**禁止全内存扫描**、落盘前先验通道、独立测试环境与消耗性账号、结论按"能证实/不能证实"分开写。

**失败根因五分类（失败也写进记录）**：环境层（翻译层致静态地址失效）、防护层（看门狗杀扫描）、通道层（目录不可写）、时序层（缓冲已释放后复读——**必须 onEnter 同步读**）、证据层（静态改写未跑流量）。每次失败记录：目标、手段、观测值、判据、**排除项**。

**证据边界口径**：静态论证完成 ≠ 动态实证完成；通道打通 ≠ 产物可用；现象存在 ≠ 影响可证实。

## 七、AI+MCP 辅助 Android 逆向工具链

> 来源：看雪帖《基于Claude+多工具MCP搭建AI辅助Android逆向分析工具链》（er7，2026-09）。
> 架构：**分析者 → Claude → MCP → 逆向工具 → Android 环境 → 分析结果 → Claude**。

### 定位
传统逆向要在 JADX/Ghidra/Frida/ADB 间反复切换、大量搜索定位阅读。用 **MCP 把逆向工具
统一接入 Claude（AI Agent）**，由 AI 理解目标、拆解任务、选工具、推进分析，
形成「分析目标 → AI 分析 → 调用工具执行 → 结果验证 → 进一步分析」的闭环，
压缩重复性的搜索、定位与信息整理。

### 工具分工（按分析阶段协同，非孤立使用）
| 工具 | 层 | 职责 |
|---|---|---|
| **JADX-AI-MCP** | Java/Kotlin | APK 代码结构、类/方法搜索、关键字符串定位、调用关系、Activity/Service 组件分析、Java→Native 调用定位 |
| **MobSF**（MCP + docker desktop） | 信息收集/安全检测 | Manifest、权限、四大组件、Exported 组件、Deep Link、Native Library、安全配置；**结果作为后续 JADX/Ghidra/动态分析的输入** |
| **GhidraMCP** | Native | SO/ELF 分析、Native 函数定位、JNI 分析、函数反编译、交叉引用；延伸链路 **Java → JNI → Native → SO** |
| **Emulator + ADB** | 运行环境 | 安装 APK、启动应用、Logcat、Shell、进程信息；MobSF 动态模块经 docker 容器用 ADB 连模拟器自动化动态环境 |
| **Frida** | 动态验证 | Hook 静态分析得到的关键方法，观测：是否执行、参数、返回值、调用次数、时机、Java/Native 运行关系，用运行时结果验证静态结论 |

### 流程要点
1. 明确分析目标 → Agent 拆解并调用对应阶段工具；
2. **MobSF 先行**做信息收集与安全检测，产出基础情报驱动后续分析方向；
3. JADX 分析 Java 层 → 需要时 GhidraMCP 进 Native 层；
4. Emulator+ADB 备运行环境 → Frida Hook 关键方法做动态观测，验证静态结论；
5. 动态结果驱动二次分析或继续追问，Agent 按新方向继续调工具。

### 验证与注意点
- Agent 侧 MCP 工具状态需为 running；静态定位与动态观测（执行/参数/返回值）互相印证。
- 实践反馈：**JADX MCP 封装成熟度一般**（回帖「JADX MCP 感觉不怎么好用」）——
  各 MCP 封装效果因工具而异，选型时保留原生工具操作兜底，不把单一 MCP 封装当唯一通道。
- Docker+模拟器链路需先打通 ADB 与模拟器连接，否则动态分析工具空转。
- 闭环有效性依赖：工具返回结果可验证 + 分析者对结果做二次判断，不是把工具全交给 AI 就完事。

## 八、CUA GUI 自动化逆向（MCP 已死，GUI 当立）

不依赖专用 MCP 封装，用桌面自动化驱动让 AI 直接操作 GUI 工具 + 手机，全流程闭环。案例：Codex + r0env2-windows 解 Android2.0.apk（Java 入口 → ARM 校验 → 真机验证通过）。

**环境装配（Windows 10 x64）**
1. Codex CLI：`Invoke-WebRequest codex-install.ps1` → `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\codex-install.ps1` → `codex login`；确认 `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin` 在 PATH。
2. r0env2-windows：下载仓库 ZIP 放 `C:\Tools\r0env2`，`.\install.cmd`，设 `$env:R0ENV_PROXY` 后 `.\r0env.cmd preview`（`apply` 需管理员）。
3. CUA：装免登录 `cua-driver 0.37.0`（`%LOCALAPPDATA%\Programs\Cua\cua-driver\bin`），用接口 `list_windows` / `get_window_state` / `bring_to_front` / 点击 / 热键 / 文本输入 / `run_script`。
4. 分析工具：jadx 1.5.6（自带 JRE 25.0.3，命令行 `jre\bin\java.exe -cp lib\* jadx.cli.JadxCLI`）；IDA Free 9.4 SP1（Hex-Rays 登录后 F5 云端反编译）；Ghidra 12.2（独立 Temurin JDK 25，低内存机用启动器限堆 512MB、`-Dcpu.core.limit=2`，headless 用 `-import ... -postScript ExportNative.java -max-cpu 2`）。
5. QtScrcpy 4.2.1 连真机；渲染报错 `QOpenGLShader::compile` 时改用户 `config.ini` `UseDesktopOpenGL=0`（软件渲染）；ADB 离线时 `adb reconnect offline`。

**调用关系**
```
用户目标 → AI 读窗口/工具输出判断下一步
  ├─ CUA 桌面（看与点击）
  ├─ Shell/Python（下载与数据处理）
  ├─ jadx/Ghidra（Java/ARM 分析）
  └─ QtScrcpy/ADB → 真机验证 → 失败核对，成功留证
```

**案例要点（Android2.0.apk）**
- Java 入口 `JNI.getResult(str)` → `Java_com_example_test_ctf03_JNI_getResult`；JNI 函数表偏移识别：`GetStringUTFChars` 在 jni.h 索引 169，32 位函数指针 4 字节 → `169×4 = 676 = 0x2a4`，与伪代码 `**(code**)(*param_1 + 0x2a4)` 吻合。
- Ghidra 基址 +0x10000；常量从 ELF 读：`文件偏移 = ELF虚拟地址 - p_vaddr + p_offset`（首段 vaddr/offset 均为 0 时可直接减基址）。`strcmp` 目标含控制字节（如 `20 35 2d 16 61` 中的 `0x16`），只看可打印 ASCII 会漏。
- 动态符号表 Thumb 状态位：`(0x116d & ~1) + 0x10000 = 0x1116c`。
- 校验逻辑：15 字节输入按 `i%3`/`i/3` 分三组，组内变换依赖上一组结果（链式异或），逆运算需按 JNI 执行顺序逐步还原。
- **真机输入偏差**：投屏键盘把 `{}` 映射成 `[]`，首输 Wrong；读 Android 控件树发现实际文本 `flag[sosorryla]`，用 ADB 修正花括号后 Great。验证结论前必须读控件树/截图核对实际内容。

**踩坑清单**
- 每次点击/输入返回成功后必须**再读一次界面**核对；Swing 后台消息窗口不处理，需 `bring_to_front` 重试；`screenshot_context_missing` 时先重新取截图再点。
- 窗口最小化先恢复；布局变化后重新读控件；控件树读不到完整 Swing 对话框时改按截图坐标操作。
- 低内存机（2GB）下 jadx/Ghidra 错峰跑（`-Xmx384m`、单线程），不同时压两个 Java 分析任务。

## 九、Android 逆向 Multi-Agent 系统设计

- **核心理念**：主控集权 + 插件化 + 上下文隔离 + 文档驱动。主控是唯一能下强制命令的角色；Agent 独立上下文，只有任务指令进对话历史；跨 Agent 知识共享走文件系统不走上下文注入；人做终审 + 路径决策。
- **消息总线**（FastAPI + WebSocket + SQLite）：四类消息——
  - `TASK`：主控派发，必须执行不可拒绝，超时上报主控；
  - `REQUEST`：同级协作（如 trace agent 请 IDA agent 查交叉引用），可拒绝/排队，超时发起方自己降级处理；
  - `REPORT`：产出通知，**不进上下文**，需要详情自己去读文档；
  - `STATUS`：心跳广播（idle/busy/blocked），调度用，**不进上下文**。
- **信息层级**：Observation → Fact → Hypothesis → Conclusion，各存 `knowledge/` 对应子目录；**只有 Conclusion 可作后续分析可信前提**，Hypothesis 只可指导探索不能作论据；`failed_attempts/` 记录失败尝试防重蹈覆辙。
- **三层校验**：
  1. 自校验：硬校验（代码直接验证寄存器值/常量/行号，覆盖率 >80% 高可信自动过，50-80% 重点审未覆盖，<50% 逐条验逻辑）+ 软校验，不过打回重做最多 3 次；
  2. 校验 agent：**无状态冷启动**（清空上下文、零先入为主），只看结论+证据+原始数据，输出 PASS/FAIL/UNCERTAIN；
  3. 人：只看 UNCERTAIN 和反复 FAIL 的，做路径决策。
- **插件化**：`plugins/<name>/manifest.yaml`（name/version/model/prompt/tools/subscribes/publishes）+ `agent.py`（消息处理、工具编排、状态管理）+ `validators/`；**subscribes 是硬约束，超范围消息直接拒收**防职责漂移；按场景组装（协议逆向→trace+IDA+unidbg；改机→fingerprint+framework；风控→traffic+rule engine）。
- **持久化与恢复**：`status.json` 全局进度快照（target/goal/phase/progress/confirmed_facts/blocked_paths/next_steps）；Agent 启动读 status.json + conclusions + hypotheses + 未处理消息即可冷启动恢复，无需记住对话历史。
- **模型分配**：litellm 统一接口，trace/关键判断用 Claude，unidbg 补环境代码生成用 DeepSeek，简单任务用便宜模型。

## 十、Windows 三环动态分析：Pin 插装框架（AI 主导）

- **基座选型**：不用 X64Dbg/Windows 异常框架（内核对抗、驱动签名、VMP trace 效率低），选 **Pin/DynamoRIO 插装框架**——JIT 代码缓存、二进制级运行、指令级停止控制，非模拟执行（不翻译指令，避开切换内核指令的对抗问题）。
- **AI 主导设计**：MCP 接口把代码动态注入框架执行，人与 AI 平级、人只做观察员；四种介入时机：**断点 / Windows 异常 / 系统调用 Hook / 指令集模板匹配 Hook**。
- **实现**：Rust 主体 + Python 解释器（非 Frida 的 JS 解释器）+ C 兼容层（Pin 是 cpp）。
- **trace 压缩（VMP 下日志巨大）**：
  1. 连续相同事件合并——`same_payload` 比较事件类型、线程、地址、arg0~arg7（不比较序号），序号连续且内容相同才合并；
  2. 重复指令记录为 `EVENT_REPEAT`（arg0=repeat_count、arg1=事件类型）；
  3. 寄存器不变则跳过记录。
- **TF 标志位虚拟化（VMP 对抗关键）**：目标 POPF/POPFD/POPFQ 设 TF=1 后，若直接置物理 TF，单步异常会落在 Pin 代码缓存地址而非预期位置；简单清 TF 也不行（目标会检查标志或依赖异常进 VEH/SEH）。处理：在指令边界虚拟化 TF——`PIN_SetContextReg(context, REG_GFLAGS, EmulateUserPopFlags(...))`，同步更新栈指针与下一条指令地址，物理 TF 不进代码缓存。
- **实战**：HOOK 系统调用分析 VMP 外壳行为找 Dump 时机（自解压改内存属性绕过系统调用），KCTF Windows 侧分析全用此工具。

## 十一、内核级注入与 Android root 方案

- **KCLF 内核级注入框架（293385）**：定位=**内核控制的线程借用执行框架**，KernelPatch 加载的 KPM（`ld -r` 可重定位，非 LKM）。核心拆两个问题：谁取得目标线程执行机会（KernelPatch 经 `task_work` 在目标线程返回 EL0 时重定向 PC/SP，**不建 ptrace 关系**）、谁把 ELF 变成可运行镜像（`manual` 后端自解析 ELF/符号/重定位；`linker` 后端调 bionic loader）。流程：提交 TID+SO 路径→为目标线程排队 task_work→内核准备临时映射+跳板→改返回 EL0 的 PC/SP→EL0 执行 IFUNC/构造函数或 bionic loader→清理 ABI 参数页+恢复现场+写完成 token+返回原 PC→内核观察点收集→回收。要点：`syscallno=-1` 避免被当系统调用重启；`RET x16` 返回故 x16 不恢复；完成 token 是内存写非专用系统调用，内核经 70 个 syscall 观察池 before-hook 和 status/reap/quiesce 两条路径发现；请求槽与 manual 镜像表分开管理，`state=done`≠资源全清。验证：manual/linker 两路径分别核对加载器可见性。
- **APatch SELinux_hide 检测（293210）**：KP 0.13.9 `selinux_hide` hook `sel_mmap_handle_status` 丢弃上游四项检查（偏移=0、长度=一页、拒 VM_WRITE、清 VM_MAYWRITE）。四项无 root 可探测违规：越界长度 mmap 放行、非零偏移 mmap 放行、`PROT_WRITE` 放行→经 `remap_pfn_range` 建**指向内核 vmalloc 的可写 PTE**（安全缺陷）、`mprotect` 升级放行（单项即可判定）。判定：只有 GRANTED 计违规、errno 拒绝视为通过、授予映射不解引用测完即 munmap、基线失败报 UNTESTABLE。**核心原则：替换内核 handler 时，原 handler 对用户态输入的全部校验与 vma flag 修改均需逐项保留**。
- **GhostLock 内核漏洞移植（292846，CVE-2026-43499）**：`rtmutex.c` `remove_waiter()` 认错人→幽灵 waiter 挂优先级树指向作废内核栈。触发：3 futex+3 线程循环等待死锁→回滚踩 15 年 bug→用户态用大栈缓冲 syscall（pselect/prctl/TCP zerocopy）重印伪造 waiter→`sched_setattr` 走优先级链→红黑树删除变**内核任意地址写**。链：改 boot_id 指针破 KASLR→改 ashmem 函数表（配 configfs 绕 CFI）拿任意读写→patch cred 得 uid=0。移植方法论：官方工厂镜像自带内核、同镜像偏移天然精确（绕开 kallsyms/BTF 权限墙）；KernelSnitch 时序侧信道找工作区页（**BTF 逻辑大小≠slab 物理步进**，960 对齐到 128B=1024）；RB_EMPTY_NODE 盖不掉→把另一节点优先级写 1000 保证必触发；物理布局三件套必须本机核实（Pixel 7 真值 0x80000000）；**竞态 exploit 调试禁热路径 print（测不准原理）**；ashmem 名带 boot_id 会被污染→扫 `/dev/ashmem*`。
- **PTE 跳板读写物理内存（292808）**：ARM64 五级页表（PGD→P4D→PUD→PMD→PTE）手动遍历 VA→PA。预分配单页跳板，**只改一个 PTE** 实现任意用户态进程物理内存透明读写——不改目标页表、不触发缺页异常。支持 1GB/2MB 大页+4KB 标准页；软件 TLB 缓存优化连续访问。对比 `access_process_vm`（受 FOLL_FORCE 限制）、`ioremap`（非对齐崩溃）。

## 十二、VMP 手写与还原

- **从零手写 ARM64 VMP（293353）**：四要素递进：①存储位置——`values[]` 存实际数值，数组下标代替名字查找；②虚拟寄存器——`R0=values[0]` 映射下标；③操作码——`[opcode,dst,lhs,rhs]`，opcode 是约定数字（ADD=1/SUB=2，无语义），执行器按 opcode 分支；④PC——字节码每条固定 4 字节，`pc` 是偏移量，`while(pc<code_size)` 取指-执行-`pc+=4`。新指令 `LOADI [LOADI,目标位置,直接数值,空]` 写常量。ARM64 落地：`br x9` 查分发表，虚拟寄存器文件 32×8B。验证：mini VMP 跑算术表达式与原函数结果一致。
- **七神 VMP 还原（292925）**：WOOT 2009 六步法则——逆向 VM 解释器（找 dispatcher/handler）→找控制流入口→写字节码反汇编器→反汇编出 IR→编译器式优化去样板→重新生成可执行代码。定位：`objdump` 搜 `blr x23`+`mov x0,x21/mov x1,x22/blr x23/mov x21,x0` 函数指针调用结构。VM 入口逐层穿透：OLLVM 外壳→间接调用外壳→壳调用点→初始化字节码调 VM→VM 健壮检测（栈/指针边界校验）→vmOneHandler。handler 语义化：从 `ByteCode**` 取字节码指针、初始化 IP=0、handlerTables 定跳转边界、虚拟寄存器文件基址=ctx+偏移。方法论：只研究 VMP 框架本身不还原算法，寄存器锚定+IR 提升。

## 十三、验证

- [ ] dex 完整提取（apktool/jadx 反编译无报错，类/方法完整，无抽取壳残留空方法）
- [ ] smali 修改后重打包签名成功（`apksigner verify` 通过，安装无签名错误）
- [ ] Frida Hook 命中目标函数（hook 回调触发，参数与返回值可观测）
- [ ] 加固壳脱壳后代码可读（内存 dump 后 JADX/GDA 反编译有有效函数体）
- [ ] 重打包 App 功能正常（启动、登录、核心功能无崩溃，与原版行为一致）

## 十三·五、代码骨架：Frida Java Hook APK 方法

> 可运行的 Frida 骨架，Hook APK 的 Java 方法观测参数与返回值。关键类名/方法按样本替换。

```javascript
// apk_frida_hook.js — Frida Java Hook APK 骨架（Android）
// 原理：Java.use 获取类，overload Hook 方法，观测 onEnter/onLeave

Java.perform(function () {
    // 占位：目标类与方法名按样本确定
    var TargetClass = Java.use("[TARGET_CLASS]");
    var targetMethod = TargetClass.targetMethod.overload(
        "[PARAM_TYPE_1]",
        "[PARAM_TYPE_2]"
    );

    targetMethod.implementation = function (arg1, arg2) {
        // onEnter：观测参数
        console.log("[hook] targetMethod called");
        console.log("[hook] arg1 = " + arg1);
        console.log("[hook] arg2 = " + arg2);

        // 可修改参数（如绕过校验）
        // arg1 = "modified_value";

        // 调用原始方法
        var result = this.targetMethod(arg1, arg2);

        // onLeave：观测返回值
        console.log("[hook] result = " + result);
        return result;
    };

    // 补充：Hook 静态方法
    var StaticClass = Java.use("[STATIC_CLASS]");
    var staticMethod = StaticClass.staticMethod.overload();
    staticMethod.implementation = function () {
        console.log("[hook] staticMethod called");
        return this.staticMethod();
    };
});
```

运行：`frida -U -f com.target.app -l apk_frida_hook.js`。验证：hook 回调打印参数与返回值，确认命中目标方法。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §三 Frida Java Hook 骨架使用

