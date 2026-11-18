# 工具链装配（toolchain）

目标：在 Linux（含 aarch64 proot）上补齐逆向渗透所需工具。**缺什么装什么，别一次性全装。**

## 一、基础探测（先看看现成有什么）

```bash
for t in gdb r2 radare2 objdump readelf nm strings file rabin2 frida adb apktool baksmali upx angr; do
  which $t >/dev/null 2>&1 && echo "$t: OK" || echo "$t: MISSING"
done
python3 - <<'EOF'
for m in ["frida","angr","capstone","pwntools","androguard","unicorn","keystone","r2pipe"]:
    try: __import__(m); print(m,"OK")
    except Exception: print(m,"MISSING")
EOF
```

## 二、apt 安装（系统级工具）

```bash
sudo apt-get update
sudo apt-get install -y \
  binutils file gdb strace ltrace \
  radare2 upx-bin \
  build-essential python3-pip
```

- `binutils`：objdump / readelf / nm / strings / addr2line
- `file`：识别文件类型
- `gdb`：动态调试（aarch64 主机可用 `gdb-multiarch` 跨架构）
- `radare2`：r2 / rabin2，静态+动态一体
- `upx-bin`：UPX 脱壳

跨架构调试（在 x86 上调 ARM，或反之）：
```bash
sudo apt-get install -y gdb-multiarch
```

## 三、pip 安装（Python 库与插桩框架）

```bash
pip install --user frida frida-tools angr pwntools capstone keystone unicorn r2pipe androguard
```

- `frida`：动态插桩，跨平台，Android/iOS/桌面通吃
- `angr`：符号执行，CFG 恢复、路径枚举
- `pwntools`：pwn 工具链（ROP、格式串、shellcode）
- `capstone`：反汇编引擎（自写工具用）
- `androguard`：APK/DEX 静态分析
- `r2pipe`：从 Python 调 r2

## 四、Android 工具（做 APK/壳时）

需要 JDK + Android build-tools + platform-tools：

```bash
sudo apt-get install -y openjdk-17-jdk
# 下载 Android platform-tools（含 adb）与 build-tools（含 apksigner/zipalign）
# 或直接 pip install androguard 做静态；真机调试需 adb + frida
```

- `adb`：真机/模拟器通信
- `apktool` / `baksmali`：APK 解码、smali 修改
- `apksigner` + `zipalign`：重打包签名对齐
- `keytool`（JDK 自带）：生成 keystore

## 五、.NET 工具

- `dnSpy` / `ILSpy`：.NET 反编译（GUI，需桌面环境）
- 无 GUI 环境可用 `monodis` / `ikdasm`（命令行 IL 反汇编）：
  ```bash
  sudo apt-get install -y mono-utils
  ```

## 六、工具选择速查

| 任务 | 首选 | 辅助 |
|---|---|---|
| 通用动态调试 | GDB + pwndbg | r2 |
| 系统调用追踪 | strace | ltrace |
| 库函数追踪 | ltrace / Frida | GDB 断点 |
| 纯静态 stripped | r2 `aaa` | angr CFGFast |
| 符号执行 | angr | GDB + Python |
| 动态库 Hook | LD_PRELOAD / Frida | GDB |
| 内存错误 | Valgrind | GDB watchpoint |
| 性能热点 | perf | GDB |
| 内核态追踪 | bpftrace / perf | — |

## 七、环境限制说明

- **无 GUI 环境**（手机 proot）：IDA Pro / Ghidra / dnSpy 跑不了，用 r2 / GDB / angr / 命令行工具替代。
- **真机调试**：adb 需要连真机或模拟器，纯本机只能做静态 + 本机动态。
- **跨架构**：调 ARM 二进制在 x86 用 `gdb-multiarch` + `set architecture arm64`。

## MCP 工具链：把逆向工具接入 AI Agent

> 来源：看雪帖学习（2026-11-17）：Win 内核在线 MCP（290992）、dnSpy.MCP（293555）、Claude+多工具 MCP Android 工具链（293009）。

### 架构通式
`分析者 → AI Agent → MCP → 逆向工具 → 运行环境 → 分析结果 → AI Agent` 闭环。
AI 负责理解目标、拆解任务、选工具、推进分析；MCP 是连接层，把不同工具统一接入；工具提供实际分析能力；运行环境提供动态验证。

### 典型 MCP 服务
| MCP | 方向 | 能力 |
|---|---|---|
| **NT-MCP（HexScan）** | Win 内核/二进制 | 通过 MCP（Streamable HTTP）暴露 PE/PDB 查询、反汇编、特征码扫描、内核文档、Intel 指令文档；免本地部署，直接加 MCP 服务器即用；支持自动制作特征码、查询结构定义、逆向未知函数 |
| **dnSpy.MCP** | .NET 逆向 | 让 AI 直接钻进 dnSpy 翻类、找方法、查调用链，替代人工复制代码；解决混淆、上下文超限、缺命名空间导致 AI 胡猜的问题；支持自动 Patch |
| **JADX-AI-MCP** | Android Java 层 | APK 结构、类/方法搜索、字符串定位、调用关系、组件分析、Java→Native 定位 |
| **GhidraMCP** | Native 层 | SO/ELF、Native 函数、JNI、反编译、交叉引用 |
| **MobSF（MCP + docker）** | APK 信息收集 | Manifest、权限、组件、Exported、Deep Link、Native 库、安全配置，结果驱动后续分析 |

### 装配与使用要点
- MCP 服务**无需本地部署**的（如 NT-MCP）直接在 Agent 配置里添加服务器即可；需要本机工具的（JADX/Ghidra/dnSpy）先跑工具再暴露 MCP。
- Agent 侧工具状态需为 running；静态定位与动态观测（执行/参数/返回值）互相印证才算验证。
- **成熟度注意**：各 MCP 封装效果因工具而异（回帖反馈「JADX MCP 感觉不怎么好用」），选型时保留原生工具操作兜底，不把单一 MCP 封装当唯一通道。
- Docker + 模拟器链路（MobSF 动态模块）需先打通 ADB 与模拟器连接，否则动态分析工具空转。
- 闭环有效性依赖：工具返回结果可验证 + 分析者对结果做二次判断，不是把工具全交给 AI 就完事。

## 五、Agent 友好反编译引擎：Droid ASC

JADX 面向人类（产出数 GB 的 CFG/AST/Xrefs），Agent 只要代码——Droid ASC 为此而生（BlackHat EU 2026 Arsenal 中稿）。

- **安装**：`pip install droidasc`；Rust 实现（`rust_ASC` 仓库）是 Python 版一比一复刻，AI+人工混合开发，性能约 10 倍。
- **核心设计**：极端懒加载 + R8 编译器优化原语，只输出代码，不做全量中间表示。
- **实测性能**：16 线程全量反编译 QQ（383MB）4 秒；300MB APK 全局交叉索引搜索 1.79 秒；50MB 量级 493ms。
- **实战案例**：Codex Agent + ASC 两天几乎零人工干预，自动拖出设备上全部 UID=1000 的 apk/jar/apex（近 100 个，多在 50~100MB），全部分析完，产出 1 个 RCE、1 个 System UID 任意文件写、2 个可直接利用 ROOT 漏洞 + 2 个受限 ROOT。
- **对比 JADX MCP**：JADX 一个 APK 一个实例、每个实例吃掉半机内存，百个包分析无从谈起；ASC 支持并行批量，是替代 JADX MCP 的直接选择。

## 六、IDA 插件：DeepFuncSimilar 跨版本函数定位

预训练机器学习模型（ONNX）驱动的 IDA 插件，在**不同版本的 x64 二进制**中快速定位相同函数（跨版本符号迁移利器）。

- **环境**：IDA 9.3 + Python 3.11；依赖 `numpy onnxruntime`（`python -m pip install numpy onnxruntime`），插件文件放 `IDA/plugins` 目录。
- **性能**：纯 CPU，4 万函数文件峰值内存 1100MB、CPU 6%。
- **用法**：旧版本已分析文件 A 中任意函数体 → `DeepFuncSimilar -> 导出至剪辑版` → 在待分析文件 B 中定位对应函数。
- **场景**：旧版已分析、新版待分析的同函数定位，省去逐函数重认。

## 七、iOS 侧：IOS-MCP + IOSDecryptHUb

- **IOS-MCP**：iOS UI 自动化能力，让 Agent 直接操控手机（可从 GitHub 下载 deb 包安装）。
- **IOSDecryptHUb**：算法自吐日志 + hook 能力；安装插件后需 `pip install ios-decrypt-hub`，MCP 配置 `{"mcpServers": {"idh": {"command": "idh", "args": ["mcp"]}}`；手机与电脑同局域网。
- **实战要点（山东航空案例）**：idh 开注入 → 开 App 出 web 面板 → 让 AI 用 IOS-MCP 操控登录并分析；AI 在加密日志找不到线索会走偏，人工引导 hook `mlock`（"指针+长度"型 API、密钥必经之路）后数分钟拿到密钥。结论：AI 思路有限，hook 选型仍靠人的经验。

## 八、IDA 全托管：IDA-Script-MCP

- **工具**：`pip install ida-script-mcp`；安装插件并配置客户端用 `ida-script-mcp-install install claude`（预设支持 claude / cursor / vscode / windsurf / claude-code，`--project` 在项目目录生成 `.mcp.json`，`--list-clients` 列出预设，`uninstall` 卸载）。
- **架构**：IDA 插件（`ida_plugin.py`）内置 HTTP 服务端，默认端口 **13338**、冲突自动递增；端点 `GET /health`、`GET /metadata`、`POST /execute`；`execute_sync` 保证 IDA API 主线程执行；多实例用 JSON 文件注册（`{instance_id: {port, database}}`）。MCP Server（`server.py`）暴露四工具：`list_ida_instances`、`execute_idapython`、`check_ida_connection`、`get_ida_database_info`。
- **环境要求**：IDA Pro 8.3+、Python 3.11+、Win/macOS/Linux；附带 50+ `ida_*` 模块文档供 AI 查 API。
- **使用**：IDA 中 `Edit → Plugins → IDA-Script-MCP`（Ctrl+Alt+S）启动，输出 `Server started at http://127.0.0.1:13338`；对 AI 直接说"列出所有函数 / 反编译 main 并解释 / 谁调用了 0x401000 / 重命名 0x401000 为 decrypt_flag"。
- **安全**：插件允许 AI 执行任意 Python 代码——只配可信 AI、默认绑 127.0.0.1、勿暴露公网、隔离环境分析不可信样本。

## 九、语义级插桩：JSVMP 纯算还原（X-Gnarly 案例）

- **适用**：JSVMP 混淆的 JS 签名 SDK（如 TikTok webmssdk 5.2.1，44KB 字节码、解释器内核），FakeEnv/Node vm 补环境因浏览器特征检测难以推进时。
- **工作流（fast-spider skills）**：`init → capture → runbook → trace → analyze → plan → fill → verify`。
- **插桩手法**：`patch_sdk.js` 源码级特征匹配定位核心执行位置，在每个 `.call()`/`.apply()`/关键二元/三元运算处注入 `__tk_log` 记录器（函数对象、参数、返回值、运算轨迹）；Playwright 拦截代理把线上 CDN 脚本替换为本地插桩版；单次产出约 **28 万行语义日志**，避开 VM 操作码转换、直接记录寄存器数值与函数交互。
- **还原路径**：日志 → GLM-5.2 辅助逻辑整合 → 分阶段假设 → 纯 JS 前向复现 → 双 trace 对拍（key48 摘要/轮数/splitIndex 一致）→ curl_cffi 发包实测。
- **通用要点**：动态输入（queryString/UA/ts）实时生成，固定常量（OT、key48、rounds、A/B/M1/M2/T12/T13）从真机 trace 提取固化；能对拍的签名才算还原完成。

## 十、Frida 内部机制与脚本运行时机

- **整体启动与进程注入（292814）**：三组角色——①Android 创建进程：Launcher→ATMS→system_server→**Zygote fork**→specialize（设 uid/SELinux 域/进程名），USAP 是预 fork 备用进程；②Frida 注入：frida-tools client→frida-server→RoboLauncher spawn→**zymbiote** 门控载荷注入 Zygote/USAP（改 `setcontext`/`setArgV0` 函数指针，新进程出生上报 PID 暂停等 ACK）→Linjector ptrace 注入→bootstrapper→loader→**frida-agent**；③门控会话：zymbiote 平时只留 RX（借 `libstagefright.so` 尾页 padding 藏身），目标 App 等 client `resume()` 发 ACK 才放行。关键区分：Zygote=应用进程父体、zymbiote=门控载荷、frida-agent=完整载荷。
- **脚本运行时机与 Java.perform（292880）**：用户 JS 第一行等 `Script.load()` 才执行。时间线：Script.load() 执行 top-level→`Java.perform(fn)` 发现默认 loader 为空将 fn 入队→VM.perform 为 JS 线程取 JNIEnv 装 framework Hook→resume()→App 主线程继续→bindApplication→LoadedApk/App ClassLoader→Hook 设 ClassFactory.loader→执行回调。三边界：`create_script()` 返回≠顶层已执行；`Script.load()` 返回≠Hook 已命中/ClassLoader 就绪；`Java.perform()` 回调开始≠当前必是主线程/插件类必可见。工具：`Java.performNow()`（不等待 loader）、`Java.scheduleOnMainThread()`、`Java.enumerateClassLoaders()`、`Java.ClassFactory.get(loader)`。
- **Frida Stalker 指令级追踪（292853）**：动态代码重写，每条指令复制到影子内存、指令后插回调。**transform 回调以基本块为单位**（非逐指令），`iterator.keep()` 保留原指令、`iterator.putCallout()` 插回调。要点：跨模块指令过滤（`instruction.address` 比对目标模块基址/大小，否则 ART/libc/linker 刷屏）；性能 30ms 批量输出+指令去重（console.log 走 IPC 逐条打印会卡死）；`Stalker.unfollow(tid)`+`Stalker.flush()` 冲刷尾部。适用：定位 SIGSEGV 退出路径、逐层回溯检测源头。
- **GLM 驱动 Frida 实战**：无道德审查模型直接生成反检测/内存修改/线程拦截脚本、长时间稳定输出 Stalker transform 回调、主动给优化建议；逆向 Agent 按"描述要做什么→生成怎么做"迭代。

> iOS Hook/重签名/风控等技术内容已归位到 `mobile-reverse.md`（按治理规则，工具链只保留工具安装，技术内容归主责 playbook）。

## 十二、PC 调试器 MCP 自动化工具链

- **x32dbg MCP（292993）**：MCP 桥接 AI 远程操控 x32dbg。三轮演进：第一代社区 HTTP 插件；第二代 x64dbg-automate 原生 ZeroMQ 消息通道（三大调试实验全流程从 10 分钟+压缩至约 2 秒）；第三代官方 x64dbg-automate MCP 服务器，**48 个标准化调试工具**，零硬编码路径、纯离线依赖、拷贝即用。安装：x64dbg 装 x64dbg-automate 插件，MCP 配置指向官方 MCP 服务器。
- **z0bdbg MCP（293257）**：自研调试器 z0bdbg 专用 MCP，C++ 写仿 codex 的逆向 agent 终端，**101 个接口+101 个 tool list** 给 AI 自由选择工具函数自动分析。适合自研调试器需要细粒度工具接口的场景。
- **选型**：官方 x64dbg-automate MCP 标准化程度最高、零配置；z0bdbg MCP 接口数多但需自行维护调试器；ZeroMQ 原生通道性能最优但需自行封装 MCP。
- **与移动端工具链对比**：PC 侧调试器 MCP 侧重断点/单步/寄存器/内存读写等底层控制；移动端 Frida 侧重 Java/Native hook、Stalker 指令追踪。两者均通过 MCP 让 AI Agent 直接驱动调试器，减少人工在工具间切换。

## 十三、验证清单

- [ ] 静态分析工具可用（`file`/`readelf`/`objdump`/`strings`/`rabin2` 命令执行无报错）
- [ ] 动态分析工具可用（`gdb`/`frida`/`strace`/`ltrace` 能正常运行，版本正确）
- [ ] 符号执行工具可用（`angr` 能加载样本并初始化工程）
- [ ] Android 工具链完整（`adb`/`apktool`/`apksigner`/`zipalign`/`frida` 命令可用）
- [ ] .NET 工具可用（`dnSpy`/`monodis` 能打开 .NET 程序）
- [ ] MCP 工具连接正常（`ida-script-mcp`/`x32dbg-automate` MCP 服务器启动，端点可达）
- [ ] 工具版本记录完整（每个工具的版本号已记录，与 playbook 要求的版本匹配）

## 十三·五、代码骨架：工具链安装与验证脚本

> 可运行的脚本骨架，批量安装并验证工具链，输出可用性报告。关键包名按环境替换。

```bash
#!/bin/bash
# toolchain_install_verify.sh — 工具链安装与验证骨架
# 批量安装逆向渗透工具，逐项验证可用性

TOOLS=(
    "gdb:gdb"
    "frida:frida"
    "strace:strace"
    "ltrace:ltrace"
    "angr:pip install angr"
    "file:file"
    "readelf:binutils"
    "objdump:binutils"
    "strings:binutils"
    "rabin2:r2"
    "adb:android-tools-adb"
    "apktool:apktool"
)

echo "=== 工具链安装与验证 ==="
PASS=0
FAIL=0

for item in "${TOOLS[@]}"; do
    name="${item%%:*}"
    install_cmd="${item#*:}"

    # 安装（apt 或 pip）
    echo "[install] $name: $install_cmd"
    if [[ "$install_cmd" == pip* ]]; then
        $install_cmd 2>/dev/null
    elif [[ "$install_cmd" == "android-tools-adb" || "$install_cmd" == "apktool" ]]; then
        # Android 工具单独处理（按环境调整）
        echo "  (skip auto-install, manual setup required)"
    else
        apt-get install -y "$install_cmd" 2>/dev/null
    fi

    # 验证
    if command -v "$name" &>/dev/null || python3 -c "import $name" &>/dev/null 2>&1; then
        VER=$(command -v "$name" 2>/dev/null || python3 -c "import $name; print($name.__version__)" 2>/dev/null)
        echo "[verify] $name: OK ($VER)"
        PASS=$((PASS+1))
    else
        echo "[verify] $name: FAIL (not found)"
        FAIL=$((FAIL+1))
    fi
done

echo ""
echo "=== 汇总 ==="
echo "可用: $PASS / 失败: $FAIL"
if [ $FAIL -gt 0 ]; then
    echo "[warn] 部分工具未安装成功，按 playbook 要求手动补齐"
fi
```

运行：`chmod +x toolchain_install_verify.sh && ./toolchain_install_verify.sh`。验证：输出每项工具可用性，汇总通过/失败数量，失败项按 playbook 手动补齐。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §一~§四 工具安装使用

