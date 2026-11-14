# 游戏外挂 / 内存读写 / 注入（game-cheat）

目标：游戏辅助开发全链路——内存读写、协议分析、反编译、Hook、驱动级隐藏、自动化脚本。**本地测试用途，覆盖 PC 端游、Android/iOS 手游。**

## 一、内存读写

### 1. 扫描（Cheat Engine 思路）
```bash
# 桌面：CE 手动扫描；命令行用扫描脚本
# 核心：对目标进程内存做 值→地址→偏移链 追踪
```

内存扫描流程：
1. 首次扫描目标数值，得到候选地址列表。
2. 改变数值，二次筛选，缩小范围。
3. 逐步收敛，得到稳定地址 + 基址 + 偏移链。

### 2. 读取（Linux/Android）
```python
# 读取进程内存（需 ptrace 权限或 root）
import struct
def read_mem(pid, addr, size):
    with open(f"/proc/{pid}/mem", "rb", 0) as f:
        f.seek(addr)
        return f.read(size)
```

```javascript
// Frida 读内存
var addr = Module.getBaseAddress("game.so");
var buf = addr.add(offset).readByteArray(size);
console.log(buf);
```

### 3. 写入
```python
def write_mem(pid, addr, data):
    with open(f"/proc/{pid}/mem", "wb", 0) as f:
        f.seek(addr)
        f.write(data)
```

## 二、Hook 技术

### 1. Frida Hook（跨平台首选）
```javascript
// Hook 函数，改参数/返回值
Interceptor.attach(Module.findExportByName("game.so", "target_func"), {
  onEnter(args) {
    // 改参数
    args[0] = ptr(0xDEADBEEF);
  },
  onLeave(ret) {
    // 改返回值
    ret.replace(0x99999999);
  }
});
```

### 2. DLL 注入（Windows）
- `LoadLibrary` 注入、`SetWindowsHookEx`、远线程注入。
- 用 `Inject` 工具或自写注入器。

### 3. 驱动级隐藏（Windows）
- 内核驱动：摘链 `PsProcessId`/`PsThreadId`，隐藏模块，绕过 EAC/BE 等反作弊扫描。
- 参考 `binary-protection.md` 的缓解绕过思路。

## 三、协议分析

### 1. 抓包
```bash
# 桌面：Wireshark / mitmproxy
# 手游：Frida 抓 SSL/Socket
```

### 2. Frida 抓 SSL 明文（Android）
```javascript
// 绕过 SSL pinning，抓 HTTPS 明文
Java.perform(() => {
  const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  // 替换信任管理器，接受所有证书
});
```

### 3. 协议还原
- 分析封包结构：长度字段、魔数、命令字、payload。
- 还原后写收发脚本，做协议级辅助（自动发包/改包）。

## 四、自动化脚本

- 按键精灵 / 模板匹配 / 坐标识别：用图像识别定位 UI，自动点击。
- OpenCV + 模板匹配骨架：
```python
import cv2, numpy as np
template = cv2.imread("btn.png", 0)
screen = cv2.cvtColor(cap_screen(), cv2.COLOR_BGR2GRAY)
res = cv2.matchTemplate(screen, template, cv2.TM_CCOEFF_NORMED)
_, _, _, max_loc = cv2.minMaxLoc(res)
# max_loc 即按钮位置，执行点击
```

## 五、引擎逆向

- **Unity il2cpp**：解 `global-metadata.dat` + `libil2cpp.so`，用 il2cpp dumper 还原 C#。
- **UE4**：解包 `.pak`，分析资产与逻辑。

## 六、反作弊绕过（本地测试）

- 检测 Debugger / Root / 模拟器：Frida 反检测脚本。
- 内存扫描检测：隐藏自身读写痕迹，或 hook 扫描 API。
- 驱动级：内核隐藏模块。

**注意**：反作弊绕过仅用于本地授权测试环境，按测试口径处理。

## 七、验证

- 读写/Hook 生效，游戏内表现符合预期
- 协议收发正确，封包格式对齐
- 自动化脚本稳定运行，不误触

## 高级外挂技术（2025-2026）

### DMA 硬件级内存读写
通过 PCIe 接口直接读取系统内存，完全绕过操作系统和反外挂。

- **工具**：PCILeech（开源，https://github.com/ufrisk/pcileech）、FPGA 自定义设备
- **优势**：反外挂完全无法检测（硬件层面）、可读受保护内存、不触发软件级监控
- **成本**：$300-500

```c
#include <pcileech.h>
uint64_t game_base = 0x7FF612340000;
uint32_t health = 0;
pcileech_memread(game_base + 0x1A3B5C, &health, sizeof(health));
```

### 虚拟化层攻击（Hypervisor / EPT Hook）
利用 CPU VT-x 虚拟化技术，在 Ring -1 层（比内核更高权限）拦截游戏。

```
1. 创建虚拟机，将游戏运行在 VMX non-root 模式
2. 设置 EPT（Extended Page Table）映射
3. 游戏访问被 Hook 页面时触发 VMExit
4. 在 VMExit 处理中执行自定义逻辑
5. 返回游戏继续执行
```
- **优势**：比内核驱动更隐蔽，可拦截任何内存访问，反外挂需同级权限才能发现
- **参考**：HyperBone、SimpleSvm、hvpp

### 直接系统调用（Direct Syscalls）
跳过 ntdll.dll 直接调内核，绕过对 ntdll 调用链的监控。

```c
// 传统（被监控）：NtReadVirtualMemory(...)
// 直接系统调用（不被监控）：
__asm__ __volatile__(
    "mov rax, 0x3F\n"   // NtReadVirtualMemory 系统调用号
    "mov rcx, hProcess\n"
    "mov rdx, addr\n"
    "mov r8, buf\n"
    "mov r9, size\n"
    "syscall\n"
);
```
- **工具**：SysWhispers（自动生成）、HellsGate（运行时解析）、RecycledGate（复用 ntdll 指令）

### 栈伪造（Stack Spoofing）
反外挂检查调用栈，直接 syscall 的调用栈不正常。伪造合法调用栈，看起来像正常 API 调用。
- **工具**：SilentMoonwalk、Stack Spoofing PoC

## 反外挂系统分析

反外挂系统分三个层次：
```
云端检测：行为分析、机器学习、举报系统
用户态检测：进程扫描、内存校验、API Hook 检测
内核态检测：驱动保护、回调监控、完整性校验
```

### 检测分类
| 检测类型 | 方法 | 示例 |
|---|---|---|
| 签名检测 | 扫描已知外挂特征码 | VAC, ACE |
| 内存完整性 | 校验游戏内存是否被修改 | BattlEye, EAC |
| 进程检测 | 扫描可疑进程/模块 | GameGuard, TP |
| 驱动检测 | 检测未签名/可疑驱动 | Vanguard, ACE |
| 调试器检测 | 检测调试器存在 | 所有反外挂 |
| 行为分析 | 分析玩家操作模式 | 云端系统 |
| Hook 检测 | 检测 API Hook | EAC, BattlEye |
| 代码完整性 | 校验代码段 CRC/Hash | VAC, ACE |

### 主流反外挂系统
| 系统 | 使用游戏 | 架构 | 关键检测 |
|---|---|---|---|
| **BattlEye** | PUBG, R6, EFT | 内核驱动+用户态服务 | 内核回调拦截、内存扫描、DLL 注入检测、调试器检测、特征码、文件完整性 |
| **EAC** | Apex, 守望先锋 | 内核驱动+用户态 | 内存完整性、Hook 检测、驱动检测 |
| **Vanguard** | VALORANT | 内核驱动 | 驱动检测、完整性校验、反调试 |
| **VAC** | CS, TF2 | 云端+本地 | 签名检测、代码完整性（CRC/Hash） |
| **ACE/TP** | 英雄联盟, 王者 | 内核驱动+云端 | 进程检测、驱动检测、行为分析 |
| **nProtect** | 各类网游 | 内核驱动 | 内存扫描、进程检测、键盘钩子 |

### 对抗思路（安全研究）
1. **内存完整性校验** → Hook 校验函数返回"未修改"，或用 DMA 绕过
2. **驱动检测** → 使用签名驱动，或 Hypervisor 层隐藏
3. **Hook 检测** → 用无痕 Hook（如 EPT Hook、硬件断点）
4. **调试器检测** → Patch/绕过，或 DMA 完全绕开
5. **代码完整性** → 只改数据不改代码，或运行时动态修改不触发 CRC
6. **行为分析** → 模拟人类操作节奏，避免机械式操作

## 引擎逆向高级技术

### Unreal Engine 逆向（UE3/UE4/UE5）

**识别特征：**
- 静态：`UE4Game.exe`/`UE5Game.exe`、`GEngine.dll`、`.pak` 文件、`UObject`/`UFunction`/`FString` 模式
- 运行时 AOB 签名：

| 目标 | AOB 签名 |
|---|---|
| GObjects | `48 8B 05 ?? ?? ?? ?? 48 8B 0C C8` |
| GNames | `48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0` |
| ProcessEvent | `E8 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ??` |

**Auto SDK 生成：**
```sh
UE4Dumper.exe -pid <target_pid> -dump
# 生成 Classes.hpp / Offsets.hpp / Functions.cpp，加载到 IDA 交叉引用写 ProcessEvent hook
```

**自动对象 dumper（Python + pymem）：**
```python
from pymem import Pymem
pm = Pymem("game.exe")
gobjects = pm.read_int(0x12345678)  # 通过 sig scan 找到
for i in range(1024):
    obj_ptr = pm.read_int(gobjects + i * 4)
    name = pm.read_string(obj_ptr + 0x18)
    print(f"[+] Object {i}: {name}")
```

**引擎工具对照：**
| 引擎 | 工具 | 用途 |
|---|---|---|
| Unity | Il2CppDumper, AssetRipper | dump C# 类、元数据 |
| Unreal | UE4Dumper, SDK Gen | 生成头文件、定位 hook |
| WebGL | wasm-decompile, DevTools | 导出分析、JS 互操作 |
| Lua | Frida, LuaJIT 工具 | dump 全局、hook 逻辑 |

### WebAssembly 逆向

**工具：** wasm-decompile（binaryen）、wasm2wat（WABT）、r2 -AA file.wasm、ghidra_wasm_plugin
**运行时 Hook：**
```js
const original = WebAssembly.instantiate;
WebAssembly.instantiate = async function(buffer, importObj) {
    console.log("[+] Hooked WASM instantiate");
    return original.call(this, buffer, importObj);
};
// 或 Hook eval/Function
Function = new Proxy(Function, {
    apply(target, thisArg, args) { console.log("Eval:", args[0]); return Reflect.apply(...arguments); }
});
```
逆向 exports 识别业务函数（heal()/moveTo()/attack()）。

### Lua 引擎逆向

**Hook 目标：** `lua_getglobal`、`lua_setglobal`、`lua_pcall`
**枚举 Lua 全局表：**
```c
int n = lua_gettop(L);
lua_pushnil(L);
while (lua_next(L, LUA_GLOBALSINDEX)) {
    printf("%s\n", lua_tostring(L, -2));
    lua_pop(L, 1);
}
```
**Frida 动态劫持：**
```js
Interceptor.attach(Module.findExportByName(null, "lua_pcall"), {
    onEnter(args) { console.log("Calling Lua:", args[1]); }
});
```

### 堆喷射与内存映射差异

**堆喷射：** 大量分配填充堆，控制目标对象落在预定地址，用于覆盖指针/返回地址。
**内存映射差异：** 对比两次内存映射，定位新增/修改的 RWX 区域、隐藏模块、动态分配的作弊代码。

### CE Mono Framework（Unity 游戏）
- CE 的 Mono 框架支持直接读取 Unity 对象，无需 IL2CPP 分析
- 用 CE Lua 脚本遍历 Mono 对象树，修改属性（血量/坐标等）

### 代码洞注入（Code Cave）
在目标进程的代码段找空闲空间（NOP 区域），写入跳转指令跳入自己的代码，执行完再跳回。
- 检测代码洞：搜索连续 NOP 或未使用区域
- 注入：写入 `jmp cave` + `jmp back`，cave 内放作弊逻辑
- 比 DLL 注入更隐蔽，无需创建新模块

### 隐身注入策略
- 不创建新进程/模块，复用已有模块的内存空间
- 用 AOB 扫描定位目标后直接修改内存
- 配合代码洞注入，避免模块加载被检测

## 游戏利用技术（Exploitation）

### 本地内存利用
**栈溢出：**
```c
void parse_chat(char *msg) {
    char buf[128];
    strcpy(buf, msg);  // 无边界检查
}
```
```python
payload = b"A" * 132 + b"\xDE\xAD\xBE\xEF"
send_to_game_chat(payload)
```

**堆溢出：**
```c
void read_item(FILE *f) {
    char *buf = malloc(64);
    fread(buf, 1, 128, f);  // 堆溢出
}
```
利用：堆喷射 + UAF，用构造的 `.inv` 文件，重新分配已释放内存为攻击者控制的结构。

**存档利用：**
现代游戏解析自定义 `.sav`/`.json`/`.bin` 存档格式。
- 目标：长字符串（名字/聊天/物品栏）、内嵌脚本字段、复用的遗留字段（如旧引擎的 Lua）
- 构造恶意存档触发解析器漏洞或注入脚本

### 远程与服务端利用
- **API 参数篡改**：修改客户端发送的参数（位置/血量/金币）
- **JWT Token 伪造**：篡改 JWT 声明（role/金币）或弱密钥爆破
- **逻辑利用**：利用服务端校验缺失的逻辑漏洞
- **网络协议利用**：UDP 模糊测试（Scapy）、自定义协议逆向后构造恶意包
- **自定义协议逆向**：抓包分析协议结构，构造能触发服务端漏洞的包

## 高级利用与绕过技术

### Asset-Based RCE（纹理/音乐/地图文件）
游戏通过第三方库加载外部资产（`.png`/`.mp3`/`.pak`/`.bsp`），可注入恶意文件触发解析器溢出或逻辑缺陷：
- 恶意 PNG → libpng 溢出
- 畸形 MP3 → libmad 解析缺陷
- 恶意 `.bsp`/`.pak` → 自定义脚本钩子
- **工具**：Peach Fuzzer、Fuzzino、自定义资产生成器

**利用矩阵：**
| 技术 | 目标 | 说明 |
|---|---|---|
| 栈溢出 | 本地缓冲区 | strcpy 覆盖返回地址 |
| 存档注入 | 客户端 RCE | 构造 .sav 触发内存破坏 |
| JWT 伪造 | 后端认证绕过 | alg=none 或弱密钥 → 管理员 |
| 参数篡改 | 游戏 API | 0 金币购买顶级物品 |
| 包模糊测试 | 多人引擎 | 超大/畸形 UDP 包 |
| 竞态滥用 | 制作/商店 | 异步洪水双重购买 |
| 脚本注入 | Lua 游戏 | `"name": "x'); os.execute('calc.exe') --"` |

### 智能合约与游戏逻辑黑客
区块链游戏：重放签名交易（双花）、代理合约操控注入逻辑、滥用编写不当的游戏逻辑。

### 回放系统黑客
现代游戏的确定性回放系统（.dem/.replay/.json）可逆向提取遥测、修改注入任意输入、利用引擎盲目信任回放内容。

| 游戏/引擎 | 格式 | 说明 |
|---|---|---|
| CS:GO/Source | .dem | 二进制命令/事件日志 |
| Rocket League | .replay | JSON+protobuf+物理帧 |
| Overwatch | .replay | Zstd 压缩二进制 |
| StarCraft II | .SC2Replay | MPQ 归档 |
| Fortnite/UE | .replay | Unreal DemoNetDriver |

**解析工具：** CS:GO 用 demoinfo2/CSGO-Demo-Parser；Rocket League 用 BakkesMod/ReplayParser。
**利用：** 反序列化 RCE（`"player_name": "__import__('os').system('calc.exe')"`）、回放重放滥用、服务器回放导入漏洞。

### Aimbot 技术
| 类型 | 来源 | 检测风险 | 平台 |
|---|---|---|---|
| 内存瞄准 | 实体内存 | 高 | PC |
| 像素瞄准 | 屏幕/颜色 | 中低 | PC/主机 |
| AI 瞄准 | 神经视觉 | 低 | PC/主机 |
| 输入瞄准 | 控制器 | 极低 | 主机+PC |

**内存瞄准：** 读敌人坐标 → 计算 pitch/yaw → 写视角内存。
**像素瞄准：** OpenCV 截图识别敌人颜色框 → pyautogui 平滑移动。
**AI 瞄准：** YOLOv5 检测敌人 → Kalman 滤波预测轨迹。
**主机瞄准：** Arduino Joystick 外部操控。

### 穿墙与延迟利用
- **穿墙（Clipping）：** Patch 碰撞标志位，`*(bool*)(player_ptr + collision_offset) = false`
- **服务端传送同步：** iptables TEE + netem 延迟制造不同步
- **PvP 延迟利用：** Frida hook sendto 延迟战斗包、scapy 丢伤害包、伪造 tick 计数

### 反外挂高级绕过
- Hook `NtQuerySystemInformation` 隐藏进程
- Patch `IsDebuggerPresent`、禁用 ETW（清零 EtwpProviderTable）
- 驱动级注入（签名驱动如 Capcom.sys）
- PEB 摘链 DLL（从 InMemoryOrderModuleList 移除）
- Patch `rdtsc`、VMProtect/Themida 加壳、伪造遥测

**内核战：** 驱动签名绕过（泄漏证书）、Hypervisor 检测规避（Patch CPUID VMX）、内存隐藏（改 CR3 幽灵内存）、DMA（PCILeech+FPGA）、行为伪造（GAN 鼠标）
**高级：** 内核回调 Patch、Rootkit 持久隐藏、HWID 伪造绕过封禁

### 游戏逻辑滥用
NOP 计时器、覆写指针跳过冷却、篡改伤害公式、禁用后坐力、货币不同步、传送、伪造事件、客户端预测不同步（幽灵敌人）、修改 RNG 种子、物品复制。
**高级：** 物理操控（Hook PhysX）、坐标扭曲、RNG 预测（逆向 Mersenne Twister）

### 引擎特化利用
- **Unity：** Patch Assembly-CSharp.dll、Hook Mono 运行时、Il2CppDumper+Ghidra、劫持 Mono JIT
- **Unreal：** 注入 .pak、Hook UFunction::ProcessEvent、UE5 GObjects/GNames dump、ExecuteConsoleCommand
- **GameMaker：** 修改 .yy/.yyp、YYDebug 注入
- **WebGL/WASM：** wasm-decompile、wasm-opt
- **高级：** Shader 替换（透视）、引擎分配器物理 Hook

### APT 级技术
Ring0 驱动注入、EPT 内存重定向（VT-x）、Patch PTE 隐藏页、Hypervisor 执行层、PCILeech DMA、UEFI/EFI Bootkit 固件持久化、GPU 卸载作弊（CUDA 着色器）、Patch Syscall Stubs、NTFS ADS 备用数据流。
**固件/硬件：** UEFI Rootkit（CH341A 刷固件）、GPU 恶意（cuMemAlloc+cuLaunchKernel）、Intel ME（Red Unlock）、SGX/SEV 保护作弊逻辑、隐写术嵌入载荷

### 自动化与模糊测试
- pymem/pyMeow 脚本化内存修改
- AFL++/Honggfuzz 模糊测试 .sav/.pak/.json/.lua
- SendInput 模拟移动、Frida 追踪、Selenium 自动化 UI
- UDP 包模糊器、脚本引擎 Hook、YOLOv5+OpenCV 自动瞄准
- AI 机器人：YOLOv7+DeepSORT 实时追踪、RL 训练（Unity ML-Agents/Gym）
- 覆盖率引导模糊：AFL++ QEMU 模式、自定义变异器（Protobuf/专有结构）

### DRM 与混淆绕过
- **Denuvo 破解：** x64dbg 运行中 dump 内存、ScyllaHide 绕过调试检测、Scylla/PE-bear 重建 PE
- **定位 OEP：** 追踪回原始入口点
- **Patch 解密循环：** 移除 XOR 例程、禁用 CRC 校验
- **定位授权检查：** IDA 交叉引用密钥字符串
- **交接点注入：** Hook stub-解密过渡
- **去虚拟化：** 脱壳 VMProtect/Themida
- **Hook NtOpenFile：** Frida 拦截授权查询
- **VMProtect 3.x：** Triton 解码 x86 操作码
- **Shellcode 工程：** ESP 覆盖（渲染函数钩子执行）、多态 XOR 混淆载荷

## 自动化脚本详解

游戏自动化通过脚本模拟玩家操作，实现挂机、刷副本、日常任务。

| 方式 | 原理 | 适用场景 |
|---|---|---|
| 键鼠模拟 | 模拟鼠标键盘输入 | 简单重复操作 |
| 图像识别 | 截图+模板匹配 | 需判断画面内容 |
| 内存读写 | 直接读游戏数据 | 数据精确获取 |
| 协议模拟 | 直接发网络包 | 无需客户端 |

**开发流程：** 分析操作流程 → 分解步骤 → 确定触发条件 → 选择识别方式 → 编写脚本 → 测试优化

**模拟输入（Windows API）：**
```c
void mouse_move(int x, int y) { SetCursorPos(x, y); }
void mouse_click(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    Sleep(50);
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}
void mouse_right_click(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
    Sleep(50);
    mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
}
```

**图像识别：** OpenCV 模板匹配定位 UI 元素；**OCR：** 文字识别读取画面文字；**AutoHotKey：** 脚本化键鼠操作。

## DLL 注入技术详解

| 注入方法 | 原理 | 适用场景 |
|---|---|---|
| CreateRemoteThread | 远程线程调 LoadLibrary | 最经典通用 |
| SetWindowsHookEx | 消息钩子 | GUI 程序 |
| APC 注入 | 异步过程调用 | 线程挂起时 |
| Process Hollowing | 替换进程内存 | 高级隐藏 |
| Reflective Injection | 内存中反射加载 | 免落地 |

**CreateRemoteThread 模板：**
```c
BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath)+1,
                                       MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath)+1, NULL);
    FARPROC loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}
```

## Hook 技术类型对比

| 类型 | 原理 | 难度 | 稳定性 | 适用场景 |
|---|---|---|---|---|
| Inline Hook | 修改函数入口指令（5字节 JMP） | 中 | 高 | 任意函数 |
| IAT Hook | 修改导入表函数指针 | 低 | 高 | 导入的 API |
| EAT Hook | 修改导出表函数指针 | 低 | 中 | 导出的函数 |
| VMT Hook | 修改虚函数表指针 | 低 | 高 | C++ 虚函数 |
| 异常 Hook | 利用异常处理机制 | 高 | 中 | 无修改检测场景 |

- **Inline Hook**：用 MinHook（推荐），x64 需处理 5 字节跳转和重定位
- **VMT Hook**：替换 vtable 中的函数指针，适用于 COM 接口/C++ 多态/游戏引擎对象

## 主机平台特化

### PlayStation（PS4/PS5）
- 前提：特定固件漏洞、安装自制系统（HEN/Mira）
- 工具：IDA Pro（MIPS/ARM）、PS4 SDK、Apollo Save Tool（存档编辑）、PS4 Cheater（内存搜索）
- 存档修改：导出存档 → Apollo/Save Wizard 解密 → 修改 → 重新加密导入

### Xbox（One/Series）
- 开发者模式可侧载应用（开发者账号 $19/年）
- 系统安全性高，主要通过存档修改或网络协议分析

### Nintendo Switch
- 自制固件 + 漏洞利用，内存修改与存档编辑

### 通用存档修改
- 存档解密 → 分析结构 → 修改数据 → 重新加密

## PC 平台 DirectX Hook

**版本检测：** 查看游戏目录 DLL（d3d9.dll/d3d11.dll/d3d12.dll）、Process Monitor 监控模块、Dependencies 查导入表。

**DX9 Hook：**
1. 创建 Dummy D3D9 设备获取 VMT
2. 记录关键函数：EndScene(index 42)、Reset(index 16)、Present(index 17)
3. VMT Hook 替换目标函数
4. Hook 中初始化 ImGui 绘制 ESP/菜单

**DX11 Hook：**
- Hook `IDXGISwapChain::Present`、`ID3D11DeviceContext::DrawIndexed`
- 创建 Dummy DXGI SwapChain → 获取 VMT → Hook Present → DX11 绘制

## libmem 库（跨语言内存操作）

libmem 是跨语言的内存读写库，支持 Python/C++/Rust。
- **核心 API**：查找进程、枚举进程、检查存活、读写内存、指针链追踪
- 适合快速开发内存读写工具，跨平台跨语言

## C++ 外挂开发基础

- **环境**：Visual Studio 2022+、CMake、依赖库（MinHook、libmem 等）
- **Windows API 常用**：OpenProcess、ReadProcessMemory、WriteProcessMemory、CreateRemoteThread
- **内存操作基础**：基址+偏移、指针链追踪（多级指针解析）
- **开发流程**：环境搭建 → 内存扫描定位 → 指针链追踪 → 编写读写/Hook → 测试

## Shellcode 工程

**ESP 覆盖**：通过渲染函数钩子执行 shellcode。
**多态 XOR**：压缩/混淆 shellcode 载荷，每次生成变体避免特征码匹配。

## DRM 加载器分阶段逆向（Staged DRMs）

现代 DRM（Denuvo、VMProtect 等）采用分阶段加载，运行时逐步解密真实代码。

**逆向流程：**
1. **检测分阶段行为**：观察程序运行中多次 mprotect/解密调用
2. **定位真实入口（OEP）**：追踪加载器流程，找到原始代码入口
3. **x64dbg 追踪加载器流程**：单步跟踪解密/加载阶段
4. **VMProtect 加载器内部**：识别 VM 主循环、handler 表
5. **VM handler 识别**：统计字节码频率，推断 opcode 语义
6. **嵌套加载器脱壳**：多层加载器逐层剥离
7. **反调试/反 dump 绕过**：Patch 检测点，ScyllaHide 等
8. **手动 dump 重建**：dump 解密后内存，用 Scylla/PE-bear 修复 IAT/导入表
9. **Denuvo 分阶段**：运行中 dump 解密 .text，重建 PE
10. **加载器签名**：识别常见加载器特征
11. **DRM 加载器模糊测试/变异**：对加载器做 fuzz，找解析缺陷

**DRM 工具生态：** Scylla、PE-bear、ScyllaHide、Qiling Framework（重建 VM handler）、Triton（解码 VMProtect opcode）

## AI/ML 增强

**生成式作弊**：用 AI 生成自然的鼠标移动（GAN）、自动瞄准（YOLOv7+DeepSORT）、智能行为模拟。
**高级技术**：强化学习训练游戏 agent（Unity ML-Agents/OpenAI Gym）、AI 驱动的反检测行为伪装。

## 硬件级攻击

- **DMA**：PCILeech + FPGA（FT601）实现不可见内存读写
- **GPU 作弊**：CUDA 着色器卸载作弊逻辑（cuMemAlloc + cuLaunchKernel）
- **Intel ME**：Red Unlock 代码注入
- **SGX/SEV**：在 enclave 中运行受保护的作弊逻辑
- **隐写术**：在纹理/资产中嵌入载荷

## 固件分析（Console & PC Firmware）

固件是反外挂和平台安全的基石，固件操控可实现：启动早期注入不可检测作弊、绕过安全启动/签名验证/TPM、完全控制内存/虚拟化/根级遥测。

**UEFI dump-patch-injection：**
| 用途 | 工具 |
|---|---|
| 固件提取 | UEFITool、Chipsec、Flashrom |
| 修改 UEFI 变量 | RU.EFI、AMIBCP、H2OUVE |
| 安全启动绕过 | UEFI Shell、EDK2 hacking |
| Flash 读取 | CH341A SPI Programmer |

```bash
flashrom -p ch341a_spi -r dump.bin
sudo chipsec_util spi dump BIOS.bin
UEFIExtract dump.bin / UEFIDump dump.bin
```

**探索 DXE 模块：** 寻找 SecureBoot、SetupUtility、TPM、SmmAccess2 等。
**Patch 启动流程：** 添加未签名 DXE 模块、Hook BootServices->StartImage、注入 payload 在 ExitBootServices() 后写 RAM。
**注入 DXE 模块载荷：** 修改 UEFI .ffs 文件 → UEFITool 插入 → 刷入 patched ROM，载荷在 pre-OS 早期触发。

**主机 Boot ROM 逆向：**
- **Nintendo Switch**：Boot0/Boot1/pkg1/pkg2；漏洞 Fusée Gelée、Warmboot Handoff；工具 hekate、Lockpick_RCM、Atmosphere、TegraExplorer、HacTool
- **PS5**：BootROM → Second Loader → Secure Kernel；LV0/LV1 Hypervisor 逆向
- **Xbox Series**：Scarlett 启动链

**固件攻击矩阵：** 从 BIOS/UEFI 到 hypervisor、bootloader 的完整攻击面，研究级固件工具链。

## 高级移动游戏利用

### iOS 高级技术
- 越狱后用 Frida/Fridump 提取内存、Hook Objective-C 方法
- 利用 `cycrypt`/`cycript` 运行时探索
- Mach-O 分析：class-dump、otool、 Hopper/IDA
- 绕过越狱检测：Frida 反检测、内核补丁

### Android 高级技术
- Frida 深度 Hook：Java/Native/JNI 全链路
- 内存转储：`gdb` + `gcore`、Frida `Memory.dump`
- 反检测：Frida 检测绕过、root 检测绕过、模拟器检测绕过

## 云存档与成就系统利用

### 云存档篡改
- 逆向云存档同步协议，修改存档数据后重放
- 篡改本地存档缓存，触发同步覆盖云端
- 利用云存档的冲突解决机制，注入恶意数据

### 成就/奖杯系统利用
- 伪造成就解锁请求，绕过成就验证
- 修改本地成就缓存，触发解锁

## 速度跑工具与技术

### TAS（工具辅助速度跑）
- 帧级输入录制与回放，精确控制游戏
- 利用游戏漏洞（穿墙、跳帧）加速通关

### RNG 操控
- 逆向随机数生成器，控制随机结果（掉落、敌人生成）
- 修改 RNG 种子，预测/操控随机事件

### 帧级输入执行
- 精确到帧的输入注入，利用游戏时序漏洞

## 内存取证规避

### 反内存转储技术
- **进程保护**：防止 `gcore`/`ProcessDump` 转储内存
- **内存加密**：运行时加密关键数据，转储后不可读
- **反调试**：检测调试器/转储工具，触发反制
- **内存清理**：定期清零敏感内存区域

## 供应链与更新机制攻击

### 游戏更新 MITM 攻击
- 中间人拦截更新请求，替换更新包
- 利用更新服务器的弱认证，注入恶意更新

### CDN 清单操控
- 篡改 CDN 上的资源清单，替换游戏资源
- 利用 CDN 缓存投毒，分发恶意资源

### 签名验证绕过
- Patch 客户端签名验证逻辑
- 利用签名验证的弱实现（如仅校验文件头）

## 侧信道攻击

### 缓存侧信道
- 利用缓存命中/未命中的时间差，推断游戏状态（如敌人位置）

### 时序健康检测
- 通过操作响应时间，推断游戏内部状态（血量、技能冷却）

## P2P 网络利用

### P2P 网络利用
- 伪造 P2P 节点，注入恶意数据
- 利用 P2P 发现机制，进行中间人攻击
- 篡改 P2P 通信，操控游戏状态

## 反作弊开发视角

### 构建简单反作弊系统
- **检测层**：进程扫描、内存校验、API Hook 检测
- **防护层**：代码完整性校验、内存保护
- **响应层**：举报系统、云端行为分析
- **设计原则**：多层级检测、行为分析、云端协同

## libmem 库详细 API（补充）

libmem 是跨语言内存读写库，支持 C/C++/Rust/Python，平台 Windows/Linux/FreeBSD（x86/x64）。
- **GitHub**：https://github.com/rdbo/libmem

**安装：**
```bash
pip install libmem                    # Python
```
```cmake
# C++ CMake
include(FetchContent)
FetchContent_Declare(libmem-config
    URL "https://raw.githubusercontent.com/rdbo/libmem/config-v1/libmem-config.cmake"
    DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(libmem-config)
set(CMAKE_PREFIX_PATH "${libmem-config_SOURCE_DIR}" "${CMAKE_PREFIX_PATH}")
set(LIBMEM_DOWNLOAD_VERSION "5.1.4")
find_package(libmem CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE libmem::libmem)
```
```toml
# Rust Cargo.toml
[dependencies]
libmem = "5"
```

**核心 API（Python）：**
```python
from libmem import *

# 进程操作
process = find_process("game.exe")
print(f"PID: {process.pid}, Name: {process.name}")
for proc in enum_processes():
    print(f"{proc.pid}: {proc.name}")
if is_process_alive(process):
    print("Process is running")

# 模块操作
module = find_module_ex(process, "game.dll")
print(f"Base: {hex(module.base)}, Size: {module.size}")
for mod in enum_modules_ex(process):
    print(f"{mod.name} @ {hex(mod.base)}")
addr = find_symbol_address(module, "get_player_health")

# 内存读写
health = read_memory_ex(process, health_addr, 4)
health_int = int.from_bytes(health, 'little')
write_memory_ex(process, health_addr, int(999).to_bytes(4, 'little'))
# 深度指针追踪：base + offset1 -> ptr1 + offset2 -> ptr2 + offset3 -> final
final_addr = deep_pointer_ex(process, module.base + 0x1234, [0x10, 0x20, 0x30])

# 模式扫描（?? 为通配符）
pattern = "55 8B EC 83 E4 F8 ?? ?? ?? ?? ?? ?? 56 8B F1"
addr = sig_scan_ex(process, pattern, module.base, module.size)
data = b"\x89\x5C\x24\x08"
addr = data_scan_ex(process, data, module.base, module.size)

# 汇编/反汇编
payload = assemble("mov eax, 1; ret", 64)
code = bytes([0x55, 0x48, 0x89, 0xE5])
for inst in disassemble(code, 64, 0):
    print(f"{hex(inst.address)}: {inst.mnemonic} {inst.op_str}")
```

**C++ Inline Hook：**
```cpp
#include <libmem/libmem.h>
void hooked_function(int arg1) {
    printf("Hooked! arg1=%d\n", arg1);
    original_function(arg1);
}
lm_address_t target = LM_FindSymbolAddress(&module, "target_function");
LM_HookCode(target, (lm_address_t)hooked_function, &trampoline);
```

**实战：特征码扫描 + 修改：**
```python
process = find_process("game.exe")
module = find_module_ex(process, "game.exe")
damage_pattern = "55 8B EC 83 E4 F8 83 EC 10 56 8B F1"
damage_func = sig_scan_ex(process, damage_pattern, module.base, module.size)
if damage_func:
    write_memory_ex(process, damage_func + 0x15, b"\x90" * 5)  # NOP 扣血指令
```

**常见问题：**
- 找不到进程 → 以管理员权限运行
- 写入失败 → 用 `ProtMemoryEx` 先改内存保护为可写
- 特征码找不到 → 版本变化，重新用 CE/x64dbg 分析
- 指针链失效 → 更新后用 CE 重新扫描

## 驱动级开发详解（补充）

### WDF 驱动基础
```c
#include <ntddk.h>
#include <wdf.h>

VOID DriverUnload(_In_ WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    KdPrint(("Driver unloaded\n"));
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = DriverUnload;
    status = WdfDriverCreate(DriverObject, RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;

    WDFDEVICE device;
    WDF_DEVICE_CONFIG device_config;
    WDF_DEVICE_CONFIG_INIT(&device_config, WDF_NO_EVENT_CALLBACK);
    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, L"\\Device\\GameHelper");
    PWDFDEVICE_INIT device_init = WdfControlDeviceInitAllocate(
        WdfGetDriver(), &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    WdfDeviceInitAssignName(device_init, &device_name);
    status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING sym_link;
    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\GameHelper");
    WdfDeviceCreateSymbolicLink(device, &sym_link);
    return STATUS_SUCCESS;
}
```

**环境搭建：** 安装 WDK，启用测试签名（`bcdedit /set testsigning on` 重启生效），或启动时按 F8 禁用驱动签名强制。

### 内核内存读写

**MmCopyVirtualMemory（跨进程读写）：**
```c
NTSTATUS kernel_read_memory(PEPROCESS src_proc, PVOID src_addr,
                            PVOID dst_buf, SIZE_T size) {
    SIZE_T bytes_read = 0;
    return MmCopyVirtualMemory(src_proc, src_addr, PsGetCurrentProcess(),
        dst_buf, size, KernelMode, &bytes_read);
}

NTSTATUS kernel_write_memory(PEPROCESS dst_proc, PVOID dst_addr,
                             PVOID src_buf, SIZE_T size) {
    SIZE_T bytes_written = 0;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), src_buf, dst_proc,
        dst_addr, size, KernelMode, &bytes_written);
}
```

**MDL 方式：**
```c
PVOID map_memory_mdl(PEPROCESS process, PVOID address, SIZE_T size) {
    PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (!mdl) return NULL;
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return NULL;
    }
    return MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
}
// 使用后 MmUnmapLockedPages + IoFreeMdl
```

**辅助函数：**
```c
// 进程名 → PEPROCESS
PEPROCESS get_process_by_name(const wchar_t* process_name) {
    for (ULONG pid = 0; pid < 100000; pid += 4) {
        PEPROCESS ep;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &ep))) {
            UCHAR* image_name = PsGetProcessImageFileName(ep);
            // 转换并比较，命中则返回
            ObDereferenceObject(ep);
        }
    }
    return NULL;
}
// 获取模块基址：遍历 PEB → Ldr → InLoadOrderModuleList
```

### 隐藏技术

**进程隐藏（摘链）：**
```c
void hide_process(PEPROCESS process) {
    PLIST_ENTRY active_process_link = (PLIST_ENTRY)(
        (PUCHAR)process + active_process_links_offset);
    active_process_link->Blink->Flink = active_process_link->Flink;
    active_process_link->Flink->Blink = active_process_link->Blink;
    active_process_link->Flink = active_process_link;  // 自引用防遍历出错
    active_process_link->Blink = active_process_link;
}
```

**模块隐藏（摘 PEB 模块链）：**
```c
void hide_module(PEPROCESS process, const wchar_t* module_name) {
    PPEB peb = PsGetProcessPeb(process);
    if (!peb) return;
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (module->BaseDllName.Buffer &&
            wcsstr(module->BaseDllName.Buffer, module_name)) {
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;
            break;
        }
        entry = entry->Flink;
    }
}
```

**注册表隐藏：** hook `RegQueryValueExW`，命中目标键返回 `STATUS_NOT_FOUND`。

### 内核通信（IOCTL）
```c
#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
用户态通过 `DeviceIoControl` 发 IOCTL，驱动在 `DispatchDeviceControl` 中处理，实现用户态↔内核态通信。

### 反检测与对抗
- 驱动签名：使用合法签名或测试签名，避免被反作弊检测未签名驱动。
- 隐藏驱动对象：从 `PsLoadedModuleList` 摘链，避免被驱动扫描发现。
- 规避回调监控：避免注册易被检测的回调，或用未文档化机制。
- 对抗完整性校验：不修改被校验的代码页，或用内存空洞/影子页。

## 硬件指纹伪装（HWID Spoof）

### 检测项与修改方式

| 项目 | 修改方式 |
|---|---|
| 主板序列号 | 注册表修改 |
| 硬盘序列号 | VolumeID 工具 |
| MAC 地址 | 注册表修改 |
| CPU ID | 硬件级，不可修改 |
| GPU ID | 硬件级，不可修改 |
| TPM | 可以清除/重置 |
| Windows GUID | 注册表修改 |
| 显示器 EDID | 可修改 |

参考：https://github.com/RejiDev/game-hacking-guidelines/blob/master/techniques/hwid.md

## Windows 安全特性绕过（补充）

### VBS（Virtualization Based Security）
Windows 虚拟化安全，将关键安全功能放在隔离的虚拟机中。
绕过：禁用 VBS、利用漏洞突破虚拟化边界。

### HVCI（Hypervisor-protected Code Integrity）
超级管理程序保护的代码完整性，确保只有签名代码能在内核执行。
绕过：利用已签名的合法驱动、BYOVD（自带漏洞驱动）。

### CET（Control-flow Enforcement Technology）
Intel 控制流保护，防止 ROP/JOP。
绕过：利用未启用 CET 的代码路径。

### ETW（Event Tracing for Windows）
Windows 事件追踪，反外挂用它监控 API 调用。
绕过：修补 ETW 函数、修改 ETW Provider 注册（如清零 `EtwpProviderTable`）。

## 外挂开发 8 阶段工作流

```
阶段 0: 侦察
  - 目标分析（引擎、反外挂、网络架构）
  - 环境搭建（虚拟机、调试器、工具链）

阶段 1: 静态分析
  - 二进制逆向（IDA/Ghidra）
  - 偏移提取（关键数据结构、函数地址）

阶段 2: 动态分析
  - 实时内存验证（只读，不修改）
  - 函数调用跟踪

阶段 3: 概念验证
  - 最小渲染（ESP 框架）
  - 首次内存写入

阶段 4: 核心构建
  - 完整功能实现
  - 性能优化

阶段 5: 加固
  - 检测规避
  - 反调试保护
  - 代码混淆

阶段 6: 测试
  - 多会话验证
  - 反外挂兼容性测试

阶段 7: 维护
  - 游戏更新适配
  - 偏移更新
  - 用户反馈处理
```
