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
