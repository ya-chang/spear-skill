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
