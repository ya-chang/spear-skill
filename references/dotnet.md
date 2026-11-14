# .NET 逆向（dotnet）

目标：反编译/去混淆 .NET 程序，还原校验逻辑、写注册机。**.NET 是托管代码，比原生好逆向。**

## 一、识别 .NET

```bash
file target
strings target | grep -iE "\.net|mscoree|mscorlib|System\.Runtime"
# PE 头有 CS 头（CLR 头）
```

## 二、反编译工具

| 工具 | 用途 | 环境 |
|---|---|---|
| dnSpy | 反编译 + 调试 + 编辑 | Windows GUI |
| ILSpy | 反编译 | Windows/跨平台 |
| monodis / ikdasm | 命令行 IL 反汇编 | Linux 无 GUI |
| dotnet-ildasm | 命令行 | 跨平台 |

无 GUI 环境（Linux proot）：
```bash
sudo apt-get install -y mono-utils
monodis target > target.il     # IL 反汇编
ikdasm target > target.il      # 另一种
```

## 三、还原流程

### 1. 反编译看逻辑
dnSpy/ILSpy 直接看 C# 伪代码，定位：
- 校验函数（license check / 激活 / 注册）
- 序列号生成算法
- 加密/签名验证

### 2. 去混淆（ConfuserEx / 其他混淆器）
混淆器会改方法名、加密字符串、加控制流。处理：
- **字符串解密**：hook `System.String` 构造，或找解密方法 dump 明文。
- **控制流**：IL 层平坦化，用反混淆插件（dnSpy 的 AntiCheat/去混淆插件，或 `De4Dot`）。
- **方法名还原**：靠 IL 结构 + 字符串引用推断。

```bash
# De4Dot：.NET 去混淆
# 下载 De4Dot，对混淆程序跑一遍，还原可读 IL
```

### 3. 还原算法写注册机
找到序列号生成/校验算法后，用 C#/Python 独立实现：

```csharp
// keygen 骨架（按目标算法填）
string GenerateKey(string user) {
    // 还原的算法：从用户信息算出校验码
    return computedSerial;
}
```

## 四、动态验证

```bash
# 用 mono 跑 .NET，Frida/ mono 调试
mono target.exe
# 或 dnSpy 直接挂载调试，改返回值验证
```

## 五、验证

- 注册机生成的序列号能通过校验
- 反编译代码与运行时行为一致

## de4dot 去混淆用法

```bash
# 自动识别并去除混淆
de4dot suspect.exe -o suspect_cleaned.exe

# 强制指定混淆器
de4dot suspect.exe -p cf    # ConfuserEx
de4dot suspect.exe -p sa    # SmartAssembly
de4dot suspect.exe -p dr    # Dotfuscator
de4dot suspect.exe -p rv    # Reactor
de4dot suspect.exe -p bl    # Babel.NET

# 详细输出调试
de4dot -v suspect.exe -o suspect_cleaned.exe

# 多文件程序集
de4dot suspect.exe suspect_helper.dll -o cleaned/
```

**.NET 混淆器对照：**
| 混淆器 | 特征 |
|---|---|
| ConfuserEx | 字符串加密、控制流、反调试、防篡改 |
| SmartAssembly | 字符串编码、流混淆、裁剪 |
| Dotfuscator | 重命名、字符串加密、控制流 |
| .NET Reactor | 原生代码生成、necrobit、反调试 |
| Babel.NET | 字符串加密、资源加密、代码虚拟化 |
| Crypto Obfuscator | 字符串加密、反调试、水印 |

## 六、.NET 程序集检测（pefile）

```python
import pefile
pe = pefile.PE("suspect.exe")

# 检查 .NET COM descriptor
if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
    print("[*] .NET 程序集")
    print(f"    运行时版本: {pe.DIRECTORY_ENTRY_COM_DESCRIPTOR}")
else:
    # 检查 mscoree.dll 导入（备选检测）
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode().lower() == "mscoree.dll":
            print("[*] .NET 程序集（mscoree.dll 导入）")
            break
    else:
        print("[!] 非 .NET 程序集")

# 检查 .NET 指示段名
for section in pe.sections:
    name = section.Name.decode().rstrip('\x00')
    if name in ['.text', '.rsrc', '.reloc']:
        print(f"    段: {name}（典型 .NET）")
```

## 七、dnSpy 分析工作流

1. File → Open → 选清理后的程序集
2. 导航到入口点：
   - Assembly Explorer → `<namespace>` → Program 类 → Main 方法
   - 或：右键程序集 → Go to Entry Point
3. 重点检查区域：
   - 入口点（Main）：初始化与执行流
   - Form 类：UI 型恶意程序（RAT/stealer）
   - 网络/HTTP 类：C2 通信
   - 加密类：数据保护
   - 资源访问：内嵌 payload
   - Timer/Thread 类：持久化与调度

**导航快捷键：**

| 快捷键 | 功能 |
|---|---|
| Ctrl+G | 跳转 token/地址 |
| Ctrl+Shift+K | 搜索程序集 |
| F12 | 转到定义 |
| Ctrl+R | 分析（找用法） |
| F5 | 开始调试 |
| F9 | 切换断点 |

## 八、配置与 C2 数据提取

**常见 .NET 恶意程序配置模式：**

```csharp
// 模式 1：硬编码值的静态类
public static class Config {
    public static string Host = "185.220.101.42";
    public static int Port = 4782;
    public static string Key = "GhOsT_RaT_2025";
    public static string Mutex = "AsyncMutex_6SI8OkPnk";
    public static bool Install = true;
    public static string InstallFolder = "%AppData%";
}

// 模式 2：运行时解密的字符串
public static string Decrypt(string input) {
    byte[] data = Convert.FromBase64String(input);
    byte[] key = Encoding.UTF8.GetBytes("SecretKey123");
    for (int i = 0; i < data.Length; i++) data[i] ^= key[i % key.Length];
    return Encoding.UTF8.GetString(data);
}

// 模式 3：资源内嵌配置
byte[] configData = Properties.Resources.config;
string config = AES.Decrypt(configData, derivedKey);
```

**从 IL dump 提取字符串（monodis/ildasm）：**
```python
import subprocess, re, base64

result = subprocess.run(
    ["monodis", "--output=il_dump.il", "suspect_cleaned.exe"],
    capture_output=True, text=True
)
with open("il_dump.il", errors="ignore") as f:
    il_code = f.read()

# 找 ldstr（加载字符串）指令
strings = re.findall(r'ldstr\s+"([^"]+)"', il_code)
for s in strings:
    # 检查 Base64
    try:
        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
        if len(decoded) > 3 and decoded.isprintable():
            print(f"  Base64: {s[:40]}... -> {decoded[:100]}")
    except Exception:
        pass
    # 检查 URL/IP
    if re.match(r'https?://', s) or re.match(r'\d+\.\d+\.\d+\.\d+', s):
        print(f"  Network: {s}")
```

## 九、dnSpy 动态调试

1. 在关键方法设断点：
   - 字符串解密函数（捕获解密值）
   - 网络连接方法（捕获 C2 URL）
   - 文件写操作（看落地什么）
   - 注册表修改方法（看持久化）
2. Debug → Start Debugging（F5）
   - 选要调试的程序集
   - 需要时设命令行参数
   - 配置异常处理（所有 CLR 异常都断）
3. 每个断点：
   - Locals 窗口看局部变量
   - Immediate 窗口求值表达式
   - 调用栈理解执行上下文
   - F10 步过 / F11 步入 / Shift+F11 步出
4. 捕获解密字符串：
   - 在解密函数返回后设断点
   - 从 Locals 窗口读返回值
   - 记录所有解密后的配置值

## 十、分析文档清单

报告应包含：
- .NET 程序集元数据（CLR 版本、目标框架、编译信息）
- 识别的混淆器与去混淆方法
- 完整 C2 配置（主机、端口、密钥、互斥体名）
- 恶意能力（键盘记录、截屏、文件窃取等）
- 持久化机制（注册表、计划任务、启动目录）
- 反分析技术（VM 检测、调试器检测、沙箱逃逸）
- 提取的 IOC（C2 IP/域名、文件哈希、互斥体名、注册表键）
- 基于唯一代码模式或字符串的 YARA 规则

## 十一、关键概念

| 术语 | 定义 |
|---|---|
| **CIL/MSIL** | 公共中间语言；.NET 程序集编译的字节码格式，可反编译回高级 C#/VB.NET |
| **元数据令牌** | .NET 类型、方法、字段在程序集元数据表中的唯一标识，用于 dnSpy 导航 |
| **de4dot** | 开源 .NET 去混淆器，识别并去除多种商业与恶意专用混淆器保护 |
| **ConfuserEx** | 流行开源 .NET 混淆器，恶意代码作者常用，做字符串加密与控制流混淆 |
| **字符串加密** | 用加密数据 + 运行时解密调用替换字符串字面量，隐藏静态分析中的 IOC |
| **资源内嵌** | 把配置、payload、附加程序集存为 .NET 内嵌资源，常以程序集元数据派生密钥加密 |
| **Assembly.Load** | .NET 从内存字节数组加载程序集的方法，支持内嵌 payload 的无文件执行 |

## 十二、工具系统

- **dnSpy/dnSpyEx**：开源 .NET 程序集编辑器、反编译器、调试器，支持 C#/VB.NET 反编译
- **de4dot**：自动 .NET 去混淆器，支持 ConfuserEx、SmartAssembly、Dotfuscator、Reactor 等
- **ILSpy**：开源 .NET 反编译器，提供 C#、VB.NET、IL 视图
- **dotPeek**：JetBrains 免费 .NET 反编译器，带符号服务器与交叉引用导航
- **Detect It Easy（DIE）**：多格式文件分析器，识别 .NET 框架版本、混淆器、编译器信息
