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

- [ ] 注册机生成的序列号能通过校验（keygen 输出序列号，目标程序校验通过，无"注册失败"）
- [ ] 反编译代码与运行时行为一致（dnSpy 反编译逻辑与实际执行结果匹配）
- [ ] 去混淆后 IL 可读（de4dot 处理后方法体清晰，无混淆残留）
- [ ] Patch 后程序功能正常（修改校验逻辑后，注册/授权路径跑通，无崩溃）
- [ ] 动态验证通过（Frida/mono 调试观察校验函数实际执行路径与预期一致）

## 五·五、代码骨架：.NET 注册机骨架

> 可运行的 .NET keygen 骨架，按逆向的校验算法生成序列号。关键算法按样本替换。

```csharp
// DotnetKeygen.cs — .NET 注册机骨架（C#）
// 从 dnSpy 逆向的校验算法，本地生成有效序列号

using System;
using System.Security.Cryptography;
using System.Text;

class DotnetKeygen
{
    // 占位：从逆向获取的校验参数
    const string SEED = "[SEED_STRING]";       // 种子/盐值
    const string LICENSE_FORMAT = "[XXXX-XXXX-XXXX-XXXX]"; // 序列号格式

    // 校验算法（按逆向还原）
    static string GenerateSerial()
    {
        // 1. 用种子生成随机基值
        byte[] seedBytes = Encoding.UTF8.GetBytes(SEED);
        SHA256 sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(seedBytes);

        // 2. 从哈希生成序列号（按样本的格式规则）
        // 占位：实际按逆向的格式拼接
        string serial = string.Format(
            LICENSE_FORMAT,
            Convert.ToBase64String(hash, 0, 4),
            Convert.ToBase64String(hash, 4, 4),
            Convert.ToBase64String(hash, 8, 4),
            Convert.ToBase64String(hash, 12, 4)
        );

        return serial;
    }

    // 校验函数（与目标程序逻辑一致，用于自测）
    static bool ValidateSerial(string serial)
    {
        string expected = GenerateSerial();
        return serial == expected;
    }

    static void Main(string[] args)
    {
        string serial = GenerateSerial();
        Console.WriteLine("Generated Serial: " + serial);

        // 自测
        bool ok = ValidateSerial(serial);
        Console.WriteLine("Validate: " + (ok ? "PASS" : "FAIL"));

        if (!ok)
        {
            Console.WriteLine("ERROR: keygen output does not pass self-validation");
            Environment.Exit(1);
        }
    }
}
```

编译：`csc DotnetKeygen.cs`（或 `dotnet build`）。运行：输出序列号，自测 PASS。验证：序列号输入目标程序通过校验。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §二 注册机实现使用

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

## dnSpy.MCP：把 .NET 逆向交给 AI

> 来源：看雪帖《dnSpy.MCP——把逆向交给AI》（如风少年，293555，2026-11-17 学习）。

### 痛点
逆向 Unity 手游（翻 `Assembly-CSharp.dll`）或 PC 端 .NET 程序时：
1. 代码全被混淆，类名/方法名全是 `a`/`b`/`c` 或乱码，肉眼无从下手；
2. 想让 AI 看核心加密/会员校验逻辑，复制代码到手酸，或直接「字数超限、上下文爆掉」；
3. 复制出来的代码缺命名空间和类结构，AI 开始瞎猜、胡说八道。

### 方案
写开源插件 **dnSpy.MCP**：**以前是你给 AI 搬运代码，现在是给 AI 装一副眼睛和双手**，让它直接钻进 dnSpy 里自己翻类、找方法、查调用链。支持自动 Patch 功能。

### 与本文档工作流的结合
- 传统流程（`七、dnSpy 分析工作流`）是人工在 dnSpy 里翻；接入 MCP 后，把「定位类/方法/调用链、读逻辑」交给 Agent，人只做方向确认与结果验证。
- 仍遵循本文档原则：**静态论证完成 ≠ 动态实证完成**，AI 给出的调用链与算法结论必须用实际运行/真实请求验证。
- 混淆严重时先用 de4dot 去混淆，再让 AI 分析，降低 AI 误判。

---

## 十三、.NET 保护量化识别与补丁实战（实战经验）

### 一、先判定"有没有壳、壳在哪一层"

.NET 的保护分三层，混在一起判断会浪费大量时间：

| 层 | 表现 | 突破点 |
|---|---|---|
| **壳/加密器**（方法体抽空） | 反编译一片空、方法体 4 字节 | 找解密 stub、dump 后修复 |
| **混淆器**（Babel/Confuser/自研） | 字符串加密、控制流平坦化、重命名 | 静态求值字符串、还原控制流 |
| **业务校验** | 少量真实方法 | 定位、打补丁 |

**识别指标（可量化，别靠感觉）**：

| 指标 | 正常 | 被保护 |
|---|---|---|
| `#US` 堆大小 | 与代码量成正比 | **异常膨胀**（真实案例 1,896B → 2,503,232B，1320×） |
| 方法 `Code size` 分布 | 集中在几十~几百字节 | **大量 4 字节**（真实案例 83% 是 4 字节空壳） |
| 真实 IL 方法数 | ≈ 元数据方法数 | 远小于（真实案例只剩 30 个） |
| 字符串解密调用数 | 0 | 数百 → 数万（真实案例 216 → 21,827） |
| 类型/成员命名 | 有意义 | `ql::a`、`ozzzzzq::b()` 单字母 |

单一指标不够（三证据规则）：#US 膨胀 + 空壳占比 + 解密调用数 三条同时成立，才能下"被加密抽走"的结论。

### 二、字符串：把多步算术静态求值成一步

混淆器的字符串解密通常是：`ldstr "<密文>"` → `call smethod_3(string)`（里面是一串 xor/add/shift），形参里有一个 int key（`A^B` 形式可算术复算）。

做法：
1. 找到被调用次数最多的 `string → string` 方法（用调用图统计，不要靠读代码）。
2. 把它的算术抽出来，用脚本对每个密文**离线算一遍**，替换成字面量。
3. **不要 `eval` 原方法**——它常带反调试（`Debugger.IsAttached`、`Stopwatch` 计时检测）。

工具：dnlib 遍历 `MethodDef`，对每个 `ldstr` 找其后的 `call`，替换 operand。

### 三、定位崩溃根因：fieldrefs 列写入点

**问题**：设置面板 `NullReferenceException`，堆栈指向某方法。**错误做法**：看堆栈 → 认定是该方法的问题 → 去改它。**为什么错**：它只是**后果**，自己也是"读到 null 才崩"的。

**正确做法**：找出所有**写入**该静态字段的位置（而不是读取）：

```csharp
// 找出所有写入该静态字段的位置（而不是读取）
foreach (var instr in method.Body.Instructions)
    if (instr.OpCode == OpCodes.Stsfld && ((IField)instr.Operand).Name == 目标字段)
        记录(method.FullName, instr.Offset);
```

真实结果：找到 **11 处自毁分支**（在特定条件下把全局对象置 null）。

> **堆栈是结果，写入点是原因。**
> 适用边界：仅适用于"全局对象被置 null"型 NRE。空数组、越界、类型转换失败都不适用。

### 四、补丁纪律：等长 + 栈平衡

**替换表（x86/x64，最常用）**：

| 原指令 | 字节 | 安全替换 | 说明 |
|---|---|---|---|
| `stsfld` | 5 | `pop`(0x5A) + 4×`0x00` | **必须 pop**：`stsfld` 从栈弹一个值，只 nop 掉栈失衡，后续指令全错位 |
| `bne.un` | — | `pop` + `pop` | 比较用的两个值都要弹掉 |
| `call` | 5 | `nop`×5 | 保留长度，不调用 |
| 函数整体 | ≥6 | `B8 imm32; C3` | `mov eax, imm32; ret`——**优于**借库函数序言，不依赖外部符号与重定位 |
| 返回 bool | 3 | `B0 01 C3` | 仅 32 位且返回类型在 AL（FPC/Delphi 常见） |
| 返回 enum | 6 | `B8 03 00 00 00 C3` | 需要返回 eax=3 时 |

**ARM64**：分支补丁 `0x14000000 | (off>>2)` 把 `BR Xn` 改成 `B imm`（`BR` 只有寄存器，`B` 才有立即数）。

**绝对禁止：重序列化**。Cecil 改 IL 很方便，但 `Write()` 会**重排 token、改写方法体偏移**。真实翻车：用 Cecil 改完 → `InvalidProgramException` → 保护依赖字节级结构，第 13 层用主程序自身派生密钥，任何字节变化顺着链传导。

**正确做法**：字节补丁——读整个文件 → RVA 换 FileOffset（按节 VirtualAddress/PointerToRawData）→ 改那几字节 → 写回。不重序列化，长度不变，偏移全保留。

**工具选择判据**：
- 保护对**语义**敏感 → 改 IL（Cecil/dnlib 回编）
- 保护对**字节偏移**敏感 → 必须降到字节层
- 判定实验：用高层工具改一次看报什么错，`InvalidProgramException` 就是降层信号

### 五、校验值与它守护的分支是一体的

真实案例（CRC64 门）：伪 CRC64 通过 → 切进"文件可信"分支 → 该分支用"原始文件派生"的方式解受保护程序集 → 补丁版字节已改 → 解出来是垃圾 → `BadImageFormatException`。

**结论：不要伪造校验值，只改那个分支本身。**

推论：任何"过了校验反而崩"的现象，都在告诉你"校验结果被用作解密/解压的输入"，而不是单纯的开关。

### 六、分层密钥与自锁

真实案例：14 层嵌套，**第 13 层的密钥从主程序自身派生**。后果：改主程序任意 1 字节 → 派生密钥变化 → 第 13 层解出垃圾 → 全盘崩。这解释了一个反直觉现象："明明只改了一个 nop，怎么整个起不来了"。

应对：
1. **先找派生点**：搜主程序文件读取 + 哈希（`SHA256`/`CRC64`/`MD5` 对自身镜像段），以及 `Assembly.GetExecutingAssembly().Location` 之后紧跟的文件读取。
2. **把补丁做在"被派生范围之外"**：派生只覆盖 `.text` 某段就打进不被覆盖的区段；覆盖全文件就只能改派生函数本身（回到"改分支不改校验"）。
3. **重建派生链**：改完后重算哈希并写回（工作量大但可行）。真实案例是"改字节即崩 / 重建链后恢复"两条证据共同确认了这条机制。

### 七、强名与程序集加载

| 事实 | 后果 |
|---|---|
| `Assembly.Load(byte[])` **不校验强名** | 可以加载同名但签名不同的程序集 |
| `AssemblyResolve` 事件动态加载 | 可在解析路径上插同名 DLL → **同名 DLL 劫持** |
| 客户端内嵌私钥（真实案例） | 签名可自行生成，"验证"退化成本地自洽 |
| 验证方法返回 bool + 调 `RSA/ECDsa.VerifyHash/VerifyData` | **这就是定位 verify 方法的判据** |

**定位 verify 方法的通用判据（比找字符串可靠）**：返回类型 == bool，且方法体内调用 RSA/ECDsa/DSA 的 `VerifyHash/VerifyData/VerifySignature`，且参数含 byte[] 或签名结构体。

### 八、定位授权点的四种锚（按可靠性排序）

| 锚 | 做法 | 案例 |
|---|---|---|
| **UI 文案/资源字符串** | 搜 `free version`、`No product key.`、`Unregistered` → 反查引用它的方法 | 有限元软件 → `ALicense.MasterCheck` |
| **版本比较指令** | 搜 `cmp word [mem], imm` 特征码 | 版本判断 |
| **调用点** | 找 `test eax,eax` 前面最近的那个 `call` | Delphi 注册码 |
| **返回值使用** | 找"返回值被赋给 UI 可见状态"的位置 | trial 计数器 |

**选定目标后，先列出"必须同时成立的完整条件集"**，不要逐个试。真实案例：`features2 == 20 && versionAllowed == 7 && Verify() == 1 && Test3() == 1`，漏掉任一条件 → 改完还是受限。把每个条件都改成"能满足的最小值"，而不是一律返回 true（返回 true 可能越界进别的分支）。

**避开的分支**：剩余天数常与 UI 显示、定时器、写配置联动，改它容易产生"能用但每天弹窗"的后遗症。优先改"功能位"。

### 踩坑速查

| 坑 | 正解 |
|---|---|
| `stsfld` 直接 nop | 栈失衡，后续全错；必须 `pop` + 4×00 |
| Cecil `Write()` 回写 | 重排 token，触发字节级保护；改字节补丁 |
| 伪造 CRC/HMAC | 校验值参与解密，伪造 → `BadImageFormatException` |
| 看堆栈定位根因 | 堆栈是结果，用 fieldrefs 找写入点 |
| 改一处授权就宣布完成 | 存在第二处判断（另一份拷贝/内联副本/服务端） |
| 一律 `return true` | 可能进越界分支；返回"需要的具体值"更安全 |
| 改剩余天数 | 与 UI/定时器/写盘联动，副作用多；优先改功能位 |
| 认为强名会挡住 DLL 劫持 | `Assembly.Load(byte[])` 不验签 |
| 用单一指标判壳 | #US 堆 + 空壳占比 + 解密调用数 三证据 |
| 只在一台机器验证 | 换机器/换用户名/换时区都要测（机器绑定常见坑） |

### 验证

- [ ] 保护层已判定（壳/混淆/业务校验），量化指标（#US 堆、Code size 分布、解密调用数）三证据齐全
- [ ] 字符串解密用离线静态求值替换为字面量，未 eval 原方法（反调试不触发）
- [ ] 补丁等长且栈平衡（stsfld 用 pop+4×00），用字节补丁而非重序列化
- [ ] 未伪造校验值；授权条件集完整列出并逐条最小化，未一律 return true
- [ ] 干净环境 + 副作用验收 + 换机器/用户名/时区回归通过

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）
