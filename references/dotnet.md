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
