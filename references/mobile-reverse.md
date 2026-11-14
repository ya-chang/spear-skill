# 移动逆向（mobile-reverse）

目标：Android + iOS 统一逆向方法论，动态插桩、SSL Pinning/Root/越狱检测绕过、移动端加密提取。**Frida + Objection 为核心。**

## 一、四阶段工作流

### Phase 1: 信息收集
```text
Android：
□ APK 获取（adb pull / 应用市场）
□ Manifest 分析：权限、导出组件、Intent Filter、backup 标志
□ androguard analyze APK → 组件/权限/签名
□ APKLeaks：硬编码 API Key/Token/Secret 扫描
□ 加固检测：360/腾讯/梆梆/爱加密

iOS：
□ IPA 获取，frida-ios-dump / Clutch 解密 App Store 二进制
□ Info.plist：ATS 配置、URL Scheme、Queries Schemes
□ class-dump 导出 ObjC 类结构
□ 加固检测：Swift/ObjC 混淆
```

### Phase 2: 静态分析
```text
跨平台：JADX(Android Java) / Ghidra / radare2 / Cutter
Android 专项：apktool d、dex2jar、smali/baksmali
iOS 专项：class-dump、swift-demangle、dsymutil、otool -L、jtool2
```

### Phase 3: 动态分析
```bash
# Frida 通用插桩
frida-ps -U
frida-trace -U -i "open*" com.app

# Objection（无需写脚本）
objection -g "com.app" explore
android root disable
android sslpinning disable
ios jailbreak disable
ios sslpinning disable
```

Frida Gadget（免 Root/越狱）：注入 `frida-gadget.so/dylib` 到 APK/IPA，重签名安装即可 Hook。

### Phase 4: 网络分析
Burp Suite / mitmproxy / Wireshark；Android 用户证书转系统证书（Magisk + MoveCert）；SSL Pinning 绕过用 Frida/Objection。

## 二、常见绕过速查

### SSL Pinning
```bash
# Objection 最简
objection -g "com.app" explore
android sslpinning disable

# Frida
frida -U -l ssl_pinning_bypass.js -f com.app
```

### Root / 越狱检测
```javascript
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() { return false; };
    // 额外绕过：Magisk su、frida-server、/proc/self/maps 检测
});
```

### 反调试
- Android：绕过 ptrace(TracerPid)、`/proc/self/status`、`isDebuggerConnected()`
- iOS：绕过 `PT_DENY_ATTACH`、`sysctl CTL_KERN/KERN_PROC/KERN_PROC_PID`

## 三、移动端加密提取

```javascript
// Android — Hook Cipher 获取算法+密钥
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log("[Cipher] Algorithm: " + algo);
        return this.getInstance(algo);
    };
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        console.log("[Cipher] Key: " + Array.from(key.getEncoded()).map(b=>b.toString(16)).join(''));
        return this.init(mode, key);
    };
});

// iOS — Hook CCCrypt
Interceptor.attach(Module.findExportByName("libcommonCrypto.dylib", "CCCrypt"), {
    onEnter: function(args) {
        console.log("CCCrypt op: " + args[0] + " alg: " + args[1]);
    }
});
```

## 四、工具链

| 工具 | 平台 | 用途 |
|---|---|---|
| JADX | A | Java 反编译 |
| apktool | A | APK 解包/重建 |
| Ghidra | A+I | 多架构反编译 |
| Frida | A+I | 动态插桩 |
| Objection | A+I | Frida REPL 增强 |
| MobSF | A+I | 自动化 SAST+DAST |
| class-dump | I | ObjC 类导出 |
| frida-ios-dump | I | IPA 解密 |
| jtool2 | I | Mach-O 分析 |

> A=Android, I=iOS

## 五、验证

- SSL Pinning 绕过后能抓包看到明文
- Root/越狱检测返回 false
- 加密提取拿到算法与密钥，能独立复现
