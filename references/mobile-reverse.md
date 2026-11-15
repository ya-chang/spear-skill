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

## 五、IPA 分析补充

### class-dump 提取 ObjC 头文件
```bash
class-dump -H Payload/App.app/App -o headers/
```

### Cycript 运行时探索
```bash
cycript -p AppName
# 常用表达式
UIApp.keyWindow.rootViewController
```

### Flexdecrypt 解密 App Store 应用
```bash
flexdecrypt /path/to/App
```

## 六、Frida CLI 完整参考

### 环境搭建
```bash
pip install frida-tools objection
# 下载 frida-server 推送到设备
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
```

### CLI 命令
```bash
frida -U -f com.example.app -l script.js --no-pause   # spawn 模式
frida -U com.example.app -l script.js                  # 附加模式
frida-ps -Ua                                            # 列出应用
frida-trace -U -f com.example.app -j "*!*encrypt*"     # Java 方法追踪
frida-trace -U -f com.example.app -i "encrypt"         # Native 函数追踪
frida-discover -U -f com.example.app                    # 自动发现函数
```

### frida-discover（自动函数发现）
黑盒分析：不需要知道函数名，自动探测可 Hook 的函数，输出 CSV 格式函数列表，用于后续精确 Hook。

### Stalker（指令级跟踪）
```javascript
// 指令级别跟踪目标函数，适用于分析混淆后的加密逻辑
Interceptor.attach(Module.findExportByName("lib.so", "target"), {
    onEnter(args) {
        Stalker.follow(this.threadId, {
            events: { call: true, ret: true },
            onCallSummary(summary) { console.log(JSON.stringify(summary)); }
        });
    },
    onLeave(retval) {
        Stalker.unfollow(this.threadId);
        Stalker.garbageCollect();
    }
});
```

## 七、网络抓包（免代理）

| 工具 | 原理 | Root | 特点 |
|---|---|---|---|
| **R0capture** | Frida 绕 SSL 抓明文 | 需要 | 免代理，输出 pcap |
| **PCAPdroid** | VPN 模式抓包 | 不需要 | Android App |
| **HttpCanary** | VPN 模式 HTTP(S) | 不需要 | 图形化 |
| **tcpdump** | 底层抓包 | 需要 | 命令行 |

```bash
# R0capture
frida -U -f com.target.app -l r0capture.js --no-pause -o capture.pcap

# 设备端 tcpdump
adb push tcpdump /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/tcpdump
adb shell su -c "/data/local/tmp/tcpdump -i any -w /sdcard/cap.pcap"
adb pull /sdcard/cap.pcap
```

## 八、ADB 高级操作

```bash
# 信息收集
adb shell dumpsys package com.target.app | head -50
adb shell dumpsys activity com.target.app
adb shell cat /data/data/com.target.app/shared_prefs/*.xml
adb shell sqlite3 /data/data/com.target.app/databases/app.db "SELECT * FROM users"

# 启动组件
adb shell am start -n com.target.app/.MainActivity
adb shell am start -a android.intent.action.VIEW -d "https://example.com"
adb shell am broadcast -a com.target.app.CUSTOM_ACTION

# 备份提取
adb backup -apk com.target.app -all -f backup.ab
# 解包 backup.ab（需 abe 工具）
```
