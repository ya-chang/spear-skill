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
