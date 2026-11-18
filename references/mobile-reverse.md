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

- [ ] SSL Pinning 绕过后能抓包看到明文（Burp/mitmproxy 抓到 HTTPS 明文请求）
- [ ] Root/越狱检测返回 false（目标 App 的 root/jailbreak 检测函数返回 false，不触发拦截）
- [ ] 加密提取拿到算法与密钥，能独立复现（本地脚本生成签名/加密值，与 App 运行时一致）
- [ ] Hook 目标函数后参数与返回值可观测（Frida hook 回调打印参数，确认命中）
- [ ] 重打包/重签名后 App 能正常运行（无签名校验失败、无闪退）

## 五·五、代码骨架：Frida SSL Pinning 绕过

> 可运行的 Frida 骨架，绕过 Android SSL Pinning，使 HTTPS 流量可被代理抓包。

```javascript
// ssl_pinning_bypass.js — Frida 绕过 SSL Pinning 骨架（Android）
// 原理：Hook 证书校验逻辑，将校验回调替换为返回成功

Java.perform(function () {
    // Hook X509TrustManager.checkServerTrusted（最常见的 Pinning 点）
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // 自定义 TrustManager，全部放行
    var TrustManager = Java.registerClass({
        name: "com.example.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function () {},
            checkServerTrusted: function () {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    // Hook SSLContext.init，替换 TrustManager
    var init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );
    init.implementation = function (km, tm, sr) {
        console.log("[ssl-bypass] replacing TrustManager");
        this.init(km, [TrustManager.$new()], sr);
    };

    // 补充：Hook OkHttp/Conscrypt 的证书校验
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    // Hook check 方法，直接放行
});
```

运行：`frida -U -f com.target.app -l ssl_pinning_bypass.js`，配合 Burp 代理。验证：Burp 抓到 HTTPS 明文，App 正常联网。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §二 SSL Pinning 使用

## 六、IPA 分析补充

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

## 七、Frida CLI 完整参考

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

## 八、网络抓包（免代理）

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

## 九、ADB 高级操作

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

## 十、iOS Hook、重签名与风控对抗

> 更新：2026-11-17 · 来源：看雪帖 291522（iOS Hook）、289492（ιldb）、287185（重签名）、293154（iOS 风控）
> 注：本节从 toolchain.md 归位，按治理规则 iOS 技术内容统一在 mobile-reverse 展开。

### 10.1 iOS Hook 四层能力栈

- **①OC 层 Method Swizzling**：`method_exchangeImplementations` 交换 SEL→IMP，Hook OC 消息。
- **②C 层 fishhook**：重绑 Mach-O GOT 外部符号（`__la_symbol_ptr`/`__nl_symbol_ptr`/`__got`/`__auth_got`），不改代码段。局限：只能 Hook 外部符号，static 函数/私有符号无效。
- **③地址层 Inline Hook**：Dobby/litehook 改 ARM64 指令，`b` 跳 ±128MB，超范围用 `adrp+br`。能 Hook 任意地址，需 ARM64 汇编功底，处理 PAC/BTI。
- **④硬件级**：hwbphook（ARM 硬件断点 watchpoint，无痕绕内存校验）、jrmemory（VMMap 改页绕代码签名）。
- **统一框架**：Substrate/libhooker/ElleKit 对三层统一封装。
- **iOS 15 分水岭**：dyld4 用 `LC_DYLD_CHAINED_FIXUPS` 替换 `LC_DYLD_INFO`，符号绑定变自引用链表，只认 `LC_DYLD_INFO` 的工具在 iOS 15+ 解析扑空，现代 fishhook 须遍历 `__LINKEDIT` 链表。
- **PAC 绕过**：ARM64e 下 Inline Hook 需处理 PAC 签名与 BTI。

### 10.2 ιldb LLDB 脚本

`ιldb.py` 放 LLDB 插件目录，`~/.lldbinit` 加 `command script import ***/ιldb.py`。核心命令：`save`（保存历史命令到 cmd_record.json，支持多格式带描述）、`show`（显示命令列表）、`using`（指定模块，后续 mark 基于该模块）、`mark`/`markd`（基于模块偏移/动态地址打断点，支持多地址）、`memread`（读内存）、`process`（启动进程）。命令名可改 `cmd_config.json`，源码在 `ιldb/src/core/lldb_script_handler.py`。

### 10.3 iOS 重签名检测

iOS 强制签名，所有组件必须签名并信任。签名结构 SC_SuperBlob（magic `0xfade0c00`+length+count，内含 CS_BlobIndex 数组）。BlobIndex type 枚举：CODEDIRECTORY_SHA1=0/REQUIREMENTS=2/ENTITLEMENTS=5/DER_ENTITLEMENTS=7/CODEDIRECTORY_SHA256=0x1000/SIGNATURESLOT=0x10000。CodeDirectory 含各段哈希、主可执行摘要、Identifier、Team ID、Entitlements hash；CMS 签名验 CodeDirectory 哈希。重签名检测五项：plist/CodeResources/entitlement/代码段/资源文件篡改。ASN.1 解析 CMS 签名结构。

### 10.4 iOS 风控对抗

四问——环境里有什么（越狱路径/注入目录/环境变量/服务）、进程里改了什么（加载镜像/线程/IMP/导入指针/函数代码）、操作怎样发生（触摸/时间/传感器/业务事件）、结果被谁使用（本地状态/缓存/报告/请求验证）。

核心：**改变的位置是否就是检测器观察的位置；改变有没有传到最终使用结果**。观察主体必须一致（越狱工具能读≠沙盒 App 能读；检测函数执行≠必命中；界面运行≠无风险记录）。

分层对抗：隐藏路径（改系统查询视图）、替换检测返回（改调用者得到的值）、修改输出字段（链路后部）。越狱检测：路径名单是入口、环境对象才是重点（rootless 布局不同，不能机械加 `/var/jb`）。Frida：藏名字≠藏行为，需截断本机协议握手。结果缓存：改检测函数但没改缓存消费路径→下次请求仍带旧记录。

### 验证
iOS Hook：逐层 hook 系统 API 观察行为改变。重签名：篡改任一 slot 后检测脚本报签名异常。风控：每层对抗后确认改动生效范围。

---

## 十一、移动端与本地数据层取证（实战）

### 一、第一判断：我要的东西在**代码层**还是**数据层**

这是本场景最省时间的一个判断，也是最大的认知陷阱。

| 你以为 | 实际 |
|---|---|
| 功能在代码里实现 → 必须 hook/改代码 | 很多功能最终只是**改了一行数据库状态** |
| 加固壳保护了一切 | **壳保护代码，不保护明文数据库** |

真实翻车：IM 防撤回，先按"微信经验"做函数级对抗——hook 收发、hook 渲染、hook UI，三层全部碰壁（壳完整性校验 + 反调试）。最后发现正确做法是 **SQLite 触发器**，10 分钟解决。

> **动手改代码之前，先看数据怎么流。**
> 判据：**这个功能是"状态型"的吗？状态最终落在哪个可写介质上？**（本地 db / 配置文件 / 缓存目录 / Keychain）

### 二、双快照 diff：找"状态型功能"改了什么

```
① 备份目标数据目录（含 -wal / -shm）
② 操作一次（触发/不触发目标行为各一次）
③ 再备份
④ 逐表逐行 diff：只报告差异行 + 差异列
```

`snap_diff.py` 这类脚本 30 行就能写。关键点：

- **必须连 `-wal`、`-shm` 一起备份**，否则最新改动看不到。
- 用 `SELECT * FROM pragma_table_info` 拿列名，不要假设列序。
- 时间戳列会掩盖真实差异 → diff 时排除 `update_time` 之类的列。
- 差异可能不止一处（主表 + 索引表 + 未读计数），**全部要找齐**，漏一个就会出现"撤回没了但红点还在"。

**这一步的收益**：把一个"要不要 hook 加密函数"的开放问题，变成一个"改哪张表哪一行"的封闭问题。

### 三、SQLite 触发器拦截

```sql
CREATE TRIGGER prevent_recall
BEFORE UPDATE OF 类型码 ON 消息表
WHEN NEW.类型码 = 55 AND OLD.类型码 != 55
BEGIN
    SELECT RAISE(IGNORE);
END;
```

**关键细节（容易翻车）**：

| 细节 | 说明 |
|---|---|
| **用 `RAISE(IGNORE)`，不要 `RAISE(ABORT)`** | `ABORT` 会让上层事务抛异常 → 应用层线程（如 gRPC 回调）直接崩；`IGNORE` 静默跳过这一行，行为最接近"什么都没发生" |
| `BEFORE UPDATE OF 列名` | 必须限定列，否则任何更新都触发，性能与副作用不可控 |
| `OLD != NEW` 双条件 | 只判 `NEW=55` 会把"已经是 55 再更新"也拦掉，可能破坏正常流程 |
| 触发器要能被应用识别 | 有些应用启动时 `DROP` 重建表 → 触发器丢失，需要"每次启动后重装"或改应用逻辑 |
| 应用在读缓存 | 触发器只改库，UI 可能读内存缓存 → 需要重启应用生效 |

**验证**：改完后**用原应用**发一条消息再撤回，确认消息还在且不崩；再测正常编辑消息是否受影响（回归）。

### 四、WAL：最新数据不在主库

真实翻车：磁盘 `page1` 与内存明文页逐块比对全部不符，一度怀疑 key 找错。解析 WAL 才明白：**最新页在 `-wal` 里，主库 `page1` 是旧的。**

- 每个页可能在 -wal 里有多个版本 → 取 frame 序号最大的那个
- WAL 头部有 salt，必须与主库 header 的 salt 匹配才有效
- 直接读主库会得到"看起来合理但过时"的数据——这是最危险的错觉

**处理**：1) 优先用 SQLite 自身接口打开（自动合并 WAL）；2) 手工解析时"主库 + WAL 页表"合并，按 `frame number` 取最新；3) `-shm` 是 WAL 的索引，损坏时可丢弃重建。

### 五、SQLCipher 与魔改版

**标准 SQLCipher 页 1 布局（必背）**：

```
偏移 0     .. 16      salt（明文！未加密）
偏移 16    .. 4016    加密的页内容（4096 - 16 - 16）
偏移 4016  .. 4032    IV / 保留（HMAC 或 IV，视版本）
偏移 4032  .. 4096    HMAC-SHA1 或保留
解密后的明文从 SQLite 页头 "SQLite format 3\0" 开始，对应密文的偏移 16
```

> **最经典的偏移错误**：以为明文从密文偏移 0 开始。实际明文与密文错开 16 字节（salt 占位）。

**魔改版的识别特征**：

| 特征 | 含义 |
|---|---|
| **`keyspec_sz = 99`**（或其它异常值） | 自定义 keyspec 结构 → 标准 SQLCipher 库打不开 |
| 有 `sqlcipher_shield` 类符号 | 进程级 mask 保护 |
| `codec_ctx` 结构存在 | 加解密上下文，比 hook `sqlite3_key` 更稳的抓手 |
| KDF 参数非常规（迭代次数/PBKDF2 变体） | 需要从代码里读参数 |

**32 字节进程 mask 的恢复（真实案例配方）**：

```
mask 不是常数，是运行时按进程状态派生的
H = PBKDF2-SHA512(K, salt XOR 0x3a, 2)   // 例：迭代仅 2 次
mask = H 的前 32 字节（或按代码里的切片方式取）
```

**恢复路径（按稳定性排序）**：
1. **结构指针找 `codec_ctx`**：hook 之后 dump 结构体，里面直接有已经派生的 key/mask（4 轮失败后最终走通的路）。
2. hook 解密函数出口，直接拿明文（最省事，但需要能注入）。
3. 静态复现 KDF（最难，参数容易读错）。

> 教训：**先找"已经算好的地方"，再考虑"自己算"。** 即 re-methodology 里的"等 key"降维。

**完整性验证**：`PRAGMA integrity_check` 必须过，否则说明页解密正确但结构拼接错了（常见于 WAL 合并错误）。

### 六、容器内嵌数据（zstd / protobuf / Base64）

| 形态 | 识别 | 处理 |
|---|---|---|
| **zstd** | 魔数 `28 B5 2F FD` | `zstd -d`；注意有的版本带 skippable frame |
| **protobuf** | 无魔数，字段 tag 呈 `0x08/0x12/0x1A` 递进 | 手写序列化可行（不必有 .proto） |
| **Base64 存进 TEXT 列** | 列类型 TEXT 但内容像 base64 | 先 base64 解，再判是否 protobuf/zstd |
| **时间字符串** | `%Y-%m-%dT%H:%M:%S` | **注意末尾没有 `Z`**，多一个字符就解析失败（真实坑） |
| **BLOB 空行** | `LIKE '%...%'` 命中空 blob | 查询时加 `AND typeof(列)='text'` |

**手写 protobuf 的最小知识**：`tag = (field_num << 3) | wire_type`；`wire_type` 0=varint, 2=length-delimited。够用了。

### 七、Android 加固与"流氓/系统类"应用

**加固的层次**：

| 层 | 表现 | 打法 |
|---|---|---|
| **指令抽取壳** | `dex` 里方法体为空，运行时回填 | dump 内存 dex / 主动调用（frida hook `ArtMethod`） |
| **VMP/so 加固** | 关键逻辑在 native | 见 `vm-bytecode.md` |
| **数据层** | db 明文或弱加密 | 直接读（**优先试这条**） |

**先试数据层**：即使代码被加固到无法反编译，只要数据落盘是明文/弱加密，任务就已经完成。

**系统助手/流氓类应用的分析要点**：

| 观察点 | 含义 |
|---|---|
| `AndroidManifest` 权限清单 | 判断它能做什么、想做什么 |
| `BOOT_COMPLETED` 的 `priority=2147483647` | 抢最高优先级的开机广播（异常值就是线索） |
| 延迟 4 分钟发"无动作"广播 | 规避"开机后立即联网"的检测/风控 |
| RSA 信封 + AES-GCM | 混合加密上报；公钥硬编码在包里 |
| **HTTPS 失败降级为明文 HTTP** | 降级路径就是抓包入口（真实案例） |
| 本地 DB 缓存上报队列 | 断网也能攒数据；也是取证入口 |
| `JobScheduler` / 前台服务 / 无障碍 | 保活手段 |

**分析方法**：先画"触发 → 采集 → 加密 → 上报 → 缓存"五段链，再逐段找证据。不要从入口 `main` 开始读。

### 验证

- [ ] 已判定目标在代码层还是数据层，数据层通道（db/配置/缓存/Keychain）已确认
- [ ] 双快照 diff 连 `-wal`/`-shm` 一起备份，差异行/列全部找齐，时间戳列已排除
- [ ] 触发器用 `RAISE(IGNORE)` 且限定列，用**原应用**验证行为且做相邻功能回归
- [ ] WAL 最新页按 frame 序号取，`integrity_check` 通过
- [ ] SQLCipher 明文偏移 16 无误，魔改版按 `keyspec_sz`/`codec_ctx` 指纹识别，mask 优先找"已算好的"结构体
- [ ] 时间字符串格式严格（无多余 `Z`），`LIKE` 查询加 `typeof()='text'` 排除 BLOB 空行

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）
