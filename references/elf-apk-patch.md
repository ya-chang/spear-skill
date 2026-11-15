# ELF / APK 本地 patch 与壳脱修（elf-apk-patch）

目标：对自持/授权范围内的 APK、ELF 做本地授权替换、卡密校验替换、APK 资源/ELF 补丁、AArch64 分支 patch、loader/memfd 执行链恢复、APK 重签名与真机验证。**只改目标校验，保留登录/授权/网络等正常业务路径。**

## 一、核心原则

1. **原样本只读**，所有修改在副本上做，每个产物记 SHA-256，保留回滚。
2. **最小 patch**：只改目标校验/授权分支，不改其他逻辑。
3. **保持可执行**：patch 后必须验证能跑，不拿"能解析"冒充"能运行"。
4. **overlay 与注入分清**：判断改动是文件内 overlay 还是运行时注入，分别处理。

## 二、ELF 本地授权 patch

### 1. 定位校验点
```bash
# 找硬编码比较、授权检查字符串
strings -a target | grep -iE "license|register|activate|授权|注册|激活|key"
# 找比较函数热点
ltrace -e strcmp,memcmp ./target
r2 -q -c 'axt @ <string_addr>' target
```

### 2. AArch64 分支 patch
常见：校验失败走 `b.ne`/`cbz` 跳到错误分支。把条件跳转改成无条件跳过成功路径，或直接把失败分支改成 `nop`。

```bash
# 用 r2 写 patch（示例：把 b.ne 改成 nop）
r2 -w -q -c 'wa nop @ 0xADDR' target
# 或用 capstone + 手动写字节
```

```python
# patch 脚本骨架（capstone）
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
# 反汇编定位目标指令，写入 PATCH_BYTE，记录 OFFSET
```

**记录**：`OFFSET` + `PATCH_BYTE` + 原始字节，用于回滚。

### 3. payload-trailer 保留
很多 ELF 在文件尾部有 payload/overlay，patch 时**不要截断或破坏 trailer**，只改目标指令字节。

## 三、Android APK 补丁与重签名

### 1. 解包
```bash
apktool d target.apk -o work/decoded
# 或 baksmali 改 smali
```

### 2. 改 smali / 资源
- 改校验逻辑：定位 smali 中的校验方法，patch 返回值（`const/4 v0, 0x1` 等）。
- 改资源：替换图片/配置，注意资源 ID 与 `resources.arsc` 一致性。

### 3. 重打包签名
```bash
apktool b work/decoded -o dist/patched.apk
zipalign -p 4 dist/patched.apk dist/aligned.apk
apksigner sign --ks dist/release.keystore --ks-key-alias release \
  --out dist/signed.apk dist/aligned.apk
apksigner verify dist/signed.apk
```

## 四、loader / memfd 执行链恢复

部分 ELF 通过 loader 或 memfd 加载真实 payload。恢复要点：
- 找真实入口：从 PHDR 证据推导，不猜固定偏移。
- 解码 XOR 运行时解密器，恢复 XOR 范围/key。
- 重建运行时镜像（参考 `unpacking.md` 动态 dump）。

## 五、影安壳脱修（APK 壳）

特征：小 `classes.dex`、`v.m.p`/`abcd655xx`、`libabcd.so`、`lib*_shellservice_dex.so`、`assets/lib*Protect*`、运行时才 materialize 真实 DEX。

流程：
1. **冻结基线**：哈希原 APK，记录包名/版本/启动行为/日志。
2. **静态盘点**：扫描壳特征，分类壳类型。
3. **抓运行时 DEX**：Frida 抓运行时 materialize 的 DEX（见 `unpacking.md` 的 DEX 捕获脚本）。
4. **校验 DEX 集**：校验 header/size/SHA-1/Adler-32/map bounds/重复类。
5. **恢复组件图**：把 manifest Application/组件映射到恢复的 DEX 集，确认真实 Application 和路由。
6. **声明式计划**：生成 recovery-plan，作为唯一允许改 APK 的输入。
7. **构建兼容版**：先做兼容构建（只替换 classes*.dex、批准的 manifest 名、计划删除项），保留未知 so/资源/ZIP 项。
8. **验证**：v2/v3 签名验证、有效 DEX 头、干净 ZIP、三次冷启动、存活 PID、预期路由、UI dump、无致命日志。

**关键**：登录/授权/网络/后端行为保持不变；产品级免费/无卡配置在源码和服务端做，不在恢复的 APK 里改这些路径。

## 六、验证矩阵

- 签名验证通过（v2/v3）
- DEX/ELF 头有效
- 三次冷启动存活
- 预期业务路由可达
- 无致命日志
- patch 字节级差异仅在目标处

## 附：Ash-12 类 ELF 特化处理

当遇到 Ash-12 类 Android AArch64 ELF 样本时（文件扩展名像 `.sh` 但实际是 ELF64 PIE，尾部附加加密 payload/trailer，通过 memfd 执行链加载 payload），按以下分支处理。

### 适用信号
同时出现多项时进入本分支：
- 文件扩展名像 `.sh`，但 `file`/`readelf` 显示为 Android AArch64 ELF64 ET_DYN/PIE
- 外层 ELF 通过 `/proc/self/exe` 自读，尾部有固定 magic、payload offset、payload size
- 外层含远程卡密/授权字段（`kami`/`markcode`/`sign`/`code`/`time`/`vip`）
- 成功路径写 `/data/local/tmp/card`，解密 payload 后经 `memfd_create`/`/proc/self/fd/%d` 执行

### 阶段流程
1. **基线盘点**：记录 SHA256、文件大小、entry、program headers。原文件只读。
2. **trailer 与 payload 范围恢复**：从文件尾部解析容器 trailer（0x28 字节：magic/payload_offset/payload_size/duplicate_offset/reserved）。验证 `payload_offset + payload_size == trailer_offset`，payload+trailer 是不可破坏区域，patch 只允许在外层 loader 代码段。
3. **外层字符串与 payload 解密复现**：定位字符串解密函数、cipher blob，复现 payload key 派生和 RC4 KSA/PRGA。解密后验证 ELF magic(`7f454c46`)、架构、大小、SHA256。
4. **外层授权链定位**：从成功/失败提示、`/data/local/tmp/card`、`/proc/self/exe`、`memfd` 字符串反向找 main/dispatch。patch 点选"远程授权返回后、失败分支之前"的最小门控点，保留 argv/card 写入与 payload 执行链。不以"跳到退出/return"为成功路径。
5. **等长 patch**：expected bytes 完全匹配，patch 等长，输出新文件绝不覆盖原文件。ELF header、program headers、entry、file size、payload、trailer 全部 unchanged。
6. **patch 后重提取验证**：trailer 仍通过 magic/range/size 检查，解密 payload SHA256 与 patch 前一致。
7. **真机动态验证**：用新鲜证据（stdout/stderr/RC/logcat），不用过往记忆。无真机证据时标 `[DYNAMIC_UNVERIFIED]`。

### 回滚条件
expected bytes 不匹配、VA 无法映射 PT_LOAD、patch 导致 header/phdr/entry/size 变化、payload/trailer 任一字节变化、patch 后无法重提取相同 payload → 立即停止回滚。

### 交付补充
```
Container: magic / payload_offset / payload_size / trailer_offset / checks
Payload: encrypted SHA256 / decrypted SHA256 / decrypted ELF info
Outer auth gate: auth function / main dispatch / patch VA+FileOff+old+new / disasm
Boundary: STATIC_VERIFY_OK or FAIL / DYNAMIC_VERIFY_OK/FAIL/UNVERIFIED
```

## 最稳 patch 点选择（详细）

**核心原则：** 选择"远端授权请求返回之后、响应解析或失败分支之前"的最小位置。

### 比较函数语义与回跳目标判定
改写 `isVip`/`vip`/`code` 分支前，必须反汇编比较包装函数，建立 `equal`/`not equal`/零值/非零值真值表。不能按函数名或 `true` 字符串猜测返回语义（比较包装层可能返回 `1 & ~equal`）。

对每个候选分支记录：比较结果寄存器、条件指令、跳转目标、落空块、以及二者各自的析构/资源检查/功能 UI/主菜单返回行为。只有跳转目标已证实为授权失败清理，且落空块进入原有功能链时，才允许将 `tbnz`/`cbnz` 改为 `nop`。

### 字段分层
当响应同时含 `token`/`endTime` 等成功状态字段和 `vip`/`isVip`/`code` 等判定字段时：
```
传输/协议错误（connect/HTTP/Error）→ 保留失败处理，不作为 patch 点
状态字段（token/endTime/cache）     → 必须先完成解析，保留原 success_init 写入
判定字段（vip/isVip/code）           → 只改其后的唯一条件分支，跳原 success_init
充值/卡密回退（recharge/card input） → 仅失败路径，不伪造返回值替代状态初始化
```

### 成功路径选择
```
跳 success_init ：优先，保留后续初始化
跳 success_tail ：高风险，可能漏初始化导致 SIGSEGV
跳 main exit/return：通常错误，破坏 payload/driver/功能链
改 ELF header/entry：常规禁止
```

### AArch64 patch 模板
```asm
// 条件失败分支改无条件成功
b success_init
// 清空失败跳转
nop
// 本地测试时间戳 + 跳转
movz x0, #LOW16
movk x0, #HIGH16, lsl #16
b success_init
```

### 失败处理与回滚
遇到以下情况停止并回滚：expected bytes 不匹配、VA 无法映射 PT_LOAD、patch 不等长、ELF Header/Program Headers/entry 改变、payload magic/offset/size 改变、APK 签名验证失败、成功路径依赖寄存器/栈变量无法确认、真机 SIGSEGV 且无法定位 success_init。

### 输出格式
```
Patch 点: VA=<addr> FileOffset=<offset> OldBytes=<hex> NewBytes=<hex> Disasm=<expected asm>
原始 SHA256: ...
Patch SHA256: ...
验证: VERIFY_OK / VERIFY_FAIL
已验证项: [ ] expected bytes match [ ] ELF header unchanged [ ] Program Headers unchanged [ ] entry point unchanged
```

## 硬约束（优先级最高，任何增强都不能覆盖）
```
[ ] 不破坏 ELF Header / Program Headers
[ ] 不改 entry point（除非明确要求且完整验证）
[ ] 优先等长 in-place patch，不改变文件大小
[ ] 不破坏 appended payload / magic / size trailer
[ ] 不改 payload 区域（除非明确要求）
[ ] APK 替换 assets 后删除旧 META-INF、zipalign、apksigner verify
[ ] patch 前 expected bytes 必须完全匹配
[ ] patch 后验证 header、phdr、tail、hash、反汇编、运行行为
[ ] 结论来自实际读取、反汇编、日志或真机检查
```

## 功能链卡点决策树
```
前端显示长期授权，但 ELF 报"卡密不存在" → 只 patch 了 UI/Java，回到 ELF 授权入口
授权过了但 SIGSEGV → 跳过 success_init，改跳更早成功初始化块，恢复寄存器/栈变量
输出"窗口化本程序/等待游戏启动"但无后续 → 授权已过，查目标包名、argv[1]、pidof、cmdline
pidof 有 PID 但 ELF 找不到 → 检查扫描逻辑、多进程、cmdline 匹配
游戏已启动但 UE4 超时 → 查 /proc/<pid>/maps、模块名/加载时机/等待时长
UE4 找到但进程不可访问或注入失败 → 查 root 上下文、SELinux、/proc/<pid>/mem 权限、pwrite 返回值
注入成功但功能无效 → 功能链跑通，查目标版本偏移、基址计算、写入字节、开关参数
```

## 悬浮窗/driver/纯内存注入判定
不要把"没看到悬浮窗/刷入动画"直接判为 ELF 失败。分类：
- **WebView 配置前端**：assets/index.html + JS Bridge，只负责配置
- **Java 状态提示窗**：WindowManager + TextView，只显示启动/完成提示
- **游戏内功能菜单**：Canvas/SurfaceView/GLSurfaceView/Overlay Service/native draw loop
- **纯内存注入**：root 打开 /proc/<pid>/mem，按模块基址写补丁
- **driver 链**：insmod/modprobe、.ko、/dev/*、sysfs/procfs、Magisk/KernelSU、ioctl

静态搜索关键词：`SYSTEM_ALERT_WINDOW WindowManager TYPE_APPLICATION_OVERLAY`、`/proc/%d/mem pwrite process_vm_writev ptrace libUE4.so`、`insmod modprobe .ko ioctl magisk ksu`

## APK 双载荷门控样本通杀
**典型特征：** assets/bin/ 下至少两个高价值文件：
- **gate ELF**：AArch64 ET_DYN，负责卡密/公告/时间/vip 判断，再执行后续 payload
- **driver 入口**：文件头可能像 shell，自解压后执行内核/驱动/写内存链

**Java/Kotlin 层：** WebView + JavascriptInterface/Bridge、saveConfig、flashDriver、startModule
**native gate 字符串：** kami/markcode/sign/code/time/vip/msg/gg/app_gg
**关键：** UI 状态文本不等同于 native 授权真实通过。

## 影安壳脱修（详细补充）

### 壳族特征信号（多信号交叉确认）
至少两层信号一致才走壳脱修路线，单个字符串/文件名可能出现在无关产品。

| 层 | 信号 |
|---|---|
| Root DEX | 类极少、`strEntryApplication`、`startApp`、`abcd655xx`、`abcdstr`、`System.load`、`System.exit`、反射加载类 |
| Native | `libabcd.so`、`lib*_shellservice_dex.so`、ZIP 形 `.so` 内含 DEX |
| Assets | `assets/lib*Protect*`、`abcd/`、无正常资源角色的加密块 |
| 运行时 | 匿名/读写映射中的 DEX magic、Application/Activity 延迟可见、重打包后 JNI 注册失败 |
| 路由 | 正常外层 UI 经 About/版本/导航路径启动内部真实 Activity |

**证据优先级（高 → 低）：**
1. 原进程运行时 DEX 与 top-activity 证据
2. Manifest 与组件对 DEX 集的解析
3. 原进程日志
4. 静态内层 ZIP/ELF payload
5. Root-Dex 字符串与命名模式

绝不在已有高优先级观测时，凭低优先级信号做破坏性选择。

### 生命周期桥接规则（仅在有证明时修复）
工具只支持原生、非静态、void 的 Android 生命周期包装。写入的标准 Smali 体：

```smali
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 0

    invoke-super/range {p0 .. p1}, Lcom/example/MainActivityCore;->onCreate(Landroid/os/Bundle;)V

    return-void
.end method
```

**使用前必须证明全部条件：**
1. 包装是 manifest 可达或运行时可达的 Android 组件
2. 方法无代码且标记为 `native`
3. 提供的 `*Core` 类是包装的直接父类
4. 核心类有确切的生命周期方法且实现是具体的
5. 原应用与首个兼容构建把该回调识别为缺失注册边界
6. 重建 DEX 校验与完整设备冒烟矩阵通过

**工具不处理：** 非 void 回调、任意业务方法、构造函数、静态方法、原生 API 替换。这些需要源码级恢复或样本特定的、单独评审的实现。

### 恢复计划 Schema（声明式、哈希绑定）
`yingan-recovery-plan/v1` 是唯一允许修改 APK 的构建输入。构建器拒绝已变更的源 APK 或 DEX。

```json
{
  "schema": "yingan-recovery-plan/v1",
  "source": {"apk": "C:/work/original.apk", "sha256": "..."},
  "dex": {
    "root": {"path": "C:/work/root-managed.dex", "sha256": "..."},
    "runtime": [{"order": 0, "path": "C:/work/dex_000.dex", "sha256": "..."}]
  },
  "manifest": {
    "application": "com.example.RealApplication",
    "application_selection": "explicit",
    "components": [{"element": "activity", "from": "com.example.ShellActivity", "to": "com.example.RealActivity"}]
  },
  "packaging": {
    "mode": "compatibility",
    "preserve_all_non_dex_entries": true,
    "remove_entries": []
  },
  "verification": {"package": "com.example.app", "launch_activity": "com.example.app/.MainActivity"}
}
```

**规则：**
- 用工具生成的绝对路径与 SHA-256 值
- 首次构建保持 `remove_entries` 为空
- 每个组件替换必须用左侧确切的当前 manifest `android:name` 值
- root DEX 可选；省略时第一个运行时 DEX 成为 `classes.dex`
- 不得用计划改动授权、凭证或服务行为

### RikkaHub 恢复经验（证据，非补丁档案）

**有效做法：**
1. 原 root `classes.dex` 视为壳控制层：类定义极少、壳回调、受保护资源、原生加载证据
2. 改动 APK 前先运行原进程，匿名运行时 DEX 镜像成为事实来源，校验后恢复 76,839 个唯一类
3. 选择真实应用/入口前，先关联 manifest 组件与运行时类定义，暴露正常外层路由与经设置/关于/版本导航到达的隐藏内部 Activity
4. 首个可用构建用完整托管 multidex 恢复，保留不确定的原生/资源，不先剥离所有保护文件
5. 生命周期失败仅在证明无代码原生包装有具体 `*Core` 直接父类且有匹配生命周期方法后修复，委托给该父类而非打桩业务 API
6. 完成证据含 APK 签名验证、干净安装、进程/top-activity 检查、外层与内部路由 UI 证据、logcat 审查

**通用规则：**
- 运行时加载顺序与类可达性胜过静态文件名猜测
- 用哈希绑定计划防止陈旧 DEX 捕获导致意外重建
- 兼容构建保留未知条目；壳清理是后续独立测试的变更
- 只替换被证明是壳边界的层：manifest 路由、root 委托或生命周期桥。避免大范围原生变异
- 把每个致命信号、`JNI_ERR`、`ClassNotFoundException`、`VerifyError`、缺失原生实现当作路由选择信号，而非盲目 patch 分支的邀请
- 产品认证、授权、远程协议行为保持在恢复机制之外

**剩余诊断规则：**
成功签名的 APK 仍可能因设备特定的原生路径失败。例如 MediaCodec/SoundDecoder SIGSEGV 是真实冒烟失败，即使 ZIP、DEX、manifest、签名都有效。保留设备日志、PID/Activity 证据、架构/Android 版本细节，并在归因此类失败到恢复计划前，对照原应用复现。

### 验证矩阵（按序跑门，首个失败即停并保留证据）

| 门 | 必需证据 | 常见诊断 |
|---|---|---|
| ZIP | `zipfile.testzip` 干净，无重复关键条目 | 重打包损坏或陈旧签名 |
| DEX | 头、文件大小、map 边界、SHA-1/Adler-32 报告 | 捕获截断或 Smali 重建损坏 |
| Manifest | Application/组件解析并对输出 DEX 解析 | Application 错、缺 DEX、AXML 编辑错 |
| 签名 | `apksigner verify --verbose --print-certs` 通过 | keystore/签名顺序错 |
| 安装 | 包管理器接受 APK | 签名不匹配；仅在可接受数据丢失时用显式干净安装 |
| 冷启动 | 三次强制停止启动后 PID 存活 | 入口/生命周期/类加载器失败 |
| 路由 | 预期 Activity 出现且返回导航正常 | 组件映射错或隐藏路由假设错 |
| 日志 | 无 `FATAL EXCEPTION`、`JNI_ERR`、`ClassNotFoundException`、`VerifyError`、`UnsatisfiedLinkError`、`No implementation found`、致命信号 | 回到最小兼容计划 |
| 产品冒烟 | 所有者定义的正常导航/功能可用 | 保留壳资源或包含遗漏的运行时 DEX/资源 |

**`JNI_ERR` 处理：** 不要反复 patch 原生分支。从最后一个有效兼容计划重建，保留未知壳产物，走托管运行时 DEX 路径。
**`ClassNotFoundException` 处理：** 把未解析类对照校验/图报告，加入缺失的观测到的运行时 DEX，而非猜测依赖。

## 附：Linker 假加载脱壳详细原理

### 保护模型
该类保护在合法外观的 Android AArch64 ELF 中，于文件偏移 0 放一个假 `PT_LOAD`，带高虚拟地址和不可能的文件大小。入口点据此选择：

```text
true_file_entry = e_entry - fake_load.p_vaddr + fake_load.p_offset
```

示例：
```text
fake p_vaddr = 0xffff0000
fake p_filesz = 0x100000000
e_entry      = 0x1006313a8
true offset  = 0x6413a8
```
这让信任正常段大小或节头的工具出错，而 Android/linker/运行时代码仍能到达目标 stub 逻辑。

### 为何节分析不可靠
有用映射编码在 PHDR 和运行时行为中。节头可能缺失、损坏、误导或无关。始终从 `e_phoff`、`e_phnum`、`PT_LOAD`、`e_entry` 开始。

### Stub 解密模式
入口 stub 通常执行少量 XOR 解密调用。成熟样本中：
- XOR key 为 `0xA2`
- stub 通过字面量加载加载大小和目标
- 调用解密若干正常 LOAD 支撑的文件范围
- XOR 应用后，重建运行时含内嵌 bash/lua/python ELF 镜像

通用检测器应跟踪：
- 赋给参数寄存器的立即字节（观测 ABI 中为 `w3`/`x3`）
- 字面量加载的大小和目标（观测为 `x1`/`x2`）
- 这些值存活后的 `bl` 调用点
- 通过非假 LOAD 的 VA 到文件偏移转换

### 动态回退
静态恢复可能失败（保护改变寄存器分配、动态计算范围、隐藏密钥生成、加反反汇编垃圾）。此时用设备证据：
- dump 可执行文件支撑的运行时映射
- dump 匿名 `rwxp` 或 memfd 映射
- 比较映射 offset/vaddr 与 PHDR 推导期望
- 运行时派生子解释器时，dump 子进程树

不要依赖单一规则（如「只 dump 匿名 rwxp」）。部分变体把解密运行时映射为文件支撑映射；只用匿名 `00:00:0` 判据会漏证据。

### 内嵌 ELF 解释
恢复的运行时可能不是最终业务 payload，可含解释器：bash、lua、python、modified-UPX 式二进制。真实 shell 源码可能只在解释器执行并存入栈/堆后才出现。因此 linker 脱壳后继续运行时明文恢复，不停在重建的运行时镜像。

### 工具期望（`linker_static_unwrap.py` 保守路径）
1. 解析 ELF64 AArch64
2. 按属性（非偏移常量）定位假 LOAD
3. 转换入口
4. 用 Capstone 反汇编
5. 恢复 XOR 范围
6. 应用 XOR
7. 雕刻内嵌 ELF 候选
8. 写 JSON 报告

静态 stub 恢复需 `capstone`；不可用时先装或转动态 dump，不静默编造范围。

### 报告模板
```text
sample: <path>
sha256: <hash>
arch: AArch64 ELF64
fake_load: index=<n>, p_offset=<>, p_vaddr=<>, p_filesz=<>
e_entry: <va>
true_entry_file_offset: <off>
xor_ranges:
  - call_va=<>, target_va=<>, target_off=<>, size=<>, key=<>
runtime_image: <path>, sha256=<hash>
embedded_elfs:
  - offset=<>, size=<>, sha256=<>, notes=<bash/lua/python/upx-like>
dynamic_crosscheck: <dump path/hash or not run>
next_stage: <plaintext/memfd/stack action>
closed_state: <closed|needs dynamic fallback|optional补证>
```

### 常见失败模式
- 把 `.sh` 当 shell，完全漏掉 ELF
- 从节头而非 PHDR 假映射算入口
- 只 dump 匿名映射，漏文件支撑的解密运行时
- 停在官方 UPX 失败
- 无 fakebin/副作用控制就调 stage installer
- 因缺可选 APK 元数据就把分析标「未闭合」，实际 loader/运行时链已完整

## 附：ELF 本地授权 patch 工具与标准流程（补充）

### 成品工具优先（xg_elf_tool.py）
本技能自带工具，覆盖 ELF 解析、VA→offset、expected-bytes patch、APK entry 替换、关键词分类、adb 证据采集。复杂汇编生成配合 keystone/capstone/IDA/r2。

```bash
python xg_elf_tool.py --help
python xg_elf_tool.py apk-inventory target.apk --json-out _analysis/apk_inventory.json
python xg_elf_tool.py elf-info payload.elf --json-out _analysis/elf_info.json
python xg_elf_tool.py va2off payload.elf 0x10169a4
python xg_elf_tool.py patch-bytes --input payload.elf --output payload.patched.elf \
  --va 0x10169a4 --expected-hex 11f7ff97 --patch-hex f8000014 --report _analysis/patch_report.json
python xg_elf_tool.py apk-replace-entry --apk in.apk --entry assets/bin/huazai.dat \
  --replacement huazai.patched.dat --out unsigned.apk
python xg_elf_tool.py scan-text _analysis/dex_classes --json-out _analysis/signal_scan.json
python xg_elf_tool.py device-probe --app com.example.app --target com.example.game \
  --out-dir _analysis/device_verify
```

### 标准产物目录（每次分析都创建可复核产物）
```text
_analysis/
  apk_unzipped/
  dex_classes/
  strings/
  payload_unpacked.elf
  elf_info.json
  patch_report.json
  signal_scan.json
  device_verify/
  dist/
```

保存原始 hash：
```bash
sha256sum target.apk payload.elf
```

### APK 盘点与真实启动链恢复
先分析 APK，不要直接运行 assets 里的 ELF 下结论。

APK 重点：
```text
AndroidManifest.xml
classes.dex / split dex
assets/bin/*
assets/*.html / JS Bridge
lib/*/*.so
META-INF/
```

搜索 Java/Kotlin 调用链：
```text
Runtime.exec ProcessBuilder su -c sh -c chmod codeCacheDir filesDir
getAssets openRawResource assets/bin
BufferedReader InputStreamReader stdout stderr stdin
export getenv HUAZAI_KAMI INNER_KAMI
cat | /proc/self/fd memfd_create fexecve execveat execv
```

**典型 2.0 真实模型：**
```text
WebView/Activity/JS Bridge
  -> 保存 config
  -> 读取卡密和功能开关
  -> 解密 assets/bin/xxx.dat
  -> 释放 assets/bin/st 到 codeCacheDir/.st
  -> chmod 700/755
  -> su shell: export KEY=... && cat | .st argv...
  -> st 从 stdin 读 payload ELF
  -> memfd_create / fexec / execveat
  -> payload ELF 执行授权和后续功能链
```

如果直接运行 ELF 无输出、崩溃或行为不对，优先检查 env、argv、stdin payload、root shell、工作目录和 loader。

### 授权流程识别
同时从 dex 与 ELF 搜索：
```text
kami card key license vip code time expire markcode sign token
http https POST GET Content-Type JSON code==200 vip>=1
auth login notice server
验证成功 验证失败 卡密不存在 到期时间 授权成功
payload driver memfd exec /proc/self/fd
```

**逆向推进顺序：**
```text
失败字符串 xref       -> auth_fail
成功字符串 xref       -> auth_success / success_init
网络请求/JSON xref    -> request/parse/check
argv/env/config xref   -> 参数初始化
payload/driver xref    -> 成功后的功能链
/proc/maps/mem xref    -> 注入链
```

**优先命名函数：**
```text
main_or_dispatch
auth_request
auth_parse_response
auth_fail
auth_success_init
parse_argv_or_config
loader_or_memfd_exec
find_target_pid
find_module_base
write_target_memory
run_feature_chain
```

### 最稳 patch 点选择（补充：状态生产型判定门）
1.0 的核心成功模型必须保留：选择"远端授权请求返回之后、响应解析或失败分支之前"的最小位置。

**状态生产型判定门：** 成功路径必须由状态生产动作驱动（写 context/cache/expiry），不能只跳函数尾。若成功块依赖保存寄存器或栈对象，跳转必须落在保存动作之后。

**字段分层（响应同时含成功状态字段与判定字段时）：**
```text
传输/协议错误（connect、HTTP、Error） -> 保留失败处理，不作为 patch 点
状态字段（token、endTime、cache）    -> 必须先完成解析，且保留原 success_init 写入
判定字段（vip、isVip、code）          -> 只改其后的唯一条件分支，跳原 success_init
充值/卡密回退（recharge、card input） -> 仅是失败路径；不要伪造其返回值替代状态初始化
```

**确认模式的证据链：** 调用方收到成功返回后是否继续执行功能链；成功块是否写 context/cache/expiry；失败块是否进入卡密输入或充值接口；跳转目标是否支配这些状态写入。

**付费功能/子菜单追踪：** 不能因为入口认证已 patch 就停止追踪。枚举该功能函数及其直接子调用中的全部 `request -> parse(vip/code) -> compare -> conditional exit` 链；每个判定门都单独记录 VA、expected bytes、失败目标和成功续接块。仅 patch 已确认会直接清理并返回上层菜单的授权分支，保留请求失败、协议异常、资源释放和非授权业务错误分支。
