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
