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
