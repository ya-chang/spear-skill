---
name: spear
description: >
  长枪 spear — 一体化逆向工程与渗透测试技能。整合脱壳、反调试绕过、去混淆、
  VM/字节码逆向、二进制保护绕过、.NET 逆向、Linux 动态分析、Hikari/OLLVM 明文恢复、
  ELF/APK 本地 patch、影安壳脱修、内存外挂与渗透打点全链路。当用户提到逆向、反编译、
  脱壳、去混淆、反调试、VM 字节码、注册机/keygen、激活绕过、内存修改、外挂、DLL 注入、
  Frida、IDA/Ghidra/r2、PE/ELF/APK/SO 分析、抓包协议、渗透、打点、漏洞利用、CTF 时使用。
  先读 references/ 下对应 playbook 再执行，不要凭空臆造步骤。
---

# 长枪 spear · 一体化逆向渗透技能

一套把「逆向破解」和「渗透打点」打通的技能。**核心原则：证据驱动，先定位再动手，每步可验证、可回滚。**

## 一、总路由（先按场景选 playbook）

| 场景 | 读哪个 reference |
|---|---|
| 不知道从哪下手 / 通用流程 | `references/re-methodology.md` |
| 环境没工具 / 要装工具链 | `references/toolchain.md` |
| 程序被加壳（UPX/商业壳） | `references/unpacking.md` |
| 有反调试，调试器被拒 | `references/anti-debug.md` |
| 控制流平坦化/字符串加密/混淆 | `references/deobfuscation.md` |
| 自定义 VM/字节码保护 | `references/vm-bytecode.md` |
| 打 pwn / 绕过 ASLR·PIE·NX·canary | `references/binary-protection.md` |
| .NET / ConfuserEx 逆向 | `references/dotnet.md` |
| Linux 下 GDB/r2/Frida/angr 协同 | `references/linux-dynamic.md` |
| Hikari/OLLVM AArch64 明文恢复 | `references/hikari-deobfuscation.md` |
| ELF/APK 本地 patch、linker 假加载脱壳、影安壳 | `references/elf-apk-patch.md` |
| 游戏外挂/内存读写/注入/协议 | `references/game-cheat.md` |
| 网站/API/内网渗透打点 | `references/pentest-playbook.md` |
| 完整破解链路（脱壳→反调试→VM→去混淆→keygen/patch） | `references/crack-workflow.md` |

跨多环节时按顺序依次读对应 reference，例如：先 `unpacking` → 再 `anti-debug` → 再 `vm-bytecode` → 最后 `deobfuscation`。

## 二、通用工作流（所有任务都遵循）

```
0. 建档基线   哈希原样本，记录文件类型/架构/编译器/安全标志，保留原始副本
   ↓
1. 识别       判断保护类型：加壳？反调试？混淆？VM？哪一类优先
   ↓
2. 剥离       按 外层→内层 顺序处理：脱壳 → 反调试 → 字符串 → 控制流 → VM
   ↓
3. 定位       找到 CHECK_FN / 校验函数 / 加密算法 / 签名入口
   ↓
4. 还原       还原算法、还原数据结构、还原协议
   ↓
5. 交付       打补丁 / 写注册机 / 重建可运行镜像 / 输出利用
   ↓
6. 验证       字节级等价 + 行为回归 + 真机/多输入验证
```

**处理顺序铁律（多种保护叠加时，外层到内层）：**
1. 加壳 → 先脱壳
2. 反调试 → 先绕过
3. 字符串加密 → 先提取（降低后续分析噪声）
4. 虚假控制流 → 清理 CFG
5. OLLVM 平坦化 → 恢复真实控制流
6. 间接调用混淆 → 解析调用目标
7. VM 保护 → 最后处理（成本最高）

## 三、核心原则

1. **原样本只读**：所有修改在副本上做，每个产物记 SHA-256，保留回滚。
2. **证据优先**：用运行时行为、抓包、内存快照定事实，不靠类名/注释臆测。
3. **两层确认**：关键结论至少两个独立工具交叉验证（GDB+Frida、strace+ltrace），才标注为已确认。
4. **不硬编码**：地址、偏移、密钥都要从样本推导，禁止照搬示例值。
5. **可运行优先**：交付的镜像/补丁要验证能跑，别拿"能解析"冒充"能运行"。
6. **不破坏业务**：patch 只改目标校验，保留登录/授权/网络等正常路径。

## 四、最小工具链（详见 references/toolchain.md）

- **静态**：`file` `readelf`/`pefile` `objdump` `nm` `strings` `rabin2`(r2) `capstone`
- **动态**：`gdb`(+pwndbg/gef) `frida` `strace` `ltrace` `perf`
- **符号执行**：`angr`
- **脱壳**：`upx`、自写 dump 脚本
- **Android**：`adb` `apktool`/`baksmali` `apksigner` `zipalign` `frida`
- **.NET**：`dnSpy`（或 ILSpy）
- 缺什么按 `references/toolchain.md` 的 apt/pip 命令补。

## 五、交付标准

- 破解类：能复现校验通过，给出 patch 字节/注册机算法，附验证命令。
- 脱壳/重建类：给出可运行产物 + 哈希 + 行为等价证据。
- 渗透类：给出可复现的 exploit/PoC + 影响面说明。
- 不允许用"安装成功"冒充"任务完成"。
