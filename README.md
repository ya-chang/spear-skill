# 长枪 spear · 一体化逆向渗透技能

由四个技能包整合而成，把「逆向破解」和「渗透打点」打通的一体化技能。

## 整合来源

| 原技能包 | 贡献内容 |
|---|---|
| 无敌逆向渗透skills | asm-analysis、Hikari/OLLVM 明文恢复、ELF/APK 本地 patch、影安壳脱修、外挂/逆向、CTF 编排、渗透 playbook |
| 逆向破解-精选技能包 | 去混淆、VM 字节码、反调试、UPX 脱壳、通用方法论、二进制保护、dotnet 逆向的提示词级 playbook |
| 逆向破解技能包 | 标准 SKILL.md 结构的 7 个子技能（聚合路由） |
| 逆向破解精选技能包 | 上述 7 个子技能的裸文件 |

整合原则：**只保留能用、有用的部分**，去重、补全、按统一工作流串成一套。

## 结构

```
spear/
  SKILL.md                      # 主技能：路由 + 通用工作流 + 核心原则
  README.md                     # 本文件
  references/
    toolchain.md                # 工具链装配（apt/pip，含 aarch64 proot 说明）
    re-methodology.md           # 通用逆向四阶段方法论
    unpacking.md                # 脱壳（UPX/商业壳/Android DEX 壳）
    anti-debug.md               # 反调试检测与绕过
    deobfuscation.md            # 去混淆（平坦化/字符串/虚假控制流/间接调用/SMC）
    vm-bytecode.md              # 自定义 VM/字节码逆向
    binary-protection.md        # 二进制保护绕过（pwn 向）
    pwn-chain.md                # pwn 利用链（栈/堆/内核，稳定 exploit）
    patch-diff-exploit.md       # N-day 补丁差分到利用（CVE 复现/武器化）
    attack-chain.md             # 多阶段攻击链编排（从 A 打到 B）
    dotnet.md                   # .NET 逆向（dnSpy/去混淆/注册机）
    linux-dynamic.md            # Linux 动态分析协同（GDB/r2/Frida/angr）
    hikari-deobfuscation.md     # Hikari/OLLVM 明文恢复（L1–L4）
    elf-apk-patch.md            # ELF/APK 本地 patch、壳脱修、重签名
    apk-reverse.md              # APK 逆向（jadx/apktool/smali/重打包/Frida）
    mobile-reverse.md           # Android+iOS 移动逆向、SSL Pinning/Root 绕过
    js-reverse.md               # 前端 JS 逆向、签名链路、补环境复现
    malware-analysis.md         # 恶意代码分析、YARA/Sigma/IOC
    firmware-pentest.md         # 固件/IoT 渗透（binwalk/EMBA/仿真）
    edr-bypass.md               # EDR/AV 绕过（unhook/syscall/ETW/AMSI）
    api-security.md             # API 安全测试（REST/GraphQL/JWT/OAuth）
    binary-diff.md              # 跨版本符号迁移 / 二进制差分
    game-cheat.md               # 游戏外挂/内存读写/注入/协议
    pentest-playbook.md         # 渗透打点（recon→利用→后渗透）
    crack-workflow.md           # 完整破解链路（端到端串联）
```

## 使用

1. **装到 dsh**：把 `spear/` 整个目录放到 `~/.dsh/skills/spear/`，重启 dsh 后按场景路由触发。
2. **手动用**：读 `SKILL.md` 的总路由表，按场景读对应 `references/*.md` 的 playbook 执行。
3. **跨环节**：按顺序依次读对应 reference（如 脱壳→反调试→VM→去混淆）。

## 核心原则

- 原样本只读，产物记哈希，保留回滚
- 证据驱动，不硬编码地址/偏移/密钥
- 关键结论双工具交叉验证
- 只改目标校验，保留正常业务路径
- 完成标准是"校验通过 + 行为等价 + 可复现"，不是"能安装"

## 环境说明

本技能面向 Linux（含 aarch64 proot）环境。GUI 工具（IDA/Ghidra/dnSpy）在无桌面环境跑不了，用 r2/GDB/angr/命令行工具替代。工具链缺失时按 `references/toolchain.md` 用 apt/pip 补齐。
