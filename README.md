# 长枪 spear · 一体化逆向渗透技能

**spear** 是一套把「逆向破解」和「渗透打点」打通的一体化技能，整合了多个来源的技能包，按统一工作流串成一套可路由、可执行的 playbook 集合。

## ⚠️ 免责声明

1. **非原创**：本技能**并非原创**，是融合、整合多个已有技能包的产物。所有方法论、流程、代码均来自下列公开/已有技能包，spear 仅做去重、补全、统一编排，不主张任何原创性。
2. **仅供学习研究**：本技能内容仅供**安全研究、授权测试、CTF 竞赛、自有资产测试、教学学习**使用。使用者须在**合法授权范围内**操作，遵守所在地区法律法规。
3. **不承担后果**：因使用本技能内容进行的任何未授权操作、违法行为，均由使用者自行承担全部责任，与本技能作者、整合者无关。
4. **占位符说明**：文档中的 `TARGET`、`DOMAIN`、`PATCH_BYTE`、`OAST_DOMAIN` 等均为占位符，需替换为实际目标/参数，不构成对任何具体目标的操作指引。

## 融合来源

spear 整合了以下四个技能包中**能用有用的部分**：

| 来源技能包 | 贡献内容 |
|---|---|
| **无敌逆向渗透skills** | asm-analysis、Hikari/OLLVM 明文恢复、ELF/APK 本地 patch、影安壳脱修、Ash-12 分支、外挂/逆向、恶意代码分析、固件渗透、EDR 绕过、渗透 playbook、IDA/radare2、协议逆向等 |
| **逆向破解-精选技能包** | 去混淆、VM 字节码、反调试、UPX 脱壳、通用方法论、二进制保护、.NET 逆向的提示词级 playbook，含 Z3/angr/unicorn 自动化代码 |
| **逆向破解技能包** | 标准 SKILL.md 结构的 7 个子技能（聚合路由） |
| **逆向破解精选技能包** | 上述 7 个子技能的裸文件 |

**整合原则**：去重、补全、按统一工作流串成一套，保留核心方法论与可执行代码。

## 未整合的内容及区别

以下内容经评估**未纳入** spear，说明如下：

| 未整合内容 | 来源 | 未整合原因 |
|---|---|---|
| `browser-automation` | 无敌逆向渗透skills | 浏览器/桌面自动化属辅助操作层，非逆向渗透核心方法论 |
| `diagram-generator` / `docs-generator` | 无敌逆向渗透skills | 图表/文档生成属辅助工具，非技术 playbook |
| `field-journal` | 无敌逆向渗透skills | 实战案例日志，非通用方法论，属经验回写 |
| `llm-security` | 无敌逆向渗透skills | LLM/AI 安全，属另一领域，与逆向渗透无关 |
| `supply-chain-security` | 无敌逆向渗透skills | 软件供应链治理，属合规/DevSecOps 范畴 |
| `codex-gpt55-instructions-deploy` | 无敌逆向渗透skills | 部署说明，非技术技能 |
| `CTF-Sandbox-Orchestrator` 的 30+ competition 子技能 | 无敌逆向渗透skills | CTF 题目类型分类，非通用方法论，底层 playbook 已覆盖 |
| hikari/elf/影安 的详细 references | 无敌逆向渗透skills | 对应 reference 为提炼版，核心流程已覆盖，详细参考库无需全部搬入 |
| `compiler-patterns` 等 asm-analysis 详细参考库 | 无敌逆向渗透skills | 详细参考库，提炼版已覆盖要点 |
| pentest-tools 的 industry/dictionaries/payload 库 | 无敌逆向渗透skills | 具体资源库/payload，方法论已在 pentest-playbook 覆盖 |
| `cheatsheet.md` 的 8831 行完整大全 | 外挂逆向skills | game-cheat 为提炼版，核心与高级技术已覆盖 |

**区别说明**：spear 是**提炼整合版**，保留可执行的方法论、命令、代码和关键表格，去除重复、辅助工具、案例日志、非核心领域内容，形成一套**可路由、可执行、无冗余**的技能。与原始技能包的区别是：spear 用统一路由表串起所有 playbook，按场景直达对应 reference，避免在多个技能包间跳转。

## 结构

```
spear/
  SKILL.md                      # 主技能：路由 + 通用工作流 + 核心原则
  README.md                     # 本文件
  references/
    toolchain.md                # 工具链装配（apt/pip，含 aarch64 proot 说明）
    re-methodology.md           # 通用逆向四阶段方法论
    ida-reverse.md              # IDA Pro 深度反编译分析
    radare2.md                  # radare2/r2 命令行分析
    unpacking.md                # 脱壳（UPX/商业壳/Android DEX 壳）
    anti-debug.md               # 反调试检测与绕过（含 PEB 偏移表）
    deobfuscation.md            # 去混淆（含 Z3/angr/unicorn 自动化代码）
    vm-bytecode.md              # 自定义 VM/字节码逆向（含完整反汇编器）
    binary-protection.md        # 二进制保护绕过（pwn 向，含 NX 绕过全表）
    pwn-chain.md                # pwn 利用链（栈/堆/内核，稳定 exploit）
    patch-diff-exploit.md       # N-day 补丁差分到利用
    binary-diff.md              # 跨版本符号迁移 / 二进制差分
    dotnet.md                   # .NET 逆向（dnSpy/de4dot/注册机）
    linux-dynamic.md            # Linux 动态分析协同（GDB/r2/Frida/angr/vtable 继承）
    hikari-deobfuscation.md     # Hikari/OLLVM 明文恢复（L1–L4）
    elf-apk-patch.md            # ELF/APK 本地 patch、壳脱修、Ash-12 分支、重签名
    apk-reverse.md              # APK 逆向（jadx/apktool/smali/重打包/Frida）
    mobile-reverse.md           # Android+iOS 移动逆向、SSL Pinning/Root 绕过
    js-reverse.md               # 前端 JS 逆向、签名链路、补环境复现
    protocol-reverse.md         # 协议逆向（抓包/序列化/重放）
    malware-analysis.md         # 恶意代码分析、YARA/Sigma/IOC
    firmware-pentest.md         # 固件/IoT 渗透（binwalk/EMBA/仿真）
    edr-bypass.md               # EDR/AV 绕过（unhook/syscall/ETW/AMSI）
    api-security.md             # API 安全测试（REST/GraphQL/JWT/OAuth）
    game-cheat.md               # 游戏外挂/内存读写/注入/引擎逆向/高级利用
    attack-chain.md             # 多阶段攻击链编排（从 A 打到 B）
    pentest-playbook.md         # 渗透打点（recon→利用→后渗透，含 Web 漏洞类型）
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

## 许可证

内容整合自多个来源技能包，各原始内容版权归原作者所有。本整合仅做编排与提炼，按原样使用请遵循各原始技能包的许可协议。
