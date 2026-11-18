# Spear Playbook 路由索引（INDEX）

> 更新：2026-11-18
> 用途：任务到来时先查此表定位**主责 playbook**，再按治理规则决定是否需读关联 playbook。
> 规则：每个技术只有一个主责 playbook（详展开），其余 playbook 只写引用行，不重复展开。通用原语统一在 `common-techniques.md`。

## 路由总表

### 逆向工程

| 任务类型 | 主责 playbook | 关联 playbook（按需引用） | 备注 |
|---|---|---|---|
| 通用逆向流程 / 不知道从哪下手 | `re-methodology.md` | `toolchain.md` | 先读此 |
| IDA Pro 深度反编译 | `ida-reverse.md` | `re-methodology.md` | |
| radare2 / r2 命令行 | `radare2.md` | `ida-reverse.md` | |
| 加壳脱壳（UPX/商业壳/压缩壳） | `unpacking.md` | `binary-protection.md`（保护原理）、`deobfuscation.md`（脱壳后混淆） | |
| 反调试绕过 | `anti-debug.md` | `edr-bypass.md`（内核层）、`common-techniques.md`（异常接管） | |
| 控制流平坦化/字符串加密/OLLVM | `deobfuscation.md` | `hikari-deobfuscation.md`（AArch64 专项）、`vm-bytecode.md`（VM 承载的混淆） | |
| 自定义 VM / 字节码保护 | `vm-bytecode.md` | `deobfuscation.md`（混淆层）、`re-methodology.md`（去虚拟化） | |
| 二进制保护机制原理（ASLR/PIE/NX/canary/CFG） | `binary-protection.md` | `pwn-chain.md`（绕过实战） | |
| .NET / ConfuserEx 逆向 | `dotnet.md` | `deobfuscation.md` | |
| Linux 动态分析（GDB/r2/Frida/angr） | `linux-dynamic.md` | `toolchain.md` | |
| 跨版本符号迁移 / 二进制差分 | `binary-diff.md` | `patch-diff-exploit.md` | |
| N-day 补丁差分到利用 | `patch-diff-exploit.md` | `pwn-chain.md`、`binary-diff.md` | |
| Hikari/OLLVM AArch64 明文恢复 | `hikari-deobfuscation.md` | `deobfuscation.md` | |
| ELF/APK 本地 patch、linker 假加载 | `elf-apk-patch.md` | `apk-reverse.md`、`unpacking.md` | |

### 移动安全

| 任务类型 | 主责 playbook | 关联 playbook（按需引用） | 备注 |
|---|---|---|---|
| Android APK 逆向（jadx/apktool/smali） | `apk-reverse.md` | `elf-apk-patch.md`、`mobile-reverse.md` | |
| Android+iOS 移动逆向、SSL Pinning/Root | `mobile-reverse.md` | `apk-reverse.md`（Android 专项）、`toolchain.md`（工具安装） | iOS Hook/重签名/风控归此 |
| 移动端加固对抗（VMP/OLLVM/抽取壳） | `apk-reverse.md` | `deobfuscation.md`、`vm-bytecode.md` | |

### 前端与协议

| 任务类型 | 主责 playbook | 关联 playbook（按需引用） | 备注 |
|---|---|---|---|
| 前端 JS 逆向、签名链路、补环境 | `js-reverse.md` | `protocol-reverse.md`、`browser-automation.md` | |
| 浏览器/桌面自动化 | `browser-automation.md` | `js-reverse.md` | |
| 协议逆向（抓包/序列化/重放） | `protocol-reverse.md` | `js-reverse.md`（JS 签名）、`mobile-reverse.md`（移动抓包） | |

### 渗透与利用

| 任务类型 | 主责 playbook | 关联 playbook（按需引用） | 备注 |
|---|---|---|---|
| 有漏洞点，写稳定 exploit | `pwn-chain.md` | `binary-protection.md`（绕过原理）、`common-techniques.md`（漏洞原语） | Linux 内核漏洞、Egg Hunter 归此 |
| 多阶段攻击链编排 | `attack-chain.md` | `pentest-playbook.md`、`edr-bypass.md` | Windows 提权链归此 |
| 网站/API/内网渗透打点 | `pentest-playbook.md` | `api-security.md`、`attack-chain.md` | |
| API 安全测试 | `api-security.md` | `pentest-playbook.md` | |
| EDR/AV 绕过 | `edr-bypass.md` | `anti-debug.md`、`common-techniques.md`（PEB/Hook 原语） | |
| 游戏外挂/内存读写/注入 | `game-cheat.md` | `apk-reverse.md`（移动外挂）、`pwn-chain.md`（内存利用） | |
| 完整破解链路 | `crack-workflow.md` | `unpacking.md`→`anti-debug.md`→`vm-bytecode.md`→`deobfuscation.md` 顺序读 | |

### 安全分析与供应链

| 任务类型 | 主责 playbook | 关联 playbook（按需引用） | 备注 |
|---|---|---|---|
| 恶意代码分析 | `malware-analysis.md` | `attack-chain.md` | |
| 固件/IoT 渗透 | `firmware-pentest.md` | `linux-dynamic.md`、`elf-apk-patch.md` | |
| 供应链安全 | `supply-chain-security.md` | `malware-analysis.md` | |
| LLM/AI 安全测试 | `llm-security.md` | `supply-chain-security.md` | |

### 通用与工具

| 任务类型 | 主责 playbook | 关联 playbook（按需引用） | 备注 |
|---|---|---|---|
| 环境没工具 / 装工具链 | `toolchain.md` | 各专项 playbook 的工具段 | iOS 工具安装也归此，但 iOS 技术内容归 mobile-reverse |
| 跨域通用技术（Hook/虚拟化/PEB/漏洞原语） | `common-techniques.md` | 各 playbook 按需引用，不重复展开 | 见下表 |

## 通用技术主责分配（去重依据）

以下技术在多个 playbook 涉及，统一在 `common-techniques.md` 展开，各 playbook 只引用：

| 通用技术 | common-techniques.md 章节 | 涉及的 playbook（引用方） |
|---|---|---|
| Windows 全架构 Hook（IAT/Inline/SSDT/VEH/IDT 等） | §1 | anti-debug、edr-bypass、binary-protection、game-cheat、mobile-reverse |
| NPT/EPT/SLAT 虚拟化 Hook | §2 | re-methodology、edr-bypass、anti-debug、game-cheat |
| VT-D 对抗 / DMA 防护 | §3 | re-methodology、firmware-pentest |
| Win11 内核异常体系与接管 | §4 | anti-debug、edr-bypass、re-methodology |
| PEB 遍历 / ntdll 基址 / KnownDlls 劫持 | §5 | edr-bypass、game-cheat、mobile-reverse |
| page cache 写入类漏洞原语 | §6 | pwn-chain、patch-diff-exploit |
| ROP / 线程池注入 / Egg Hunter | §7 | pwn-chain、game-cheat、attack-chain |
| VM 字节码通用结构（解释器/dispatcher/handler） | §8 | vm-bytecode、deobfuscation、apk-reverse |

## 使用流程

1. 任务到来 → 在「路由总表」按任务类型找**主责 playbook**
2. 读主责 playbook；若涉及通用技术，按「通用技术主责分配」查 `common-techniques.md` 对应章节
3. 需要跨环节时，按 SKILL.md「总路由」的顺序依次读关联 playbook
4. 追加新内容时，遵守 SKILL.md「Playbook 治理规则」：查主责分配、标注时间戳与来源、控制单 playbook 体积

## 新增录入（2026-11-18，看雪帖 2138362 逆向技能包整合）

十份实战技能内容已按主责分配录入下列 playbook（各 playbook 内标注「更新：2026-11-18 · 来源：看雪帖 2138362」）：

| 技能包内容 | 主责 playbook | 录入章节 |
|---|---|---|
| 逆向思维内核（四步纪律/证伪/三证据/降维六形态/认知陷阱） | `re-methodology.md` | 「思维内核与降维决策」 |
| 逆向作战流程（定义赢/闸门地图/选点/补丁纪律/止损/三层验收） | `crack-workflow.md` | 「七、逆向作战流程」 |
| 原生授权与注册机（授权形态/算法证据链/模数可分解/keygen 自验） | `crack-workflow.md` | 「八、原生客户端授权 / 注册机」 |
| .NET 量化识别与等长 IL 补丁 | `dotnet.md` | 「十三、.NET 保护量化识别与补丁实战」 |
| 私有协议帧推演与 WSS | `protocol-reverse.md` | 「十二、私有协议帧推演」 |
| VMP 结构识别与指令语义拼接 | `vm-bytecode.md` | 「十六、VMP 结构识别与指令语义拼接」 |
| VMP handler 层反调试拆除 | `anti-debug.md` | 「十、VMP handler 层反调试：按层整体拆除」 |
| 补环境方法论与 WASM/JSVMP 黑盒实战 | `js-reverse.md` | 「十一、补环境方法论与 WASM/JSVMP 黑盒实战」 |
| JS 混淆 AST 七步还原流水线 | `deobfuscation.md` | 「九、JS 混淆 AST 七步还原流水线」 |
| 移动端与本地数据层取证（双快照/SQLite 触发器/SQLCipher/WAL） | `mobile-reverse.md` | 「十一、移动端与本地数据层取证」 |
| 引擎资源容器逆向（源码优先/容器推演/算法指纹/round-trip） | `game-cheat.md` | 「引擎资源容器逆向」 |
