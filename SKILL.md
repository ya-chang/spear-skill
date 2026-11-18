---
name: spear
description: >
  长枪 spear — 一体化逆向工程与渗透测试技能。整合脱壳、反调试绕过、去混淆、
  VM/字节码逆向、二进制保护绕过、pwn 利用链、.NET 逆向、Linux 动态分析、Hikari/OLLVM 明文恢复、
  ELF/APK 本地 patch、APK/移动逆向、前端 JS 逆向、恶意代码分析、固件/IoT 渗透、EDR 绕过、
  API 安全、跨版本符号迁移、影安壳脱修、内存外挂与渗透打点全链路。当用户提到逆向、反编译、
  脱壳、去混淆、反调试、VM 字节码、注册机/keygen、激活绕过、内存修改、外挂、DLL 注入、
  Frida、IDA/Ghidra/r2、PE/ELF/APK/SO 分析、抓包协议、APK 逆向、JS 逆向、恶意代码、固件、
  EDR 绕过、API 安全、pwn、渗透、打点、漏洞利用、CTF 时使用。
  先读 references/ 下对应 playbook 再执行，不要凭空臆造步骤。
---

# 长枪 spear · 一体化逆向渗透技能

一套把「逆向破解」和「渗透打点」打通的技能。**核心原则：证据驱动，先定位再动手，每步可验证、可回滚。**

## 一、总路由（先按场景选 playbook）

> 详细路由表与通用技术主责分配见 `references/INDEX.md`。任务模糊时先查 INDEX 再定位主责 playbook。

| 场景 | 读哪个 reference |
|---|---|
| 不知道从哪下手 / 通用流程 | `references/re-methodology.md` |
| 环境没工具 / 要装工具链 | `references/toolchain.md` |
| IDA Pro 深度反编译分析 | `references/ida-reverse.md` |
| radare2 / r2 命令行分析 | `references/radare2.md` |
| 程序被加壳（UPX/商业壳） | `references/unpacking.md` |
| 有反调试，调试器被拒 | `references/anti-debug.md` |
| 控制流平坦化/字符串加密/混淆 | `references/deobfuscation.md` |
| 自定义 VM/字节码保护 | `references/vm-bytecode.md` |
| 打 pwn / 绕过 ASLR·PIE·NX·canary | `references/binary-protection.md` |
| 有漏洞点，写稳定 exploit | `references/pwn-chain.md` |
| .NET / ConfuserEx 逆向 | `references/dotnet.md` |
| Linux 下 GDB/r2/Frida/angr 协同 | `references/linux-dynamic.md` |
| Hikari/OLLVM AArch64 明文恢复 | `references/hikari-deobfuscation.md` |
| ELF/APK 本地 patch、linker 假加载脱壳、影安壳 | `references/elf-apk-patch.md` |
| Android APK 逆向（jadx/apktool/smali/重打包） | `references/apk-reverse.md` |
| Android+iOS 移动逆向、SSL Pinning/Root 绕过 | `references/mobile-reverse.md` |
| 前端 JS 逆向、签名链路、补环境复现 | `references/js-reverse.md` |
| 浏览器/桌面自动化（Playwright/OpenReverse） | `references/browser-automation.md` |
| 协议逆向（抓包/序列化/重放） | `references/protocol-reverse.md` |
| 恶意代码分析、YARA/Sigma/IOC | `references/malware-analysis.md` |
| 固件 / IoT 渗透（binwalk/EMBA/仿真） | `references/firmware-pentest.md` |
| EDR / AV 绕过（unhook/syscall/ETW/AMSI） | `references/edr-bypass.md` |
| API 安全测试（REST/GraphQL/JWT/OAuth） | `references/api-security.md` |
| LLM/AI 安全测试（Prompt 注入/Agent/OWASP LLM+ASI） | `references/llm-security.md` |
| 供应链安全（SBOM/SCA/CI-CD/依赖溯源） | `references/supply-chain-security.md` |
| 跨版本符号迁移 / 二进制差分 | `references/binary-diff.md` |
| N-day 补丁差分到利用（CVE 复现/武器化） | `references/patch-diff-exploit.md` |
| 多阶段攻击链编排（从 A 打到 B） | `references/attack-chain.md` |
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

## 四、Playbook 治理规则（追加内容时必须遵守）

**去重规则**：每个技术/方法论指定一个**主责 playbook**，其余 playbook 只在需要时写一行引用（`→ 详见 common-techniques.md §X.Y` 或 `→ 详见 <主责playbook> §X`），不重复展开。主责分配如下：

| 技术/方法论 | 主责 playbook |
|---|---|
| NPT/EPT/SLAT 虚拟化 Hook、VT-D 对抗、内核异常接管 | `re-methodology.md`（通用技术细节见 `common-techniques.md`） |
| PEB 遍历、ntdll 基址获取、KnownDlls 劫持等内核免杀原语 | `edr-bypass.md`（原语细节见 `common-techniques.md`） |
| Hook 技术图谱（IAT/Inline/SSDT/VEH 等全架构） | `common-techniques.md`（各 playbook 按需引用） |
| VM/字节码保护与去虚拟化 | `vm-bytecode.md`（VMP 还原细节）；`deobfuscation.md` 只处理混淆类 |
| page cache 写入类漏洞（Dirty Pipe/Copy Fail） | `pwn-chain.md` |
| SLAT/虚拟化相关原语 | `common-techniques.md` |
| 加壳/脱壳（UPX/商业壳/压缩壳） | `unpacking.md`；`binary-protection.md` 只管保护机制原理 |
| 移动端 Hook/重签名/风控 | `mobile-reverse.md`（不写进 toolchain.md） |

新增内容前先查上表，若该技术已有主责 playbook，新内容追加到主责处，其他 playbook 只加引用行。

**时间戳与来源标注规则**：每个新增小节末尾必须标注：
```
> 更新：YYYY-MM-DD · 来源：看雪帖 <帖号>（板块名）
```
多批次追加同一小节时，保留历史标注，新标注追加在末尾。这样可快速判断内容新旧与溯源。

**热度平衡规则**：单次追加内容超过 200 行时，检查是否可拆分到更聚焦的 playbook（如通用原语抽到 `common-techniques.md`），避免单一 playbook 无限膨胀。

**代码骨架规范**：每个 playbook 至少提供一个**可编译/可运行的代码骨架**（非伪代码），放在该 playbook 的「代码骨架」小节。骨架要求：
- 含完整 include、函数定义、关键逻辑，能编译或能跑（允许关键常量/地址用占位符 `[TARGET]`）
- 纯逻辑占位（如以字符串置零代替函数 patch）必须替换为真实实现，或明确标注为占位并给替代方案
- 骨架与正文流程对应，读者照着骨架改参数即可落地
- 新追加的漏洞利用/绕过类内容，必须附可运行 PoC 骨架，不允许只给文字描述

**验证清单机制**：每个 playbook 的「验证」小节必须是**可勾选的检查清单**，不是散文描述。格式：
```
## 验证
- [ ] 检查项 1（具体命令或观察点）
- [ ] 检查项 2
- [ ] 检查项 3
```
每项须含具体验证命令、观察点或判定标准，不允许写"验证通过"这类无操作描述。执行任务时按清单逐项勾选，未全勾不算完成。

## 五、专项技能边界（何时用 spear，何时用专项技能）

spear 是一体化覆盖，但在以下方向有更聚焦的专项技能，优先用专项，spear 作为补充或兜底：

| 方向 | 专项技能（优先） | spear 角色 |
|---|---|---|
| API 安全 / SRC 挖洞 | `src-hunter`（5 阶段方法论+19 playbook+305 payload） | spear 的 `api-security.md` 作快速参考 |
| 验证码协议逆向 | `captcha-reverse` / `captcha-vision` | spear 不覆盖验证码专项 |
| 微信小程序逆向 | `wechat-miniapp-reverse` | spear 的 `js-reverse.md` 作通用补充 |
| Web 协议还原（未知族/多层级） | `trace` / `iv8-web-reverse` / `nv8-node-runtime` | spear 的 `protocol-reverse.md` 作通用补充 |
| Akamai 纯协议还原 | `akamai-protocol-reverse` | spear 不覆盖 |
| CTF 沙箱编排 | `ctf-sandbox-orchestrator` | spear 的 `pwn-chain.md` 作利用链补充 |
| 汇编深度分析 | `asm-analysis`（GDB/r2/Frida/angr 协同） | spear 的 `linux-dynamic.md`/`radare2.md` 作工具参考 |
| 逆向报告/文档生成 | `docs-generator` | 任务完成后用 docs-generator 出正式报告 |

**判断原则**：任务明确命中专项技能的触发条件时，优先加载专项技能；任务跨多个域或专项技能未覆盖时，用 spear 的 playbook 组合。spear 的价值在于跨域串联和一体化流程，专项技能的价值在于单域深度。

## 六、结构化执行前置检查清单

任务到来时，**先完成以下检查再动手**，不跳过：

1. **[ ] 路由定位**：查 `references/INDEX.md` 确定主责 playbook，读该 playbook（不凭空臆造步骤）
2. **[ ] 样本建档**：哈希原样本（SHA-256），记录文件类型/架构/编译器/安全标志，保留原始副本
3. **[ ] 保护识别**：判断保护类型（加壳/反调试/混淆/VM），按「处理顺序铁律」排优先级
4. **[ ] 骨架核对**：检查主责 playbook 是否有「代码骨架」小节，有则基于骨架改造，无则按流程自写并标注
5. **[ ] 验证清单**：执行前确认「验证」小节为可勾选清单，执行后逐项勾选，未全勾不算完成
6. **[ ] 去重检查**：涉及通用原语时，查 `common-techniques.md` 对应章节，不重复展开
7. **[ ] 两层确认**：关键结论至少两个独立工具交叉验证（如 GDB+Frida、strace+ltrace）

**执行纪律**：每步产出可验证证据（日志/截图/哈希），不破坏业务路径，原样本只读，所有修改在副本上做。

## 七、最小工具链（详见 references/toolchain.md）

- **静态**：`file` `readelf`/`pefile` `objdump` `nm` `strings` `rabin2`(r2) `capstone`
- **动态**：`gdb`(+pwndbg/gef) `frida` `strace` `ltrace` `perf`
- **符号执行**：`angr`
- **脱壳**：`upx`、自写 dump 脚本
- **Android**：`adb` `apktool`/`baksmali` `apksigner` `zipalign` `frida`
- **.NET**：`dnSpy`（或 ILSpy）
- 缺什么按 `references/toolchain.md` 的 apt/pip 命令补。

## 八、交付标准

- 破解类：能复现校验通过，给出 patch 字节/注册机算法，附验证命令。
- 脱壳/重建类：给出可运行产物 + 哈希 + 行为等价证据。
- 渗透类：给出可复现的 exploit/PoC + 影响面说明。
- 不允许用"安装成功"冒充"任务完成"。
