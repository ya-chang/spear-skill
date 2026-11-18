# 通用逆向方法论（re-methodology）

适用于 PE / ELF / MACH-O / APK / SO / 固件 / JS 等任意目标。四阶段循环。

## 阶段 0：建档与基线

```bash
sha256sum target
file target
readelf -h target      # ELF；PE 用 pefile；Mach-O 用 otool
readelf -S -l target   # 段、程序头
readelf -d target      # 动态依赖、NEEDED
strings -a target | head -100
```

记录：文件类型、架构（x86/x64/ARM/ARM64）、编译器与优化级别、安全标志（PIE/NX/canary/RELRO/CFI）、入口点、导入表。

## 阶段 1：静态侦察

```bash
r2 -A -q -c 'aaa; afl; axt' target      # r2 全量分析 + 函数列表 + 交叉引用
r2 -q -c 'iI; iS~entropy' target        # 信息 + 段熵值（判断是否加壳）
objdump -d target | less                 # 反汇编
nm target                               # 符号表（未 strip）
```

- 熵值 > 7.0 → 疑似加壳/加密（转 `unpacking.md`）
- 函数极少 + 大量 `call [reg]` → 混淆/VM（转 `deobfuscation.md` / `vm-bytecode.md`）
- 有 `v.m.p`/`abcd`/小 DEX/`libabcd.so` → 壳（转 `elf-apk-patch.md`）

## 阶段 2：动态验证

静态看不清的（自解密、运行时 DEX、动态调用）用动态补：

```bash
strace -tt -T ./target 2>&1 | tee /tmp/strace.log
ltrace -e strcmp,memcmp,EVP_*,AES_* ./target
gdb -q ./target
frida -f ./target -l hook.js
```

动态优先看：
- `open`/`read`：密钥文件、配置、运行时 DEX
- `mprotect(EXEC)`：自解码/脱壳触发点
- `strcmp`/`memcmp`：密码/校验比较
- 加密库函数：算法识别

## 阶段 3：定位与还原

- **定位 CHECK_FN**：找校验/激活/注册入口。线索：字符串 "register/license/key/激活"、`strcmp` 热点、返回值分支。
- **还原算法**：识别加密/哈希/签名算法（见 `deobfuscation.md` 算法特征表），还原成可复现的 Python/C 实现。
- **还原结构**：vtable、结构体布局、类型重建（见 `linux-dynamic.md` 结构体恢复）。

## 阶段 4：交付与验证

- 打补丁：记录 `OFFSET` + `PATCH_BYTE`，保留原始副本，验证字节级差异仅在目标处。
- 写注册机：还原算法后，用独立实现生成有效序列号/卡密，回填验证。
- 重建镜像：脱壳/重组后，验证可运行 + 行为等价。

**完成标准**：不是"能安装"，而是"校验通过 + 行为符合预期 + 有验证证据"。

## 常用命令速查

| 目的 | 命令 |
|---|---|
| 看入口/段 | `readelf -h -l target` |
| 看导入 | `readelf -d target` / `rabin2 -i target` |
| 反汇编函数 | `objdump -d target` / `r2 pdf @ sym` |
| 找字符串引用 | `r2 axt @ <addr>` |
| 搜字节 | `r2 /x <hex>` / GDB `find` |
| 看内存映射 | `cat /proc/<pid>/maps` / pwndbg `vmmap` |
| 查算法常数 | `strings` + 常数表（0xd76aa478=MD5，0x63=AES S-box） |

## 调用约定速查

| 平台 | 约定 | 参数传递 |
|---|---|---|
| x86 cdecl | 调用者清理栈 | 参数从右往左压栈 |
| x86 stdcall | 被调用者清理栈 | 参数从右往左压栈 |
| x64 Windows | Microsoft x64 | RCX, RDX, R8, R9，多余走栈 |
| x64 System V | AMD64 ABI | RDI, RSI, RDX, RCX, R8, R9，多余走栈 |
| ARM | AAPCS | R0-R3，多余走栈 |

## 常见代码模式识别

```c
// 字符串混淆（XOR 解密循环）
for (int i = 0; i < len; i++)
    str[i] ^= key;

// 反调试（IsDebuggerPresent）
if (IsDebuggerPresent())
    exit(1);

// API 哈希（恶意软件常用，隐藏导入）
hash = 0;
while (*name)
    hash = ror(hash, 13) + *name++;

// 栈字符串构造
char s[8];
*(DWORD*)s = 0x6C6C6548;  // "Hell"
*(DWORD*)(s+4) = 0x6F;    // "o\0"
```

## 权威文档与白皮书 URL 索引

遇到不确定的指令语义、调用约定、加密规范，优先查以下权威来源，不要凭记忆臆测。

### x86 / x86-64

**Intel（首选）：**

| 文档 | URL | 关键内容 |
|---|---|---|
| Intel SDM（完整版 7 卷合一 PDF） | https://cdrdv2.intel.com/v1/dl/getContent/671200 | 最权威，含所有指令语义 |
| Intel SDM Volume 2A（指令集 A-M） | https://cdrdv2.intel.com/v1/dl/getContent/671110 | ADD 到 MOVQ |
| Intel SDM Volume 2B（指令集 N-Z） | https://cdrdv2.intel.com/v1/dl/getContent/671108 | NOP 到 XTEST |
| Intel SDM Volume 2C（VEX/EVEX 扩展） | https://cdrdv2.intel.com/v1/dl/getContent/671112 | AVX/AVX-512 |
| Intel SDM Volume 1（基础架构） | https://cdrdv2.intel.com/v1/dl/getContent/671094 | 寄存器、寻址模式 |
| Intel Intrinsics Guide（在线版） | https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html | SIMD 内置函数对应指令 |
| Intel 64 ABI（System V AMD64） | https://refspecs.linuxbase.org/elf/x86-64-abi-0.99.pdf | 调用约定、栈布局 |

**AMD：**
- AMD64 Architecture Programmer's Manual Vol.1-5：https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/

**在线快速查询：**

| 工具 | URL | 用途 |
|---|---|---|
| Felix Cloutier x86 Reference | https://www.felixcloutier.com/x86/ | 按指令名快速查语义 |
| uops.info（微架构延迟） | https://uops.info/table.html | 查延迟/吞吐量 |
| Godbolt Compiler Explorer | https://godbolt.org | 对比不同编译器输出 |

### ARM64 / AArch64

**ARM 官方（首选）：**

| 文档 | URL | 关键内容 |
|---|---|---|
| ARM Architecture Reference Manual (DDI 0487) | https://developer.arm.com/documentation/ddi0487/latest | 最权威 AArch64 手册 |
| Arm A64 ISA Reference（在线 HTML） | https://developer.arm.com/documentation/ddi0596/latest | 按指令名索引 |
| Arm Cortex-A Series Programmer's Guide | https://developer.arm.com/documentation/den0013/latest | 编程模型，入门 |
| Arm64 Procedure Call Standard (AAPCS64) | https://github.com/ARM-software/abi-aa/releases | 调用约定 |
| Arm NEON Intrinsics Reference | https://developer.arm.com/architectures/instruction-sets/intrinsics/ | NEON 指令查询 |

### 通用逆向工具文档

| 工具 | 文档 URL |
|---|---|
| IDA Pro 帮助 | https://hex-rays.com/products/ida/support/idadoc/ |
| Ghidra 文档 | https://ghidra-sre.org/CheatSheet.html |
| Binary Ninja 文档 | https://docs.binary.ninja |
| LLVM IR 参考 | https://llvm.org/docs/LangRef.html |

### 文件格式参考

| 格式 | 文档 |
|---|---|
| ELF | https://refspecs.linuxfoundation.org/elf/elf.pdf |
| PE/COFF | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format |
| Mach-O | https://developer.apple.com/documentation/kernel/mach_header |
| DWARF 调试信息 | https://dwarfstd.org/doc/DWARF5.pdf |

### 加密算法参考规范

| 算法 | 规范来源 |
|---|---|
| AES | NIST FIPS 197 — https://csrc.nist.gov/publications/detail/fips/197/final |
| SHA-2 | NIST FIPS 180-4 — https://csrc.nist.gov/publications/detail/fips/180/4/final |
| SHA-3 | NIST FIPS 202 — https://csrc.nist.gov/publications/detail/fips/202/final |
| ChaCha20/Poly1305 | RFC 8439 — https://www.rfc-editor.org/rfc/rfc8439 |
| RSA | RFC 8017 (PKCS#1) — https://www.rfc-editor.org/rfc/rfc8017 |
| RC4 | RFC 6229 — https://datatracker.ietf.org/doc/html/rfc6229 |

## AI Agent 辅助逆向（作战系统方法论）

> 来源：看雪「AI 助力安全」/「AI 工具与工作流」版块多帖学习（2026-11-17）：
> r0crawl_skills 全面介绍（292402）、逆向已死 GPT-6 通杀 CTF（293109）、
> 代码虚拟化被 AI 击溃（292370）、Claude+MCP Android 工具链（293009）。

### 核心思想：把「感觉」推进到「有证据的复现」
- 逆向最浪费时间的不是某个 API 不会用，而是**不知道先看什么、证据放哪、下一步切哪条线**。
- Agent 作战系统 = **总参谋部**：拆任务 → 选路线 → 串工具 → 留证据 → 做复现。
- 一句话：把「我感觉这里是加密」推进到「**我有证据证明输入、变换、输出和复现结果**」。
- 不是「装了自动破解一切」，是把判断与重复劳动整理成 Agent 可直接调度的工程流程。

### 四问入口（先固定范围再选模块）
1. **分析什么**：网页、JS、APK、DEX、SO、二进制、PCAP、固件、样本？
2. **关键动作**：登录、搜索、上传、支付、加密、校验、网络交换？
3. **已有材料**：URL、文件、HAR、PCAP、日志、截图、dump、或只有描述？
4. **目标产物**：行为解释、入口定位、Hook、dump、算法、复现请求、报告？

回答完四问，Agent 才选**最小模块集**，少加载、准命中、快推进。

### 案件目录结构（证据落盘）
```text
case/
  case.yaml
  evidence/raw/        原始 APK、日志、maps、内存片段、HAR、PCAP
  evidence/derived/    DEX/SO/修复产物、反编译输出
  notes/timeline.md    加载与提取时间线
  notes/hypotheses.md  假设与排除表
  repro/               复现脚本与请求
  tests/fixtures.jsonl parity 比对夹具
  report.md            壳判断、证据、限制、下一步
```
每个结果必须含：**大白话摘要、证据、路线、可复现检查、局限性、下一步**。绝不把单个静态字符串、单行日志、自动反编译结果当作已确认调用链，必须独立验证。

### 三条主线工作法
- **脱壳五步**（见 `unpacking.md`）：识别保护面 → 跟踪加载时机 → 提取运行时代码 → 修复重建 → 验收交付（记来源/地址/大小/SHA-256）。
- **抓包追到协议语义**：先存原始 HAR/PCAP 不在原文件改；展开字段清单；最小差分（一次只改一个输入）；脱敏；比对 parity 夹具；把字段语义、状态依赖、限制写进报告。
- **参数逆向从最终请求倒推**：先锁最终出站值，再沿数据流反查 writer/builder/entry/source；验收要有固定输入、变量控制、多样本 parity、真实请求验证。

### AI 自动化逆向环境与提示词（r0env / 批量解题）
- **意图驱动**：人给目标 → Agent 检查系统/日志 → 执行命令/改配置 → 复核结果。
- **持久记忆**：每完成一题把目标、关键证据、已验证路径、结果写入 `ai-memory`，跨题/重启不丢进度。
- **批量解题提示词四要素**（经实战验证有效）：
  1. 明确给出命令/目标（找出 flag）
  2. **「找到再停」把结束条件写死**，拒绝乱停
  3. 「当前目录就是题目目录」集中注意力
  4. 列出已有工具，增强信心
- **分工**：r0skill（路由选工具）+ ai-memory（跨会话记忆）+ diagram-design（专业报告）。

### AI 是加速器不是神
- **先跑通，再抬 IR，再谈优化**；AI 不替你负责对错，分析者必须对结果做二次判断与验证。
- 各 MCP/技能封装成熟度不一，选型保留原生工具兜底，不把单一封装当唯一通道。
- 虚拟化等「人肉门槛」可被流水线拆，「语义门槛」仍需自己的语义表 + 数据流（详见 `vm-bytecode.md` 第十四节）。

## AI Agent 逆向工程的体系化方法（看雪四子板块深读）

### 一、Binary Analysis Agent：AI 当编排器的架构范式（291002）

基于 OpenCode 的 Agent+Plugin 机制，AI 不直接操作 GUI，而是通过**分析引擎 headless 模式**间接驱动工具，输出 JSON 结构化结果。

- **核心设计**：
  - 依赖方向严格单向：基础设施 ← 业务工具 ← 共享分析 ← 操作脚本，禁反向/循环依赖，保证每层独立测试。
  - **headless 封装**：所有分析操作封装为「脚本启动→等待分析→执行业务→输出 JSON→退出」，AI 只构造命令行调用（`-A -S脚本路径`），通过环境变量传参（引擎 `-S` 机制下环境变量是唯一可靠跨层传参方式）。
  - **三阶段强制框架**：信息收集 → 方案规划 → 执行监控，不允许跳过；先花 2 分钟规划，省 20 分钟无效尝试。
  - **渐进式披露**：主 Prompt 控制在 500 行以内，只放核心规则和触发条件；18 份知识库文档按场景标签（packed/crypto/gui）按需加载，场景可组合、按优先级处理（先脱壳→再识别密码学→最后 GUI）。
  - **四维度量**：每个新增脚本/Prompt 都评估——减少上下文占用、减少对话轮次、提升分析速度、提升结果准确度；不满足的明确拒绝（如给简单异或写脚本，AI 自己能算）。
  - **核心禁令**：绝对禁止用自己重实现的代码验证自己的结论（作弊式验证）；必须让原始程序实际执行，从外部观察结果。
  - **失败熔断**：同一方向连续失败 2 次强制切换方向；累计耗时上限 120 分钟。
- **工具栈不绑定 Python**：计算密集型（暴力搜索、大数运算）用 C/C++（10-100 倍性能）；算法验证优先模拟执行而非手动重实现；不确定时先 Python 原型验证正确性再转 C 加速。
- **进程 Patch 工具（最后手段）**：Patch（改地址字节）/ Write Data/Code（写空闲内存）/ Capture（读中间结果）/ Signal（等待内存标记同步）/ Trigger（GUI 触发执行）。
- **效果**：难度 99/100 的 CrackMe 半天到一天逆向出注册机；只破解不逆向则难度 99/100 也很快。

### 二、自主渗透 Agent 的「管理制度」（293529/293551）

XBOW Web CTF 104 题做对 101（97.1%，deepseek-flash）。核心一句话：**模型是提出者，代码和人才是裁决者**。

- 五件事各归其主：能不能做→12 道 Gate 代码裁决；是不是真的→证据和数学裁决（防误报五层漏斗）；下一步打哪→落盘计划裁决；打得多响→策略文件裁决；知道些什么→确定性代码注入。
- **三大贯穿模式**：
  1. **拒绝即引导**：拦下模型动作时，拒绝理由作为工具结果回填，模型读到「为什么不行」下一轮自己改道，堵而不死。
  2. **文件系统即状态**：计划、发现、证据、知识全部落盘成文件；进程重启、对话压缩、换执行引擎，状态都不丢。
  3. **事故驱动演进**：每个机制背后都有一次真实事故（烧掉百万级 token、技能被反复激活 61 次、交付物引用不存在的证据文件）；没有事故背书的机制是猜的。
- **最小 Agent 循环（70 行）+ 三配件**：
  ```python
  def run_agent_loop(client, messages, cfg, execute_tool):
      for _ in range(cfg.max_iterations):        # 配件一：迭代上限 25
          resp = client.call(cfg.system, messages, tools=schemas())
          messages.append({"role": "assistant", "content": resp["content"]})
          tool_uses = [b for b in resp["content"] if b["type"] == "tool_use"]
          if resp["stop_reason"] != "tool_use" or not tool_uses:
              return final_text(messages)
          results = []
          for tu in tool_uses:
              out = execute_tool(tu["name"], tu["input"])  # 配件二：异常转文本
              results.append({"type": "tool_result", "tool_use_id": tu["id"],
                              "content": str(out)[:15000]})  # 配件三：输出截断
          messages.append({"role": "user", "content": results})
      return budget_exhausted()                   # 预算耗尽体面退出，可续跑
  ```
  - 迭代上限：模型找到「有趣」循环会一直转烧账单；上限到不是报错，是带终因退出。
  - 异常转文本（批次容忍）：一批 5 个调用第 2 个炸了，其余照常执行，错误信息回填让模型下轮改道。
  - 输出截断（15000 字符）：全量 nmap 输出几百 KB，截断是**循环层纪律**，所有工具无差享受。
  - 重试分类：`RETRYABLE = {408,429,500,502,503,504}` 退避重试；`FATAL = {400,401,403,422}` 不重试（422 被当限速重试四次是典型坑）。
  - 终因登记表：闭合词表记录每个回合结束原因（完成/预算耗尽/操作员停止/LLM 故障），方便复盘与调度。
- **坑**：循环没上限跑了 40 分钟；输出不截断第三回合上下文爆炸；累计 token 计数器直接当预算（累计器只能做差，不能当预算）。

### 三、任务结果验证器：执行状态≠任务进度≠完成结果（293317，Gravity Amber）

Agent 调完工具后必须回答「目标真的实现了吗」。三层信息不可互相替代：

| 信息层次 | 回答的问题 | 典型信息 |
|---|---|---|
| 执行状态 | 调用跑到哪一步 | 指令已接收、动作结束、工具返回码 |
| 任务进度 | 离目标还有多远 | 目标被找到、物体已搬起、部分区域已处理 |
| 完成结果 | 目标条件是否满足 | 对象正确、位置正确、结果稳定、证据充分 |

**验证链路**：任务生成时写 `verification_spec`（goal、target_id、required_conditions、evidence_needed、spec_version）→ 证据对齐（同时检查**任务版本 + 执行尝试 + 采集时间**，失败补传画面不覆盖新结果）→ 质量检查（证据不足输出 `unknown`，不硬判）→ 规则提取事实 + VLM 逐项评估（要求给出依据的证据编号，事实保留**满足/不满足/未知**三态）→ 核对形成结论（`passed/partial/failed/unknown`）→ 决策表驱动下一步（通过→提交；部分→补做未满足条件；失败→按原因调整；未知→补观察或人工复核）。

**重试针对原因**：位置对但没释放→补释放；对象错了→重确认目标；区域不可见→先补观察证据。从头重跑会丢中间进度、重蹈失败。
**验收指标**：未完成被误判为通过的比例；对照情境测试（对象对位置错、动作完对象落、只完成部分、目标遮挡、旧证据迟到）。

### 四、vibe reversing：双 MCP 直接对话驱动（293018）

IOS-MCP（UI 自动化）+ IOSDecryptHUb（算法日志+hook），无需抓包工具、无需 Frida，直接和 AI 对话完成逆向。AI 在加密日志无线索时会走偏半小时，**人工引导 hook `mlock`**（"指针+长度"型 API、密钥必经之路）后数分钟拿到密钥。结论：AI 思路有限，hook 选型等关键决策仍以人的经验为主。

### 五、AI 模型层安全认知（168 板块，用 AI 也要防 AI）

**Claude Code 客户端上报机制（291395，v2.1.88 逆向）**
- `/v1/messages` 请求除用户输入外还带：`system` 里拼入工作目录（绝对路径含用户名/项目名）、git 分支/状态/`git user.name`（主动读取，常填真名）、平台信息；`metadata.user_id` = `{device_id, account_uuid, session_id}`，device_id 来自 `~/.claude/config.json`，**换号仍带同一 device_id**，具备多账号关联同一本机的条件。
- `event_logging/batch` 第一方遥测：默认 10 秒一批、单批 ≤200 条；`envContext` 含系统/运行时/工具链/终端编辑器（Cursor、VS Code、JetBrains 等）/部署环境（CI、Docker、K8s、云）/VCS；还有进程 uptime、内存、CPU 等「生命体征」；`rh` = git 远程地址归一化 SHA256 前 16 位（同仓库稳定映射）。
- **中转池结构性缺陷**：sub2api 类网关能复刻请求指纹（`cc_version` 消息指纹、`cch` 客户端证明、HTTP 头大小写），但池子账号 OAuth token 在中转服务器、不在用户本地进程，伴随上下文（遥测绑定、trusted devices、policy limits、登录链路）天然缺失——「单次请求做得再像，账号使用形态也不完整」。判断标准：使用痕迹是否像一个真实客户端在真实机器上持续连贯运行。

**中转站模型掺假鉴别（291619）**
- 商业模型黑盒（无梯度、采样随机），用**遗传算法**黑盒搜索最大化各模型响应嵌入距离的提示词；多模型用两两距离**乘积**而非求和（防偏科：某对距离趋零乘积即崩）；锦标赛选择 k=3；产出提示人工润色，避免触发商业模型安全拒绝。
- 判别器：冻结嵌入（all-MiniLM-L6-v2）→ 两个 Inception-1D 块（kernel 3/9/27/81 四分支多尺度）→ 尾部卷积 → 全局平均池化 → 全连接；Go 实现推理仅 15MB 二进制、CPU 毫秒级、200 行 WebUI，10 分类。

**梯度分析与权重编辑（290817，Qwen3-4B）**
- 拒绝行为由单一梯度方向介导；拒绝向量位置选 MLP `down_proj` 输出（叠加残差前，干预注意力几乎不可行——块间残差让 MLP 绕过注意力看输入隐状态）。
- 流程：PyTorch hook 采集 dp/res → PCA 可视化确认中间层拒绝方向成型 → 用**余弦相似度**选编辑层（SRC 与 DST 表示分开的层，如 15-24）→ LoRA r=1 直接合并：最小二乘 `u = (S_dd·s_dp - S_sd·d_dp)/(S_ss·S_dd - S_sd²)`，`ΔW = v ⊗ (uW)`，满足 `ΔW·s_dp = d_res - s_res`，编辑后模型拒绝一切提问。适用安全对齐研究。

**Claude 间接提示词注入样本分析（291126，SHub Stealer）**
- 攻击链：间接提示词注入 → Claude 输出嵌入伪装 Apple 安全更新的恶意命令 → 诱导用户复制到终端 → `curl | zsh` 落地。
- Dropper：双层编码（`base64 -D | gunzip | eval`，gzip OS 字段改 255 隐藏开发平台），heredoc 分隔符带 8 位 hex 后缀。
- 载荷（AppleScript，35KB/1086 行）：CIS 地理围栏（检测俄语键盘即退出）；系统密码钓鱼（`display dialog` + LockedIcon.icns，`dscl . authonly` 验证，重试 10 次全保存，成功后提取 Chrome 钥匙串主密码）；14 款 Chromium 浏览器 + Firefox 窃取，约 90 个钱包扩展 ID 硬编码（3 元组 {extension_id, flag1, flag2, flag3}，flag3=1 去 IndexedDB 找）；25+ 桌面钱包默认路径（单钱包 100MB 上限，排除 .DS_Store/Cache 等）；Electron **asar 注入** 5 款钱包（pkill → cp 到 /tmp → rm 原目录 → mv 回（绕过 TCC/SIP）→ 换 asar → `xattr -cr` → `codesign -f -d -s -` ad-hoc 重签，Ledger 系另换 Info.plist 提权）；伪装 Google Keystone 持久化（LaunchAgent 60 秒心跳，IOPlatformUUID 作 bot 标识，C2 响应携带 base64 命令落 `/tmp/.c.sh`）；分片回传（<85MB 直传 /gate，≥85MB 按 Wallets→KeyChains→Browsers→Telegram→Safari→Notes→Profile 分片 ≤70MB）。
- IOC：loader.sh SHA256 `efe6b07d573c788d1bae0a296fd1482fbbdc78ee8fefa04c287439349a60b68d`；C2 `babulikinet.com`（Cloudflare Anycast，注册仅 1 天）；Build Hash `e743990506148cbbcc2675048e5b6f78`。

### 六、大模型使用边界（293156，百亿 Token 实战经验）

- 大模型**没有逻辑思维**，本质是 Token 接龙，不维护可被证据推翻的假设。
- 安全场景：擅长暴力探索，但最易**钻牛角尖出不来**（例：扒出隐藏账号后坚信是 admin，反复失败也不怀疑题目描述是烟雾弹）；安全场景换模型无影响。
- 开发场景：架构设计、逻辑抽象、实现合理性是短板（参数该不该有默认值判断不稳定、同构数据意识不到是同一类），商用软件必须人工 Review。
- 补短板靠 **SKILL / COMMAND / MCP / PLUGIN** 自定义扩展机制；不自己部署主力模型（本地部署非优选）。
- 评价三阶段：真牛逼 → 傻子 → 重要助手。正确定位：**它蠢得很高效，产出的可用部分用，不可用部分再改**。

### 七、多 Agent 逆向工程框架：上下文状态机（291067）

- **问题**：AI 逆向五大痛点——古法主导 AI 辅助、上下文压缩丢信息、发散偏离轨道、不懂逆向手法只会 F5、爆上下文（注意力只看前和最后）。
- **架构**：主脑决策派发 + 子 Agent 拆分（上下文管理 / 逆向分析 / 审查），后续任务复杂可继续加子 Agent。
- **产物双分区**：
  - `.artifacts/`：类/方法/函数 YAML（类元数据、vtable、父类、字段偏移、方法清单；方法含地址/签名/证据/C 源码），`index.yaml` 主索引（地址→路径→kind）；
  - `.investigations/`：任务.md / 发现*.md / 待挖清单.md / 假设A-*.md 并行 / 结论.md，存思维链防二次返工。不用 sqlite/RAG——工具调用多、费 token、国产模型易漂移。
- **status 状态机（治幻觉核心）**：`draft`（worker 初稿）→ `wip` → `candidate`（fan-out 候选）→ `confirmed`（**仅用户拍板，AI 永远写不到**）/ `rejected` / `superseded`；worker 最高 candidate，judge 只出意见不改状态，审查 agent 只输出意见——任何 AI 产出都带置信度，多维证据验证后才可信。
- **版本与关联**：`<name>.yaml` 活跃版 / `.vN.yaml` 时间线历史 / `.bN.yaml` fan-out 互斥分支；`cross_refs/` 管理跨 dll 引用（从/到/关系类型 调用/虚表/数据/字符串/继承/证据）；函数→类方法文件迁移机制（写新位置→更新主索引→更新 class.yaml→删旧位置）。
- **Skills**：lift（人肉 F5）五步——骨架还原（控制流壳+占位符）→ 逐行机械翻译（asm→C 伪码，寄存器名不优化）→ 签名草稿 → 优化（约定寄存器/折叠中间寄存器/内存操作分类/lea）→ 语义折叠（算法模式+有意义变量名）；Class-identify——RTTI 优先→无 RTTI 给 ctor/thiscall 起点→vtable 列虚方法→thiscall 偏移聚类→`[this+N]` 成员清单，强制 YAML schema。
- **模型搭配**：opencode 主脑 DeepSeek-V4、干活 GLM5.1，国产/内网模型即可，不受制于 Claude。

### 八、AI 渗透的黑板架构：Cairn AI（291340）

- **问题抽象**：渗透 = **无限状态空间中的有向搜索**——起点已知、终点已知（拿 shell/flag）、中间路径未知；信息收集只是未知空间里的移动方式。
- **黑板架构**：Fact（已确认信息，图的节点）/ Intent（接下来做什么，图的边，执行完变 Fact）/ Hint（图外高维输入：人类洞见、题目线索）。
- **OODA 循环三种任务**：BootStrap（直接尝试，失败也把尝试和发现写回图）→ Reason（读整图推理下一步，产出 Intent）→ Explore（执行 Intent，结果写成新 Fact），循环直到某条边直连终点。
- **核心理念**：**没有任何一行代码定义渗透流程**——分工从运行时图涌现，Worker 互不点对点通信，只写 Fact/Intent 间接协调（蚁群信息素式涌现）。对比传统多 Agent（预定义角色=把人类残缺理解硬编码进架构，信息孤岛、翻译过滤损耗）。
- **Harness vs AI First**：Harness 预定义编排、可控可解释、适合可控维护任务；AI First 状态空间最小表达、涌现、适合目标直达的渗透任务。设计 Agent 系统 = 在**控制论与涌现**之间找平衡。
- **启示**：堆工具前先想清问题本质结构，找最小表达再构建——Think-First，AI 只是之后的事。

### 九、AI 逆向取证与协议验证方法论：银狐 C2 复盘（293005）

- **案例**：84 字节通信帧 `[4B 小端负载长度][16B IV][64B AES-CBC 密文]`，密钥 `MD5(b"6153")`（IL 链：UTF8→MD5→stsfld）；三层结构：AES 解出 53B → **QuickLZ 压缩层**（标志位 0x4E/0x4F 最低位=压缩标志、存储长度/展开长度两个 U32、`00 00 00 80` 是控制字不是分隔符）→ **NetSerializer TLV 字符串**（`05 02`=4+1 字节+2 码元，UTF-16 码元数≠字节数）。
- **输入治理先行**：先哈希去重（23 文件→21 唯一）、剔除自测流量（`GET /selftest`）与重复写盘，明确每份输入的来源；文件名时间≠内容时间，不能画毫秒级行为轨迹。
- **分层验证纪律**：
  - 长度声明必须核对完全消费，声明 36 实际 44 的矛盾不能被"EXACT"包装；
  - **测试的名字没有权威性，决定价值的是失败条件**；
  - 宽容解码（`decode('utf-8','replace')`）掩盖异常是错误，严格解码的报错是下一层结构的路标；
  - 熵值要打印样本长度和理论上限（64B 密文上限 log2(64)=6，套"接近 8 才是加密"不成立），熵不能认算法；
  - 相关≠定义：`0x4F` 帧出现"管理员:"标题是假相关，全量反例推翻；
  - 观测≠推断："没响应"≠撤服、"没记录"≠没发生、进程无端点≠从未外发；本地监听器结果≠远端已接收。
- **AI 的正确用法**：把分散材料组织成可检查清单（文件数/来源/重复/自测/二次报告）；把每个怀疑变成可执行实验（哈希分组、反例遍历、控制字偏移跟踪）；把运行响应/完整代码/公开样本/私密证据分开整理。**不用"另一个 AI 也同意"作终点**——换验证方向（语义退回长度、几份样本扩展到全部输入、正向运行走向刻意失败）。
- **可复用提示词**：列输入与哈希 → 每个字段假设给偏移/长度/支持样本/反例 → 外层帧、加密、压缩、序列化分层验证不跨层解释 → 不用宽容解码 → 检查每个长度声明完全消费 → 不复用旧通过条件、写明确失败条件 → 人工数据测截断/超长/多字节/非 BMP → 全量运行 → 分别列出验证通过的结构、尚不支持的输入、未确定的语义 → 没运行过的只能标建议或推测。

### 十、Agent 层安全：间接提示词注入与 MCP 供应链投毒（290496）

- **对齐的盲区**：SFT+RLHF+红队只覆盖模型"看得到"的东西（用户输入/网页内容/工具返回）；工具内部行为、网页 JS 后台请求、MCP 源码里的东西模型看不到。综述结论：所有已知防御（Prompt Hardening/LED/Circuit Breakers/Safe Decoding）**全部作用于 prompt/model 层，无一覆盖工具执行层**；自动化黑盒攻击商用模型成功率 80-94%。
- **间接注入四实验**：
  1. 直接命令（`[SYSTEM NOTICE]` 等）→ 全被识破，对齐对已知模式有专门训练；
  2. 上下文操纵（伪装安全 Bug Report，可信用户层层确认+复现步骤）→ AI 主动读 storage 全展示，**零防御意识**（印证 PAP 智能悖论：越强越易被情境操纵）；
  3. 字符串反转混淆 SDK + Tracking Pixel 外传 → 数据外传成功但 AI 读源码识破，**简单混淆对 LLM 透明**；
  4. 完整链：同源代理（页面与收集同端口）+ XOR 加密 + obfuscator.io 混淆（280 行→218KB）+ `setTimeout(0)` 劫持 `Dashboard.getState()` + "半坏"页面诱导 → 被动+主动外传均成功，AI 全程零感知。
- **MCP 供应链投毒**：fork js-reverse-mcp，在 `navigate_page`/`evaluate_script`/`get_storage`/`take_screenshot`/`get_network_request` 五个 handler 植入后门（每工具 6-89 行），101 行 `c2.ts` 集中外传（fire-and-forget、错误静默）；工具名称/描述/参数/返回值完全不变，**接口层面就是正常 MCP**；正常提示词即触发，AI 零感知。供应链攻击绕过 AI 推理链路，prompt/model 层防御全无效；数据外传发生在 AI 分析之前，**检测≠阻止**。
- **要点**：上下文操纵 > 直接命令；LLM 代码分析有阈值（简单混淆无效、专业混淆有效）；攻击影响超出当前页面（浏览器全部站点 cookie/localStorage）；对敏感工具调用加人机确认、工具行为沙箱化 + 运行时审计是仅有的防线。

### 十一、AI 分析 Web 漏洞实战：缓存投毒（291104）

- **案例**：Next.js App Router + nginx 缓存 + Puppeteer Bot，XSS 窃取 flag Cookie。
- **关键突破——空 RSC 头**：base-server.js 严格匹配 `req.headers['rsc'] === '1'`（按普通请求路由），app-render.js 宽松匹配 `headers['rsc'] !== undefined`（按 RSC 渲染、输出 flight data **不做 HTML 转义**）。发 `RSC: ""`：前者按普通请求走、后者按 RSC 渲染 → nonce 未转义。
- **Vary 绕过**：nginx 用 `$http_rsc` 取请求头值，**缺失头与空串头等同**（都当空字符串），故 Bot 不发 RSC 与投毒发空串的二级键匹配 → HIT。
- **投毒四要素**：路径必须 `/_next/` 开头（nginx 只缓存该 location）；投毒时手动 `Host: proxy:4000` 对齐 Bot 的缓存主键（`$request_method|$scheme://$host$request_uri`）；AE 用 `X-Proxy-Cache` 响应头探测反推 Bot 精确值（如 `gzip, deflate`）；中间件 Content-Type 覆盖把 flight data 的 CT 改成 `text/html`。
- **无外网 exfil——缓存中缓存**：XSS `fetch('/_next/exfil', {headers:{'Content-Type':'text/html','RSC':'','x-nonce':'STOLEN:'+document.cookie}})`，Cookie 经 nonce 未转义进 flight data 被 nginx 缓存，攻击者再读该路径。
- **黑盒探测**：HTML 搜 `nonce` 关键字 → fuzz `x-nonce`/`x-csp-nonce`/`nonce` 头看反射；两次请求对比 CT 看中间件覆盖；不同路径两次请求看 `X-Proxy-Cache` 是否 HIT；`X-Powered-By`+`main-app` chunk+`_buildManifest.js`（buildId 拼接）确认技术栈，下载对应版本源码灰盒分析。
- **验证**：Step2 投毒后不带 RSC 的请求 `X-Proxy-Cache: HIT` 且 XSS 仍在；Step4 缓存中出现 `STOLEN:flag=...`。

### 十二、AI 原生协议还原：tracedb + 自定义 MCP（291533，nSign）

- **场景**：VMP/扁平化控制流/白化常量/反调试淹没下的算法还原，反编译伪代码前瞎猜无效。
- **工具链**：ARM64 trace → 自定义 tracedb（mmap 定宽行 + addr/value/reg 索引，几十 GB trace 秒级查询）→ user-trace-MCP → AI 结构化查询 → Python assertion 固化证据。
- **核心原则**：**从输出开始，不从算法名开始**——看到 32B 不叫 SHA-256，看到 S-box/GF 不直接宣布 AES。链路：output slice → first real producer → producer operands → operand producers → PC/template/count → arithmetic proof → Python reimplementation → cross-run validation。
- **MCP 查询工具**：`find_value_occurrences`（找值首次出现，但同值≠同源）、`get_producers`/`walk_dataflow`（跳过 transport 找真实计算 producer）、`get_pc_stats`/`get_pc_executions`/`analyze_pc_sequence`（数 round、找重复模板、定首尾边界）、`taint_trace_origin`（字节级反向污点）、`get_call_at`/`list_calls`/`find_callers`（识别 rand/read/JNI 外部来源，追不到时给出明确结论"这是外部来源"）。
- **错误路线地图（局部现象≠算法结论）**：KEY16（实为末轮密钥 RK14^0x55 白化快照）、"Saw"明文误判（中间槽值经 nibble 重组/白化/S-box 而来）、HKDF（局部 HMAC 证据≠整段 HKDF，先定 I/O 边界再跑标准库）、五段 SHA 拼接、自定义 byte-mixing VM（VM 是承载层，AES 是承载的计算）、非标准 AES。
- **证明方法**：计数（pc 出现次数=8 blocks×15 groups×16 bytes=1920 给 AES-256 轮数轮廓）→ 末轮 SubBytes^RK14 → 中间轮 SubBytes/ShiftRows/MixColumns/AddRoundKey 逐字节对 → key schedule 展开对 → 端到端前向 AES256(P0^A,K)==B0 逐字节相等。
- **反调试教训**：目标枚举 `/proc/self/fd` 而 trace 工具自身不断制造 fd → procfs readdir 死循环，被当成算法复杂度；用 PC 统计+调用统计+unidbg 对照区分采集环境与程序行为。

## 十三、Android 逆向 Agent：r0re 黑板架构（292470）

- **定位**：Cairn 架构 Java 重写 + Android 逆向工具/提示词/验证，解决"工具间切来切去、结论说不清来源、候选错了要重开对话"三个痛点。
- **黑板三类对象**：**Fact**（已确认发现，如 Manifest 入口、JNI 映射、Frida hook 参数、已导出 dex）、**Intent**（下一步可独立工作，如定位 RegisterNatives 注册表、复现 AES 解密链）、**Hint**（人为约束方向，如"先检查 libmobisec.so""候选必须真机输入通过后才可结束"）。Worker 围绕黑板读写间接协调，**无固定角色切分**。
- **架构**：WebUI/HTTP API → SQLite 黑板（projects/facts/intents/hints/runtime_events/completion_candidates/verification_intents）→ Dispatcher（bootstrap→reason→explore→verify→finalize，**serve+dispatch 双进程**分离模型调用与分析现场）→ Docker Worker（jadx/apktool/readelf/Frida/ADB/自定义 solver）。
- **关键设计**：候选答案进独立 verification/finalize 流程，**验证失败保留失败痕迹不覆盖**；`dead_end` 也作事实保留（如"静态 dump 无解密代码页"）避免重复搜索；**Flag 含金量分级**——strings 所见 ≠ memcmp hook 结果 ≠ 本地脚本正逆向跑通，用 `verified`/`kind`/artifact 路径分开保存。
- **验证**：看雪 Android CTF 9 题全通，首候选错时补 Hint 重新收敛而非重开。

## 十四、常驻式插桩：Shadow Cave 架构（292354）

- **问题**：高频逐次观测下，异常往返（BRK/XOL 约 401ns/op，百万次 401ms）成主要开销；直接改代码页破坏进程对自身代码的原始视图。
- **核心**：在 wxshadow **original/shadow 双视图**上，于 shadow 执行视图的已证明区域生成观测代码，页内分支进入 Cave，完成 ARM64 指令重定位+寄存器状态观测后返回原始控制流——**稳态命中不进内核、不单步、不经运行时回调，观测本身成为普通指令流**（4.5ns/op，百万次 4.5ms，近两个数量级）。
- **双视图契约**：CPU 取指 → shadow PFN（anchor 变 B cave，页内含 Cave 代码）；普通数据读取 → original PFN（仍是原始字节）；完整性检查/GUP 在契约覆盖范围内仍观察 original。
- **分层通道**：低频一次性锚点（需改寄存器或无法安全重定位）走 BRK/XOL 异常通道（语义兜底）；满足死区证明与重定位约束的高频锚点进 Cave（吞吐）。
- **需解决的工程问题**：页内死区证明、ARM64 指令重定位、lease 观测与事务化退役、signal/fault/fork/mprotect/并发退役正确性（精确 PC 相位、rendezvous、logical retire、代际 tombstone）。
- **验证**：真机重定位对拍、逐次寄存器观测、并发退役、fork 隔离、signal/fault 矩阵、真实 Android 应用负载。

## 十五、移动加固全链路实战：银行 App 梆梆 + Go 纯 crypto（292885）

- **四块硬骨头**：梆梆 DexHelper 抽取壳、反 Frida 主动自毁、Go 纯 crypto/tls 网络栈（不走系统库）、加密 JS bundle（无明文可读）。
- **反 Frida 自毁特征**：`Fatal signal 11`、`fault addr` 与 `pc` 同落低地址（如 0x97c，比任何合法映射都小）、`lr/sp` 被清零、backtrace 仅 2 帧全 `<unknown>`——**控制流被劫持跳未映射低地址**，是加固壳主动自毁典型手法。
- **核心教训**：**"App 能稳定运行"≠"绕过了反 Frida"，只是"没开 frida-server"**；对照实验一次只变一个变量（手贱拉起 frida-server 会打回原形）。
- **路线撞墙与破局**：eCapture 挂系统 TLS 库→Go 不走系统库无效；Frida→自毁；内核 HWBP→受限。最终靠**定制系统任意 so 注入 + 自写 arm64 inline hook**，在 `libgojni.so` JNI 业务入口落地登录参数与响应头。
- **验证**：登录请求四件套（URL/headers/body/response）完整落地。

## 十六、Google Play PairIP 自动保护对抗（292523）

- **三件套**：代码虚拟化 + TEE 硬件密钥 + 运行时反篡改，Play 侧自动套上。
- **静态特征**：`libpairipcore.so`（VM 解释器+反篡改）、`com.pairip.*` 包、assets 顶层随机名无扩展名文件（加密 VM blob）、Play 版多 split（`gpdeku` 密钥下发载体）。关键类：StartupLauncher（驱动 VM 初始化）、VMRunner（运行器）、VmDecryptor（字节码解密）、SignatureCheck（`$SignatureTamperedException`）、InitContextProvider（Application 前跑的 ContentProvider）。
- **启动次序**：InitContextProvider 抢跑拿密钥→校验通过才换真实组件+StartupLauncher 驱动 VM，任一环不过替换占位实现+进程自退。被虚拟化方法在 dex 只剩 `VMRunner.invoke("编码签名", args)`。
- **密钥门**：密钥在 TEE，需 PlayIntegrityFix 过 Play Integrity，服务端才签发 TEE 密钥；无密钥则退出。
- **验证**：真机跑到交互态，用 `\x00IAP` 头作判据把 VM blob 解密落盘。

## 十七、TVM 去虚拟化：tvm-recover（293277）

- **场景**：Tencent VM（ACE 壳）去虚拟化，常规 SMT 求解恢复时间极长且有毛病。
- **方法**：**不用 SMT 求解器**，纯数学代数化简。流程 `.tvm0 → 语义提升与代数化简 → guest IR → LLVM 编译 → PE 写回 + PDB → IDA/Ghidra`。
- **核心**：跟踪 guest 寄存器与内存变化，化简调度过程中可抵消的计算，恢复控制流；生成入口桥接桩（新入口先跑分析 payload，再按自身地址+RVA 找原入口交回控制权）。大函数拆多切片由生成调度器连接。
- **成果**：121 个恢复函数完成编译并通过与解释器的差分检查；恢复后 Ghidra 反编译可见条件判断/寄存器更新/分支，寄存器成员（t_rcx/t_rdx/t_rax）对应 guest 寄存器。
- **验证**：与解释器差分检查，恢复代码在分析器中可顺结构化结果继续分析。

## 十八、VT-D 对抗与 VT 调试器重建（293258 / 292825）

> 通用原语详见 `common-techniques.md §3`（VT-D 对抗与 DMA 防护）、`§2`（NPT/EPT 虚拟化 Hook）。本节侧重方法论与实战流程，原语细节不重复展开。

- **DMA 防护（VT-D）**：UEFI 模式 Type1 Hypervisor 在设备访问内存路径上加硬件控制。自定义 Hypervisor 建转换表规定设备请求地址对应物理内存及读写权限。三步：①确定保护范围（记录 Hypervisor 映像+数据池物理范围）②配置映射权限（普通内存原址映射，受保护范围映射到 0xFF 填充替代页只读）③硬件执行保护（读得替代页内容，写被 VT-D 阻止）。VTD 一对多绑定 DMA 设备，上限推荐 4；经 MMIO 控制 VTD 物理硬件，DMAR 表经 ACPI/EDK2 `EfiLocateFirstAcpiTable` 获取。
- **DMA 旧时代对抗**：CR3Fix（混淆 CR3，执行时回调回填+异常接管）；HAL HOOK（劫持 HAL 回调地址全局变量）。
- **EPT/NPT Hook 三种**：①无痕 Hook（整页读写无效只留可执行，P2 改绝对跳转，读写触发 Violation 切换，缺点自读自跳无限 MTF 卡死）；②仿内存执行断点（全程可读写不可执行，MTF Handler 恢复，4KB 页高频访问巨卡）；③MTF 置位全程可执行（最适合，读写触发 Violation 设 MTF，MTF VM Exit 判断后恢复）。核心：**读与执行分离**，读出正常、执行另一套代码，绕内存检测/PatchGuard/CRC。
- **重建调试体系**：全局维护 g_Debuginfo 双向循环链表，hook `NtDebugActiveProcess` 插入独立 DebugObject，通过 PID 查自己的 DebugObject，**不走 Process->DebugPort**（该字段在 Windows 调试体系下无法隐藏）。两种虚拟化调试器对比：无附加读写（驱动直读物理内存，VT MFT 单步，完全无痕但实现难度大、脱离主流生态）vs 重建调试体系（EPT/NPT hook 重写 Windows 调试体系对接传统调试器，代码量小稳定但易被检测）。

## 十九、VMProtect 授权锁 RSA 另类 Bypass（293138）

- **原理**：VMP 授权锁=基于 RSA 的代码级授权绑定。受保护函数核心代码被抽离加密转虚拟化指令，运行时依赖 8 字节 ProductCode 解密因子，封存在序列号中，VMP 用内置 RSA 公钥指数 e 和模数 n 解密序列号提取 ProductCode。
- **常规思路（替换 n）的痛点**：动态调试定位 n 载入 Bignum 时内存替换——新版 VMP 的 n 不以连续明文暴露；静态还原 VM 指令找加密 n——代价极高、版本间算法不一致复用差。VM 运算区真假写入难辨，黑盒下拼 n 片段大海捞针。
- **另类思路（改 e）**：数学原理——任何数 1 次方=本身；e 改为 1 后 `c^1 mod n`，因 c<n 故 `c mod n = c`，退化为输入=输出，**不碰黑盒 n**。
- **实操（VMP 3.10.6）**：Base64 解码函数断点→硬件访问断点定位密文转大数→大数运算函数断点（尚未真正运算处）→在 VM 内存工作区搜索喂给解密函数的参数（指针/长度必然实体化，暴露标准密码学组件内存布局），找到静态 e 的相对位置改 1。
- **验证**：改 e=1 后任意序列号均授权通过。

## 二十、Chromium ABE 解密工程化（293071）

- **目标**：无需 UAC 提权、无视浏览器独占锁，读取解密 Cookie/密码。
- **数据存放**：`Local State`（JSON，存 DPAPI/ABE Key）+各 Profile 目录（`Network\Cookies`、`Login Data` 为 SQLite，`encrypted_value`/`password_value` 为 Blob）。
- **加密格式**：`v10`/`v20` 版本号(3B)+nonce(12B)+AES-256-GCM 密文+tag(16B)，AAD 为空。
- **密钥 Envelope**：`Local State` 的 `os_crypt` 节点——`encrypted_key`=Base64("DPAPI"前缀+DPAPI Blob) 存 v10 Key；`app_bound_encrypted_key`=Base64("APPB"前缀+ABE Blob) 存 v20 Key。
- **v10**：Windows DPAPI（`CryptProtectData/CryptUnprotectData`），**同用户任意进程可解**。
- **v20**：App-Bound Encryption，需解 ABE Blob。
- **明文格式**：Cookie=SHA256(host_key)+cookie 值（防跨站拷贝复用）；密码=密码本身。
- **验证**：PoC AbeDecrypt 获取 v10/v20 Key 并解密 Cookie/密码。

## 二十一、PC 调试器 MCP 自动化（293257 / 292993）

- **z0bdbg MCP（293257）**：给自研调试器写专用 MCP，C++ 写仿 codex 的逆向 agent 终端，支持 101 个接口+101 个 tool list 给 AI 自由选择工具函数自动分析。
- **x32dbg MCP（292993）**：MCP 桥接 AI 远程操控 x32dbg，三轮演进——第一代社区 HTTP 插件；第二代 x64dbg-automate 原生 ZeroMQ（三大调试实验从 10 分钟+压缩至约 2 秒）；第三代官方 x64dbg-automate MCP 服务器，48 个标准化调试工具，零硬编码路径、纯离线依赖、拷贝即用。
- **选型**：官方 MCP 服务器标准化程度最高；自研 MCP 接口数多但需自行维护；ZeroMQ 原生通道性能最优。

## 二十二、ROP 返回导向编程（293304）

> 通用原语详见 `common-techniques.md §7.1`（ROP）、`§7.2`（PoolParty 线程池注入）。本节侧重实战布局与流程。

- **原理**：ROP 链布局在栈内存中，形如 8 字节数组，成员是 gadget 地址（实时获取填入）和立即数，**栈被赋予控制执行流程的重任**。区别于 ShellCode（代码控制流程、栈传参互不干扰）。
- **实战布局**（notepad.exe 弹 MessageBox）：1MB 远程内存自高地址向低分三区——A 区 4KB ROP 主链（控制中心）、B 区 4KB 数据区（字符串）、C 区剩余 MessageBoxA 专用栈及返回主链预留。
- **入口 gadget**：`push rcx; pop rsp; ret`（chain entry pivot），`CreateRemoteThread` 的 lpStartAddress 指向该 gadget、lpParameter 传 A 区基址。ROP 链依次调 MessageBoxA、RtlExitUserThread 安全退出。
- **验证**：notepad.exe 弹出 MessageBox 并安全结束。

## 二十三、PoolParty 线程池注入（293254）

- **原理**：Windows 线程池复用工作线程执行短生命周期任务，恶意软件利用此机制执行代码，避免直接调 `CreateRemoteThread()` 降低被检测。PoolParty（SafeBreach BlackHat Europe 2023）8 种变体注入。
- **默认 vs 自定义线程池**：默认池由系统管理直接提交工作；自定义池用 `CreateThreadpool()` 创建，可设线程数，经 `TP_CALLBACK_ENVIRON` 回调环境关联任务。`TrySubmitThreadpoolCallback()` 第三参数 NULL=默认池，传 cbe=自定义池。
- **WorkerFactory 注入**：向目标进程默认线程池灌阻塞任务占满工作线程，迫使目标用自定义池执行回调，回调中跳转恶意代码。
- **验证**：C 语言重实现 PoolParty WorkerFactory 注入，目标进程执行注入代码。

## 二十四、Win11 内核异常体系与无痕 Hook（292876）

> 通用原语详见 `common-techniques.md §4`（Win11 内核异常体系与接管）。本节侧重利用点分析与实战流程。

- **KVA Shadow**：内核页表隔离后进程有 2 套 CR3（KPROCESS.DirectoryTableBase 存内核态 CR3），R3 用残缺页表（完整用户态+KVASCODE 节区小部分内核态），进内核后切完整页表。
- **异常派发链**：`#DE`（向量号 0）→IDT 第 0 项→`KiDivideErrorFaultShadow`（KVA 开启时）→`KiDivideErrorFault`→`KiExceptionDispatch`→`KiDispatchException`（构造 Context、错误码转换、R0/R3 FirstChance/SecondChance）。
- **三种提前接管异常利用点**：①`ntdll!KiUserExceptionDispatcher`/`Wow64PrepareForException`（用户态异常）；②`nt!PsPicoDispatchException`+注册 PicoProvider+WSL 子进程（用户态+反调试+进程保护）；③替换 Hal 函数指针（Win11 25H2 及以下，特征码定位 HalpPerformanceCounter，堆栈回溯恢复异常信息，构造中断返回帧）。
- **无痕 Hook 实验**：制造影子模块（ShadowModule）→向目标函数页面注入异常（隐藏不可执行页面）→修复 CFG→修复全局变量不一致→挂 Inline Hook。
- **验证**：三种接管点分别实现无痕 Hook/反调试/进程保护。

## 二十五、内核免杀与系统机制劫持

> 通用原语详见 `common-techniques.md §5`（PEB 遍历/ntdll 基址/KnownDlls 劫持）、`§1`（全架构 Hook）。本节侧重各原语的组合实战。

- **不调 API 找 ntdll 基址（292791）**：EDR 在 ntdll Nt* 入口插 inline hook 或 hook kernel32，走 GetProcAddress 必被检测。绕过：从 PEB 直接取 ntdll 基址，自己算函数地址直接调，不经任何可被 hook 的 API。x64 下 `gs:[0x60]`（`__readgsqword(0x60)`）取 PEB（TEB+0x30）；PEB.Ldr 指向 PEB_LDR_DATA，选 `InMemoryOrderModuleList`（Ldr+0x20，**哨兵头节点**，Flink 指向第一个真实模块）；`LDR_DATA_TABLE_ENTRY.DllBase` 从 curr 算 **+0x20**（+0x08 是 Blink 后向指针，易错）。验证：代码编译运行输出 ntdll 基址。
- **KnownDlls Section 劫持（292539）**：KnownDlls 启动时为常用系统 DLL 各建 SEC_IMAGE Section 放 `\KnownDlls\`，加载器查此目录直接映射。劫持：驱动关掉原 Section、建同名 Section。关键：KnownDlls Section 是**永久对象**（OBJ_PERMANENT），ZwClose 只减句柄计数，指针计数不归零不删。解法：先 `ZwMakeTemporaryObject` 降级为临时对象再 ZwClose，句柄归零后系统删名称并调整指针计数。验证：WinObjEx 确认原 Section 关闭、自建同名 Section 生效。
- **EDR 不可见网络通信（292235）**：lwIP（嵌入式 TCP/IP 栈）移植到 Windows NT 内核驱动，内核态直接收发包绕 Winsock。分层：lwIP 核心→ethernetif.c（pbuf↔NDIS）→protocol.c（NDIS 5/6 双路径）→miniport.c+dma.c→ndishook.c（JMP 补丁拦 ndis.sys）→sys_arch.c。关键：零拷贝接收（`pbuf_alloced_custom(PBUF_REF)` 持有 NDIS 缓冲区外指针，引用计数管理）；SG DMA 散列汇聚（三级降级：SG DMA+预分配/SG DMA+临时/普通 DMA 合并）；内核态 Hook（改 CR0.WP 写 JMP，x64 触发 Kernel PG）。验证：内核驱动经物理网卡收发，EDR 检测不到用户态通信。
- **NPT 无痕 Hook（291859）**：Hook 四代演进——①表项替换（易检测）②Inline Hook（CRC 可发现）③绕过修改（硬件断点有限/VEH 可遍历/回调受限）④**硬件虚拟化 Hook**（SLAT/EPT/NPT，Hypervisor 控制物理页 R/W/X 权限，CPU 硬件层面 Guest 看不见）。NPT 优势：代码页零修改、PatchGuard 无感知、NPT 页表 Guest 不可读、Ring -1 特权级、不依赖未文档化接口。实现：塞系统进虚拟机→建 NPT 页表→NX 位取指陷阱→影子页（读见 original/执行见 shadow）→跳板→NPF 与 #BP 联动→复位卸载→Hypervisor 反侦察→多核/TLB/中断处理。验证：Hook 后内存字节不变，PatchGuard 不报篡改。
- **Windows 全架构 Hook 图谱（291370）**：按隐蔽性从低到高 34 种，第一层用户态 Hook（IAT Hook 等），每层提供完整可编译实现。IAT Hook：改导入地址表函数指针，检测★（遍历 IAT 对比地址或 CRC 即暴露），局限只能 Hook IAT 调用。

## 二十六、验证清单

- [ ] 样本建档完成（原样本 SHA-256 记录，文件类型/架构/编译器/安全标志已标注，原始副本保留）
- [ ] 保护类型识别准确（加壳/反调试/混淆/VM 类型判断正确，按处理顺序铁律排优先级）
- [ ] 证据驱动（关键结论有运行时行为/抓包/内存快照佐证，不靠类名/注释臆测）
- [ ] 两层确认（关键结论至少两个独立工具交叉验证，如 GDB+Frida、strace+ltrace）
- [ ] 不硬编码（地址/偏移/密钥从样本推导，无照搬示例值）
- [ ] 可运行优先（交付的镜像/补丁验证能跑，非"能解析"冒充"能运行"）
- [ ] 不破坏业务（patch 只改目标校验，登录/授权/网络等正常路径保留）
- [ ] 案件目录结构完整（`case/` 下 evidence/raw、evidence/derived、notes/timeline、report 齐全）

## 二十六·五、代码骨架：逆向案件管理骨架

> 可运行的 Python 骨架，建立案件目录、记录证据哈希、生成时间线。关键路径按样本替换。

```python
# case_manager.py — 逆向案件管理骨架（Python）
# 建立案件目录结构，记录证据哈希，生成时间线

import os
import hashlib
import json
import datetime

CASE_DIR = "[CASE_DIR]"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def init_case(case_name):
    """建立案件目录结构"""
    dirs = [
        "evidence/raw",
        "evidence/derived",
        "notes",
        "repro",
        "tests/fixtures",
    ]
    for d in dirs:
        os.makedirs(os.path.join(CASE_DIR, case_name, d), exist_ok=True)
    print(f"[init] case dir created: {os.path.join(CASE_DIR, case_name)}")

def record_evidence(case_name, evidence_path, evidence_type="raw"):
    """记录证据：计算哈希，写入清单"""
    evidence_dir = os.path.join(CASE_DIR, case_name, "evidence", evidence_type)
    os.makedirs(evidence_dir, exist_ok=True)

    # 复制证据到 evidence 目录（保持原始不动）
    import shutil
    dst = os.path.join(evidence_dir, os.path.basename(evidence_path))
    shutil.copy2(evidence_path, dst)

    # 记录哈希与时间戳
    hash_val = sha256_file(dst)
    timestamp = datetime.datetime.now().isoformat()
    record = {
        "file": os.path.basename(evidence_path),
        "hash": hash_val,
        "timestamp": timestamp,
        "type": evidence_type,
    }

    # 追加到证据清单
    manifest = os.path.join(CASE_DIR, case_name, "evidence", "manifest.json")
    manifest_data = []
    if os.path.exists(manifest):
        with open(manifest) as f:
            manifest_data = json.load(f)
    manifest_data.append(record)
    with open(manifest, "w") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)

    print(f"[record] {os.path.basename(evidence_path)} -> {hash_val[:16]}...")
    return hash_val

def log_timeline(case_name, event, detail):
    """记录时间线事件"""
    timeline = os.path.join(CASE_DIR, case_name, "notes", "timeline.md")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(timeline, "a") as f:
        f.write(f"## {timestamp}\n")
        f.write(f"- **{event}**: {detail}\n\n")
    print(f"[timeline] {event}: {detail}")

if __name__ == "__main__":
    case = "[CASE_NAME]"
    init_case(case)

    # 记录样本
    sample = "[SAMPLE_PATH]"
    record_evidence(case, sample, "raw")
    log_timeline(case, "样本建档", f"SHA-256: {sha256_file(sample)[:16]}...")

    # 记录分析产物
    log_timeline(case, "保护识别", "判断为 UPX 加壳 + OLLVM 混淆")
    log_timeline(case, "脱壳完成", "OEP 定位成功，内存 dump 完成")

    print(f"[done] 案件管理完成: {os.path.join(CASE_DIR, case)}")
```

运行：`python3 case_manager.py`。验证：案件目录结构完整，证据哈希记录在 manifest.json，时间线可追溯，原始样本只读未修改。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §通用工作流使用

## 十九、大规模二进制集全量画像（批量 PE 画像方法论）

> 场景：一次拿到几百个 PE（安装包解包产物、引擎套件、套件目录树），需要先建立全局基线再决定主攻点，而不是逐个打开。

### 19.1 核心思想：先画像，再判断

拿到大样本集（如 426 个 PE / 326 MB）时，**第一轮不做深度分析，先做全量画像**：用统一脚本对每个文件记录同样的维度，输出成一张表（TSV），再在表上做统计、聚类、排序。这一步能直接推翻或确认第一轮的预判，并给后续每个模块的深度分析提供坐标。

关键判例：某安全软件套件第一轮预判「难点在壳」，全量画像后发现**壳只覆盖 2/426**——真正的壁垒是内核驱动面、100% 有效签名、云端策略。画像用数据修正了判断，避免把主攻方向押在壳上。

### 19.2 全量画像的六个维度（28 列 TSV 模板）

按用途把画像列归为六组，每行一个 PE，输出 `payload_pe_scan.tsv`：

```
├── 身份面
│   ├── path / rel     相对路径
│   ├── arch           x86 / x64
│   ├── size           字节数
│   └── sha256         内容指纹
├── 结构面
│   ├── machine        IMAGE_FILE_MACHINE_*
│   ├── sections       节名清单
│   ├── ep             入口点 RVA
│   └── ep_section     入口点落在哪个节
├── 保护面
│   ├── packer         识别出的壳（节名映射表，见 19.3）
│   ├── entropy_all    全文件熵
│   ├── entropy_text   .text 熵
│   └── overlay        是否有段后数据
├── 导入面
│   ├── import_dlls    导入 DLL 清单
│   ├── key_imports    关键 API（按语义分组的兴趣 API 表，见 19.4）
│   └── import_count   导入总数
├── 签名面
│   ├── signer         签名主体
│   ├── valid          Valid / Invalid / None
│   └── timestamp      时间戳时间
└── 分类面
    ├── subsystem      目录归类（按目录名分功能区）
    ├── is_driver      .sys 与否
    └── verdict_hint   判定提示
```

### 19.3 壳识别节名映射表

脚本内置 `PACKER_SECTIONS` 字典，节名小写化后查表，命中即记录壳名（带 `?` 的是低置信）：

```
UPX        upx0/upx1/upx2、.upx0/.upx1
VMProtect  vmp0/vmp1/vmp2、.vmp0/.vmp1/.vmp2、.vmp
Themida    .themida/.winlice/.boom
Enigma     .enigma1/.enigma2/.enigma
MPRESS     .mpress1/.mpress2
Petite     .petite
ASPack     .aspack/.adata
NsPack     .nsp0
PECompact  pec1
通用       .packed / protect（低置信）
厂商自有    .wow0 / .wow1 → "360-wow"（厂商自有保护节，需按样本总结）
```

**注意**：`.sys` 驱动入口点落在 `INIT` 段是 WDK 把初始化代码标记为可丢弃的标准写法，**不是加壳特征**——不要把编译器行为误读成保护。

### 19.4 兴趣 API 表（按语义分组标记模块职能）

画像脚本内置兴趣 API 表（约 28 项），按语义分组，标记每个 PE「实际做什么」：

```
设备与系统信息：DeviceIoControl / NtQueryInformationProcess /
                NtQuerySystemInformation / GetSystemFirmwareTable /
                CreateToolhelp32Snapshot
服务与注册表：  CreateServiceW/A / OpenSCManagerW / RegSetValueExW / RegCreateKeyExW
网络：          WinHttpConnect / WinHttpSendRequest / InternetOpenW
加密：          BCryptEncrypt / CryptEncrypt / CryptAcquireContextW
驱动装载：      LoadDriver / NtLoadDriver / ZwLoadDriver
内存与注入观测：MiniDumpWriteDump / SetWindowsHookExW / CreateRemoteThread /
                WriteProcessMemory / VirtualAllocEx / SetThreadContext
权限：          AdjustTokenPrivileges / WTSQuerySessionInformationW
```

原则：兴趣表不区分善恶，只记录「谁导入了它」——防守方 API（DeviceIoControl 用于自我保护）和攻击面 API（CreateRemoteThread 用于行为检测）都记录，价值判断留给读报告的人。

### 19.5 熵作为格式指纹

纯 Shannon 熵实现：

```python
import math
def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts if v)
```

用法：`.enc` 文件熵 ≈ 8.00（加密/压缩），`.dat` 文件熵 ≈ 3.78（明文结构表）——**一眼分开两类数据文件**，为后续容器格式分析提供优先级。

### 19.6 分析纪律：只读、不执行

- **`pefile` 是「读文件格式的库」不是「加载器」**：画像脚本只解析 PE 结构，不 LoadLibrary、不创建进程、样本不联网。
- 结论的形态边界要写清楚：

```
能拿到：入口在哪 / 码表是什么 / 导出导入长什么样 /
        格式长什么样（容器头字段、熵指纹）/ 分类字符串的语义
拿不到：实际运行态判定结果 / 云查真实返回（策略在服务端）/
        驱动实际拦截行为（未加载）/ 任何运行态证据
```

### 19.7 构建指纹：PDB 泄露的 CI 布局

大量 PE 的 `.rdata` 里残留 PDB 绝对路径，是构建机环境的化石：

```
<构建机>\bin\joblist\<编号>\src\<分支>\<模块>\objfre_<平台>\<架构>\<模块>.pdb
```

按 joblist 编号和 src 分支聚类可还原并行构建线：
- 同一批 PDB 的模块 = 同批构建（如 AVEngine.dll 与 AVEI.dll 同批）；
- 分支名带年份（如 `hookport_2014_sys`）说明组件沿用年代；
- 路径中残留的源码文件名（如 `adrules.c / capfilters.c / rpcblock.c / rules.c`）可直接反推模块内部分工——注意这是**命名惯例推断，未经反汇编验证**，措辞保留「推测」。

### 19.8 验证

- [ ] 全量画像脚本跑完，TSV 行数与样本文件数一致（如 426/426）
- [ ] 抽样 5 个 PE 手动核对画像列（arch / sections / packer / sha256）与 `file`、`readelf` 输出一致
- [ ] 保护分布统计表输出，壳覆盖率有明确数字（如 2/426），据此修正主攻方向
- [ ] 熵统计按文件类型分组（.enc / .dat / .dll），确认两类数据文件可被区分
- [ ] PDB 聚类结果与模块目录结构对照，构建线归属无冲突
- [ ] 画像脚本全程只读（无进程创建、无网络），样本哈希前后一致

> 更新：2026-11-18 · 来源：看雪帖 2138217《某杀毒引擎逆向(很久之前)》（脱壳破解区）

---

## 思维内核与降维决策（看雪实战方法论）

> 逆向的产出不是补丁，是一条**别人能独立复算的因果链**。补丁只是这条链的副产品。

### 一、四步纪律：把"猜对了"和"会了"分开

每件事拆成四步，每步都能被第三方独立复算：

| 步骤 | 只允许写什么 | 反面例子（真实） |
|---|---|---|
| **观察** | 数字、字节、地址、耗时、调用次数 | ❌「字符串被加密了」——这是结论，不是观察 |
| **假设** | 一个能被**一次实验杀死**的陈述 | ❌「可能是保护导致的」——无法证伪，等于没说 |
| **验证** | 与假设**独立**的另一条证据 | ❌用同一个现象自证（看到堆变小→所以被抽走） |
| **结论** | 附上三条证据 + 失效条件 | ❌只写结论，不写边界 |

观察的正确写法：`#US 堆 1,896 B → 2,503,232 B（1320×）`、`83% 的方法 Code size = 4`、`每 tick 约 4ms`。这些是异常、是线索原料；"被加密了/被抽空了/被加固了"是解释。

### 二、证伪优先于证实

**能提出假设不算本事，能设计一个便宜实验把假设杀死才算。**

| 假设 | 依据 | 证伪实验 | 结果 |
|---|---|---|---|
| D3D 设备丢失 | 日志里 DeviceLostTimer 在报 | 拿**原版**跑同样操作 | 原版也报 → 假设死 |
| UI 初始化有问题 | 设置面板加载时报错 | 整段跳过后看结果 | 主题变蓝 → 假设死，暴露"只绕过症状" |
| 全局对象被置 null | 堆栈指向全局字段 | fieldrefs 列全部写入点 | 找到 11 处自毁分支 → 假设活 |

账要这么算：证伪成本 = 跑一次原版配对；不证伪的成本 = 留一个隐蔽副作用，几天后在别处炸。**任何"改完有别的怪现象"的修复，都先怀疑自己只绕过了症状。**

### 三、三证据规则

单一证据一定出错。每个结论至少三条**相互独立**的证据（独立 = 换观测面，不是同一数字换说法）：

| 结论 | 证据一 | 证据二 | 证据三 |
|---|---|---|---|
| 方法体被抽空 | 83% 方法 Code size=4 | 真实 IL 只剩 30 个方法 | #US 堆 1320× 异常 |
| 字符串被加密 | 三段式 IL 结构存在 | A^B 可算术复算 | 解密调用 216 → 21,827 处 |
| 授权是单点 | 触发点只有 1 处 | 业务代码引用数 0 | 打补丁后整个体系失效 |

凑不出三条就老老实实标注「**待验证**」。带着待验证结论往前走，是后面所有翻车的源头。

### 四、成本分级：判断保护强弱只有一个尺子

不看它用了多少招，看它把攻击成本抬到了哪一级：

| 级别 | 形态 | 攻击成本 | 案例 |
|---|---|---|---|
| **O(1)** | 单点授权判断、单点反调试、单点 CRC | 堵死一处即全线失效 | 保护全押在一个 `Validate()` 上，一个 nop 完事 |
| **O(n)** | n 层独立校验，每层失败不影响别层 | 线性叠加 | 14 层洋葱 |
| **耦合级** | 层与层互相依赖，改一处动全身 | 改一个字节 → 自锁 | 第 13 层密钥从主程序自身派生 |
| **无门之墙** | 密钥不在这份产物里（服务端/云端） | 本地不可解 | 七条路线全死，结论是"这不是难度，是没门" |

三个用法：侦察阶段估工期；卡住时定位问题（O(1) 却卡两天 = 没找到点，不是保护太强）；判断值不值得继续（遇无门之墙，正确产出是写下七条路为什么都不通，而不是硬啃第八条）。

> **复杂 ≠ 难破，加密 ≠ 对抗。** 98 字节的 WASM 被吹成 6.8MB（7 万倍），本质还是 98 字节的信息量。

### 五、降维：突发动机的六种通用形态

卡住时不是等灵感，是逐个试这六个开关：

| # | 形态 | 触发条件 | 案例 |
|---|---|---|---|
| 1 | 从"求逆"改为**接管出口** | "这个值在运行时一定会出现" | L2 密钥静态拿不到 → hook `avio_read` 抢下解密后的容器 |
| 2 | 从"还原算法"改为**黑盒调用** | "厂商自己的二进制就在磁盘上" | slice_type==18 逃逸码 → 直接 ctypes 加载厂商 32 位 DLL 当解码器 |
| 3 | 从"解 key"改为**运行时等 key** | "中间值一定存在于某个寄存器/结构体里" | 魔改 SQLCipher 的进程 mask → 在密钥传给下一层的位置读出来 |
| 4 | 从"改代码"改为**改数据** | "功能是状态型的吗？状态落在哪个可写介质上？" | IM 防撤回 → SQLite `BEFORE UPDATE` 触发器 `RAISE(IGNORE)`，10 分钟解决 |
| 5 | 从"破壳"改为**绕过壳管不到的面** | 列出"壳保护了什么"和"我要什么"，交集越小越好 | 不碰 UI，只做后台抢流；`__COMPAT_LAYER=RunAsInvoker` 免 UAC |
| 6 | 从"看懂"改为**对齐** | "这个目标有开源实现/官方源码吗？" | 0 知识逆 UE4：用引擎源码搭加载链，对着反编译找不同 |

共同点：都把问题换成一个**更窄、更便宜、有确定答案**的问题。

### 六、认知陷阱清单（每条都是真实翻车）

| # | 陷阱 | 正确姿势 |
|---|---|---|
| 1 | 把**别的项目经验**当规律 | 经验只能给"假设"不能给"结论"；先做双快照 diff |
| 2 | 用**单一信号**判断打包 | 导入表 + 体积 + 编译方式 + 段熵 一起看 |
| 3 | 把**日志里的名字**当病因 | 日志是症状名，不是因果；先拿原版配对 |
| 4 | 把**功能可用**当成功 | 修复必须做"副作用验收" |
| 5 | 以为**伪造校验值**就能过校验 | 校验值和它守护的分支是一体的，改校验值等于改控制流 |
| 6 | 把**混淆强度**当保护强度 | 先问"密钥在哪"，再问"有多难" |
| 7 | 把**看着像密钥的字符串**当密钥 | 任何 key 先做一次已知答案验证，蜜罐一验就露馅 |
| 8 | 把**扫到的常量**当算法 | 四字节搜索命中数据区假标记；遍历全部命中并校验结构 |
| 9 | **一次命中**就当规律 | 至少 5 次真机样本才能定契约 |
| 10 | 把**抓包顺序**当协议顺序 | 纯 ACK 被网关丢弃；对照开源实现逐字节 diff |
| 11 | 数据对不上就**怀疑 key 错** | 先检查 WAL：最新数据在 `-wal` 里，磁盘 page1 是旧的 |
| 12 | 把**表象**当机制 | 状态机的"看起来"和"走过了"是两件事 |
| 13 | 用**工具便利**代替**敏感维度判断** | 保护对语义敏感→改 IL；对字节偏移敏感→等长字节补丁 |
| 14 | 一路加 hook **掩盖**问题 | 并发问题收敛成单入口 + 互斥 + 只 resolve 一次，不是加日志 |

### 七、卡住时的合法动作（只有三个）

1. **换观测面**：静态看不到看运行时；运行时看不到看内存结构；内存看不到看磁盘/WAL/网络。
2. **换对照物**：原版配对、开源实现、厂商 DLL、引擎源码、官方发布版哈希、另一平台同名二进制。
3. **缩小问题**：不问"这个算法怎么算"，改问"它读了哪个字段""这个分支在什么条件下为真""这个值在哪个瞬间是可读的"。

不允许的动作：猜着改字节、靠重启环境碰运气、用更多 hook 掩盖不确定性、把"待验证"的结论写进文档继续往下做。

### 八、突发动机的可复现触发源

卡住时**主动去这六处找**：异常数字（1320×、83%、4 字节）、成本对比（求逆 O(n) vs 借壳 O(1)）、边界实验失败（原版也报→假设死）、错误文本（服务端把结构告诉你了）、意外的一致（两份无关实现算出同一个值）、反向追问（"如果我是作者，我会把密钥放哪"）。

### 验证

- [ ] 每个关键结论都有 ≥3 条相互独立的证据，凑不齐的标注「待验证」且不继续推进
- [ ] 每个假设都对应一个能在几十秒~几分钟内执行的证伪实验，且执行过
- [ ] 卡住 30 分钟无新观察时，强制换了观测面或对照物（记录换了什么）
- [ ] 每次修改后做了副作用验收，未出现"改完有别的怪现象"仍宣布完成的情况

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）

