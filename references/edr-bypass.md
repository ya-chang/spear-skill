# EDR / AV 绕过（edr-bypass）

> 通用原语详见 `common-techniques.md §5`（PEB 遍历/ntdll 基址/KnownDlls 劫持）、`§1`（全架构 Hook）、`§2`（NPT/EPT 虚拟化 Hook）。本节侧重 EDR 四监控面的针对性绕过组合。

目标：逆向防御方实现，针对性绕过 EDR/Defender/AV。**先逆 hook 表/ETW/AMSI 实现，再写针对性绕法，组合使用。**

## 一、核心原理：EDR 四个监控面 ↔ 红队对策

```text
用户态 ntdll hook        ◄──►  unhook（fresh ntdll）
                                间接 syscall / Hell's Gate / Halo's Gate
                                hardware breakpoint Blindside

kernel callback          ◄──►  call stack spoof
(Ps/Cm/Ob 系列)              走合法触发链

ETW telemetry           ◄──►  EtwEventWrite patch
                              NtTraceControl 关 provider

AMSI 扫描               ◄──►  AmsiScanBuffer patch (mov eax,0x80070057; ret)
                              hardware breakpoint 旁路
```

关键认知：
- EDR 不是黑盒，关键 hook/callback/provider 都能逆出来
- 绕过技术要**组合使用**，单独 unhook 解决不了 ETW 告警
- **顺序很重要**：先 ETW patch → 再 AMSI patch → 再 unhook
- 现代 EDR 把 ETW + kernel callback 当主战场，单纯用户态 unhook 已不够

## 二、工作流

### Step 1：识别目标主机的 EDR
```powershell
Get-Service | Where-Object {$_.Name -match 'CSAgent|SentinelAgent|elasticendpoint|esets|ekrn|MsMpEng|wdsvc|cyserver|sysmon'}
fltmc filters
```

### Step 2：从 EDR DLL 提 hook 表
- attach 到被注入 EDR 用户态组件的进程
- dump 当前 `ntdll.dll` 的 `.text` 段，与磁盘干净 ntdll 做 diff，不一致即 hook 点
- 或用 `pe-sieve`：`pe-sieve64.exe /pid 1234 /shellc 3 /modules 3 /dir hooks_dump`

### Step 3：选绕过技术组合

| 防御点 | 推荐绕法 |
|---|---|
| ntdll inline hook | indirect syscall + 动态 SSN (Halo's Gate) |
| ETW-TI provider | EtwEventWrite head patch |
| AMSI（PowerShell/.NET） | AmsiScanBuffer patch 或 HWBP |
| kernel callback | call stack spoof + legit gadget |
| Sysmon ProcessCreate | PPID spoof + unbacked memory |

### Step 4：在 implant 中实现
- 代码骨架：unhook / 间接 syscall stub / ETW patch / AMSI patch

### Step 5：本地 sandbox 验证
部署目标 EDR 试用版，启用 Sysmon + olaf-config，跑 implant 看是否触发：Defender AMSI、ETW-TI、Sysmon Event ID 1/7/8/10、EDR 控制台。

## 三、典型场景

### 投递 beacon 过 Defender + Sysmon
组合拳：
1. shellcode 加密存储，运行时解密
2. AMSI patch（PowerShell 投递时）
3. EtwEventWrite patch（消 ETW-TI）
4. 间接 syscall + Halo's Gate（消 ntdll hook 告警）
5. PPID spoof 到 explorer.exe
6. sleep 阶段用 Ekko/Foliage 加密自身内存

### 已落地 shell 上做 EDR sleep mask
1. 不再申请新 RWX 内存
2. sleep 期间 Ekko：定时器里加密自身 `.text` + 堆栈刷全 0
3. wake 时 ROP 还原
4. 配合 call stack spoof 让 `RtlCaptureStackBackTrace` 看不到信标地址

## 四、工具链

| 工具 | 用途 |
|---|---|
| pe-sieve | 检测进程 hook/注入 |
| SysWhispers3 | 生成直接/间接 syscall stub |
| Hell's Gate POC | 动态 SSN 解析参考 |
| windbg + IDA | 逆 EDR DLL / 内核 callback |
| Sysmon + olaf config | 本地验证环境 |

## 五、验证

- [ ] 投递后 EDR 控制台无告警（打开 EDR 管理台查看告警列表为空）
- [ ] Sysmon 关键事件不触发（`Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational` 确认无 Event ID 1/7/8/10）
- [ ] beacon 正常 callback（c2 端收到心跳，目标进程存活）
- [ ] 内存扫描不发现明文 shellcode（用 pe-sieve 或 EDR 内存扫描确认无 RWX 区域）

## 六、代码骨架：间接 syscall 绕过 ntdll hook

> 可编译运行的最小间接 syscall 骨架，绕过 EDR 对 ntdll 的 inline hook。SSN 动态解析或硬编码占位。

```c
// indirect_syscall.c — 间接 syscall 骨架（x64 Windows）
// 绕过 ntdll inline hook：不调用 ntdll 导出，直接 syscall 指令
#include <windows.h>
#include <stdio.h>

// 占位：SSN 从 Hell's Gate 解析或按目标系统硬编码
#define SS_NtCreateFile 0x55   // 示例：NtCreateFile 的 SSN

// syscall 指令地址（从干净 ntdll 提取，或从内存搜索 "syscall" 指令）
// 占位：实际从磁盘干净 ntdll 的 Nt* 函数体提取
PVOID syscall_addr = [SYSCALL_INST_ADDR];

// 间接 syscall 包装：按 SSN 调用
NTSTATUS IndirectSyscall(PVOID func_addr, ...) {
    // 构造调用：把参数压栈，跳转到 syscall 指令地址执行
    // 实际实现：用 ROP 或直接构造栈帧跳转到 syscall_addr
    // 简化骨架：直接调用 syscall 指令地址（需保证栈参数正确）
    void (*syscall_fn)(void) = (void(*)(void))syscall_addr;
    syscall_fn();
    return 0; // 占位
}

// 用法示例：绕过 NtCreateFile 的 hook
int main() {
    // 1. 解析 SSN（Hell's Gate 方式或硬编码）
    // 2. 构造 syscall 参数（IO_STATUS_BLOCK、文件句柄等）
    // 3. 调用 IndirectSyscall 执行，不经过 ntdll 导出函数
    printf("indirect syscall skeleton — replace [SYSCALL_INST_ADDR] and SSN\n");
    return 0;
}
```

编译：`cl indirect_syscall.c /Fe:indirect_syscall.exe`（MSVC）或 MinGW `gcc`。验证：编译运行后，EDR 对 ntdll hook 的告警不触发，syscall 正常执行。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §二工作流使用

## 七、杀软引擎静态画像 → 绕过面识别

> 做 EDR/AV 绕过前，先用静态画像把目标套件的「壁垒结构」看清楚，再选绕过组合。全量画像方法论见 re-methodology §19，通用原语见 common-techniques §9。

### 7.1 先画像，修正「难点在壳」的预判

对大型安全套件（几百个 PE）先跑全量画像，重点看三个数字：

```
壳覆盖率      —— 壳往往只覆盖极少数模块（案例：2/426）
驱动规模      —— 几十上百个 .sys 的内核面
签名有效性    —— 100% Valid 时任何字节改写都会掉签名
```

**核心结论**：壳少不代表弱。真正的壁垒是**内核驱动面 + 有效签名 + 云端策略**。把主攻方向押在脱壳上是错误开局——画像数据直接修正判断。

### 7.2 四层检测链还原（找绕过要打哪一层）

安全软件的检测通常是多层并行，从导出/导入/字符串/调用者交叉推出结构：

```
层 1 静态特征层   AVE/AVEI：微特征计算 + 本地特征库比对
层 2 学习型判定层 QVM：机器学习分数（统计判定）
层 3 文档格式层   qex：复合文档解析（Office/PDF/LNK），规则可云端下发
层 4 行为+云查层  BAPI/BAPIDRV/cloudcom2：行为规则命中 + 云仲裁
横切 信任与白名单 SigMatchCert / GetFileTrustState / Has360SignEx / 白名单
```

绕过策略对应每一层的打法：

| 层 | 绕过思路 |
|---|---|
| 静态特征层 | 特征库更新滞后窗口、变形/加壳规避、特征计算点 patch |
| 学习型判定层 | 分数阈值探测、样本污染、判定入口 hook |
| 文档格式层 | 格式解析 VM 补环境绕过、规则下发通道（cloudqexvm）干扰 |
| 行为+云查层 | 行为钩子摘除（hook 表）、云查请求阻断/伪造、白名单伪造 |
| 信任链 | 验签模块 patch、签名匹配函数 hook、信任表注入 |

### 7.3 自我保护链与 hook 框架（先拆防护再做事）

- **自我保护链**：用户态主程序（打开 `\\.\XXX` 自我保护设备 + DeviceIoControl 下发保护指令）→ 用户态 API 封装 DLL → 内核保护驱动。要动引擎先过这条链：设备控制码表、权限门、无条件放行码（见 common-techniques §9.3）。
- **hook 框架识别**：导入表出现 `NtCreateThread/Ex`、`NtQueueApcThread/Ex`、`NtSetContextThread`、`NtSystemDebugControl`、DPC 系列（`KeInitializeDpc`）→ 成熟 SSDT/Inline hook 框架，钩子覆盖面广，**摘钩前先定位 hook 表与分发函数**（用 ida-reverse §9.3 的 MajorFunction 扫描法）。
- **ELAM/WHQL 签名驱动**：启动最早阶段加载的驱动，patch 后签名失效会被自检抓到——优先考虑 hook 其判定函数而不是改文件。

### 7.4 验证

- [ ] 全量画像输出：壳覆盖率、驱动数量、签名有效性三组数字明确
- [ ] 四层检测链各层定位到具体模块，每层至少一个绕过思路
- [ ] 自我保护链的 IOCTL 码表 + 权限门 + 放行码已梳理
- [ ] hook 框架驱动已识别，hook 表/分发函数定位方法已选定
- [ ] 绕过组合按层选择，至少覆盖静态层与行为层两层

> 更新：2026-11-18 · 来源：看雪帖 2138217《某杀毒引擎逆向(很久之前)》（脱壳破解区）
