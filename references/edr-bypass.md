# EDR / AV 绕过（edr-bypass）

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

- 投递后 EDR 控制台无告警
- Sysmon 关键事件（1/7/8/10）不触发
- beacon 能正常 callback 且稳定驻留
