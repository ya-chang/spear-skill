# Pwn 利用链（pwn-chain）

目标：从已识别的漏洞点写出**稳定打通的 working exploit**，不是只能本地复现、远程一打就崩的脚本。**强调 CTF 本地通 → 真实远程稳定打通的工程差距。**

## 一、前提与分工

前提：已经知道"哪里炸了"（溢出/UAF/double free）。本技能不负责发现漏洞（那是 fuzzing/审计），只负责从漏洞点写 exploit。

## 二、核心工作流

```text
Step 1: 确认漏洞类型 + 保护机制
   ├─ checksec ./vuln（NX/Canary/PIE/RELRO/Fortify）
   ├─ 漏洞分类：栈溢出/格式化串/堆(UAF/DF/OF)/整数/竞态/内核
   └─ → 决定走哪个策略

Step 2: 选择利用策略
   ├─ NX 关 + 无 ASLR → 直接 shellcode
   ├─ NX 开 + 给 libc → ret2libc / one_gadget
   ├─ NX 开 + 不给 libc → leak 后 libc-database 反查
   ├─ 堆 → 按 glibc 版本对应技术(tcache/fastbin/unsorted/large)
   └─ 内核 → commit_creds / modprobe_path / core_pattern

Step 3: 准备 libc + gadget
   ├─ libc-database：./find puts 0x6f0
   ├─ ROPgadget --binary ./libc.so.6 --only "pop|ret"
   ├─ one_gadget ./libc.so.6
   └─ 计算 base：leak_addr - libc.sym['puts']

Step 4: 写 pwntools 模板（本地 process）
   ├─ context.binary = ELF('./vuln')
   ├─ p = process('./vuln') / gdb.debug('./vuln','b *main+xx')
   ├─ payload = cyclic(N) + p64(ret) + ...
   └─ p.interactive()

Step 5: 本地通
   ├─ 反复 attach + 看寄存器 + 调 offset
   ├─ pwndbg/GEF 的 vmmap/heap/bins/telescope
   └─ 跑通后切 remote()

Step 6: 远程稳定化
   ├─ libc 偏移：用 leak 反查 libc-database，不拍脑袋
   ├─ 栈对齐：16-byte 不对齐 → movaps 崩 → 加一个 ret gadget
   ├─ 远程延迟 → recvuntil 精确锚字符串，禁用模糊 sleep
   ├─ 远程缓冲：sendlineafter 比 sendline 更稳
   ├─ 堆喷成功率：放大 spray + 留 padding chunk 防合并
   └─ 多次跑：while True 验证成功率 ≥ 95%
```

## 三、典型场景

### 远程 64 位二进制（NX+PIE+canary，给了 libc）
1. leak canary（栈/格式化串/部分读）
2. leak 一个 libc 函数地址（puts@got）
3. `libc.address = leaked - libc.sym['puts']` 算 base
4. `one_gadget` 选约束能满足的 gadget
5. `payload = padding + canary + saved_rbp + (pop_rdi + bin_sh + system)` 或直接 one_gadget
6. 加一个 ret gadget 修栈对齐（关键）

### Linux 内核驱动 ioctl 越界写 → 拿 root
1. 改 init 脚本拿 root shell（CTF）或先 leak KASLR base（真实）
2. 通过 `/proc/kallsyms` 或未初始化堆喷 leak 内核基址
3. 在 kmalloc-64 slab 喷 tty_struct/msg_msg/pipe_buffer
4. 覆盖 vtable 指针 → 不行（SMEP），改 stack pivot + 内核 ROP
5. ROP 链：`prepare_kernel_cred(0)` → `commit_creds` → `swapgs+iretq` → 用户态 execve
6. 或覆盖 `modprobe_path` 为 `/tmp/x`，写 `/tmp/x`，触发 modprobe

## 四、工具链

| 工具 | 用途 |
|---|---|
| pwntools | exploit 编写框架 |
| GEF / pwndbg | gdb 增强（堆调试体验最好） |
| ROPgadget / Ropper | gadget 搜索 |
| one_gadget | libc magic gadget |
| libc-database | libc 指纹反查 |
| qemu-system | 内核题调试 |

## 五、注意事项

- **不要在本地跑通就交差** — 本地 libc/ASLR/网络与远程不同，必须 remote 连续跑 20 次以上验证稳定性
- **libc 版本必须确认** — leak + libc-database 反查，不假设默认版本
- **栈对齐是 64 位常见坑** — `movaps xmm0,[rsp]` 未 16 字节对齐时段错误，加空 ret gadget 解决
- **堆利用对 glibc 版本极敏感** — tcache(2.27+)、safe-linking(2.32+)、2.34 移除 hooks，每版路径不同
- **内核 pwn 先确认 cpu 标志** — qemu 启动参数有无 +smep/+smap/+pku 决定 ROP 写法
- **KASLR leak 一次就够** — 拿到一个内核地址后所有地址算偏移

## 六、验证

- remote 模式连续 20+ 次成功率 ≥ 95%
- 拿到预期权限（shell / root）
- 栈对齐、libc 偏移、堆喷时序均稳定
