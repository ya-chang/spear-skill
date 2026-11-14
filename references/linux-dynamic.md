# Linux 动态分析协同（linux-dynamic）

目标：GDB / r2 / Frida / angr / strace / ltrace 多工具协同，静态看不清的用动态补。**每个关键发现至少两个工具交叉确认。**

## 一、环境探测

```bash
for t in gdb lldb r2 objdump readelf nm strings strace ltrace perf valgrind bpftrace; do
  which $t >/dev/null 2>&1 && echo "$t: OK" || echo "$t: MISSING"
done
python3 -c "import frida,angr" 2>/dev/null && echo "frida/angr OK" || echo "frida/angr MISSING"
cat /proc/sys/kernel/randomize_va_space   # ASLR
cat /proc/sys/kernel/yama/ptrace_scope    # ptrace 限制
```

## 二、工具分工

| 工具 | 擅长 | 盲点 |
|---|---|---|
| GDB | 精确控制、寄存器/内存快照 | 不看系统调用全貌 |
| strace | 完整系统调用 | 不看库函数 |
| ltrace | 库函数参数 | 不看内联代码 |
| r2/静态 | 不受反调试影响 | 看不到运行时值 |
| Frida | 灵活 hook | 注入可被检测、开销大 |
| angr | 路径完整、约束求解 | 路径爆炸 |

## 三、核心命令

### GDB（+pwndbg）
```gdb
vmmap                      # 内存映射
telescope $rsp 20          # 栈递归
context                    # 寄存器+栈+反汇编一屏
checksec                   # 安全标志
rop --grep "pop rdi; ret"  # 找 gadget
heap / bins                # 堆状态
```

### strace
```bash
strace -tt -T ./target 2>&1 | tee /tmp/strace.log
strace -e trace=file,network,memory ./target
strace -f -p <pid>         # 附加运行中进程
strace -c ./target         # 统计
```

### ltrace
```bash
ltrace -e strcmp,memcmp,EVP_*,AES_* ./target
ltrace -tt -T -n 2 ./target
```

### Frida
```javascript
// hook 函数参数与返回值
Interceptor.attach(Module.findExportByName(null, "target_func"), {
  onEnter(args) { console.log("arg0", args[0]); },
  onLeave(ret) { console.log("ret", ret.toInt()); }
});
```

### angr
```python
import angr
proj = angr.Project("./target", auto_load_libs=False)
cfg = proj.analyses.CFGFast()
# 符号执行 / 路径枚举
```

## 四、结构体 / vtable 恢复

```bash
r2 -A -q -c 'avj' target    # 所有 vtable
```

结构体字段推断规则：
- `[base + N]` 反复访问 → 字段 N
- 访问大小推断类型：b=uint8 / w=uint16 / d=uint32 / q=uint64
- `malloc(M)` 后多字段初始化 → 结构体大小 M
- 相邻偏移间隙 → padding

置信度：动态验证(GDB/Frida 实读)+30，跨函数一致+15，仅一处访问-10。≥90% 标 CONFIRMED。

## 五、动态-静态交替节奏

```
[静态] r2 aaa → 函数列表 + CFG 骨架
  ↓
[动态-宽] strace + ltrace 全量 → 找热点和关键行为
  ↓
[静态] 对热点函数详细反汇编，推断算法/结构体
  ↓
[动态-精] GDB 断点 + Frida hook → 验证静态推断
  ↓
[自动化] angr/bpftrace → 补 GDB 难追踪的部分
  ↓
[更新] 动态结果写回结构体推断卡 + 算法置信度
  ↓ 循环
```

## 六、常见错误处理

| 错误 | 原因 | 处理 |
|---|---|---|
| `ptrace: Operation not permitted` | ptrace_scope=1 | `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 或 `gdb -f ./target` |
| `no debugging symbols` | stripped | r2 `aaa`、GDB `b *addr`、angr CFGFast |
| `Cannot access memory` | PIE+ASLR | pwndbg `vmmap` 算基址，或 `set disable-randomization on` |
| strace EPERM | 权限 | `sudo strace` |
| perf Permission denied | perf_paranoid>0 | `echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid` |

## 七、LD_PRELOAD 注入（绕过校验示例）

```c
// hook_strcmp.c — 拦截 strcmp，伪造返回 0（密码绕过示例）
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
int strcmp(const char *s1, const char *s2) {
    typedef int (*fn_t)(const char*, const char*);
    fn_t orig = dlsym(RTLD_NEXT, "strcmp");
    int ret = orig(s1, s2);
    fprintf(stderr, "[strcmp] %s vs %s -> %d\n", s1, s2, ret);
    return ret;
}
```
```bash
gcc -shared -fPIC -o hook_strcmp.so hook_strcmp.c -ldl
LD_PRELOAD=./hook_strcmp.so ./target
```

## vtable 继承关系推断

**推断规则：**
1. 子类 vtable 前 N 个条目与父类 vtable 相同（N = 父类虚函数数量）
2. 子类 vtable 在父类基础上追加新虚函数
3. 多继承：子类对象包含多个 vptr，排列按继承顺序

**识别多继承：** 构造函数中对 this 的不同偏移分别写入 vptr：
```asm
mov [rdi + 0x00], vtable_A    ; 第一个基类 vptr
mov [rdi + 0x20], vtable_B    ; 第二个基类 vptr（偏移 = 第一个基类大小）
```

**r2pipe 继承分析：**
```python
import r2pipe, json
r = r2pipe.open('./target', flags=['-A', '-2'])
vtables = json.loads(r.cmd('avj') or '[]')
# 对每对 vtable 检查前缀关系（疑似继承）
for vt_a in vtables:
    for vt_b in vtables:
        # 比较 vt_a 前 N 个条目是否与 vt_b 匹配 → 推断继承
```

## 记忆机制（上下文快照）

### 上下文快照
每 10 轮对话自动生成一份上下文快照，保存分析进度，下次对话可无缝继续。

**快照内容：**
- 目标信息：文件、架构、编译器、安全标志
- 工具确认：GDB/r2/Frida/angr 等版本
- 混淆状态：clean/upx/olllvm/vmprotect
- 算法发现：名称、置信度、函数地址、验证状态
- 结构体恢复：字段布局
- 函数分析：已完成/待分析
- 动态分析：strace/ltrace/Frida 结论
- 待办任务、未解决点

### P0-P3 优先级
- **P0（突破性发现）**：密钥、密码、核心算法、绕过验证——永不丢弃
- **P1（重要进展）**：结构体确认、函数完整分析、反调试绕过——优先保留
- **P2（中间结论）**：疑似算法、结构体疑似字段——可压缩
- **P3（常规记录）**：已完成函数、工具记录——可截断

### STAGED → COMMITTED 两阶段门控
- **STAGED（暂存）**：单工具单次观测，标注 `[STAGED]`，不写入正式发现
- **COMMITTED（提交）**：两个独立工具交叉验证 + 无矛盾证据，正式写入
- 防止未验证结论在下次对话中被当作事实，避免幻觉传播
