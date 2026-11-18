# radare2 逆向（radare2）

目标：用 radare2/r2 从命令行完成二进制的侦察、分析、定位、导出和轻量修改，不依赖 GUI。**先侦察后深挖，优先最小足够命令，修改前保持谨慎。**

## 一、适用场景

- 用 r2/radare2 分析 exe/dll/so/elf/apk/dex/wasm
- 命令行反汇编、看函数、看字符串、看导入导出、查交叉引用、做 patch
- 写 r2 批处理命令、`-c` 自动化命令、r2pipe 脚本
- 二进制 diff（radiff2）、哈希（rahash2）、进制转换（rax2）

> 若需 GUI 逆向、Hex-Rays 伪代码，用 `ida-reverse.md`；若需动态插桩，用 `linux-dynamic.md`。

## 二、基本原则

1. **先侦察，后深挖** — 先用轻量命令确认文件类型、架构、入口点、字符串、导入，再决定是否 `aaa`/`aaaa`
2. **优先最小足够命令** — 看信息用 `rabin2 -I`，看字符串用 `rabin2 -z`，不一上来就全量分析
3. **修改前保持谨慎** — 默认只读打开，明确需修改时才用写模式，修改前先备份

## 三、常用工作流

### 工作流 1：快速侦察
```bash
rabin2 -I sample.exe   # 基本信息：格式、位数、架构、平台、入口点
rabin2 -z sample.exe   # 字符串
rabin2 -i sample.exe   # 导入
rabin2 -E sample.exe   # 导出
```
关注：可疑字符串（URL/路径/报错/注册表）、导入函数（网络/文件/加密/进程注入/注册表）。

### 工作流 2：交互式分析函数
```bash
r2 sample.exe
```
进入后：
```text
aaa          # 常规自动分析（优先 aaa，不要一开始用 aaaa）
afl          # 列出函数
iz           # 列出字符串
iS           # 列节区
is           # 列符号
s entry0     # 跳到入口点
pdf          # 反汇编当前函数
VV           # 可视化模式（终端适合时）
q            # 退出
```

### 工作流 3：定位 main / 关键逻辑
```text
afl~main
afl~sym.
iz~http
iz~error
axt <addr>     # 查谁引用了某地址/字符串
```
思路：从 main、入口点、字符串引用入手 → `axt` 查引用 → `s <addr>` 跳转 → `pdf` 反汇编。

### 工作流 4：十六进制与内存查看
```text
px 64        # 当前地址起 64 字节十六进制
pd 20        # 反汇编 20 条指令
psz          # 读取当前地址字符串
pxa          # 更友好的十六进制视图
```

### 工作流 5：二进制 patch（仅明确要求修改时）
```bash
r2 -w sample.exe
```
```text
s 0x401000
wa nop           # 写汇编
wa jmp 0x401050
wx <hex>         # 写原始字节
wq               # 写入并退出
```
修改前先备份原文件。

### 工作流 6：非交互自动化
```bash
r2 -A -q -c "afl;iz;ii;q" sample.exe
```
- `-A`：启动自动分析
- `-q`：安静模式
- `-c`：执行命令串

## 四、常用子工具

### rabin2（静态信息提取）
```bash
rabin2 -I sample.exe   # 基本信息
rabin2 -S sample.exe   # 节区
rabin2 -s sample.exe   # 符号
rabin2 -i sample.exe   # 导入
rabin2 -E sample.exe   # 导出
rabin2 -z sample.exe   # 字符串
rabin2 -zz sample.exe  # 详细字符串
```

### rasm2（汇编/反汇编）
```bash
rasm2 -d "9090"
rasm2 -a x86 -b 64 "xor eax, eax"
```

### radiff2（二进制对比）
```bash
radiff2 old.exe new.exe
radiff2 -C old.exe new.exe
```

### rahash2（哈希）
```bash
rahash2 -a md5 sample.exe
rahash2 -a sha256 sample.exe
```

### rax2（进制/编码转换）
```bash
rax2 0x401000
rax2 4198400
rax2 -s hello
```

## 五、推荐分析顺序

遇到未知样本：
1. `rabin2 -I` 看格式、架构、入口点
2. `rabin2 -z` 看字符串
3. `rabin2 -i` 看导入函数
4. 如需交互分析，进 `r2`
5. 先 `aaa`，再 `afl`/`iz`/`pdf`
6. 通过字符串引用、导入调用、入口流程逐步定位关键函数

好处：噪音低，能尽快建立方向感。

## 六、与 IDA 的分工

| 场景 | 用哪个 |
|---|---|
| CLI 快速侦察、轻量 patch、自动化 | 本技能（radare2） |
| Hex-Rays 伪代码、深度反编译、复杂数据流 | `ida-reverse.md`（IDA） |

## 七、注意事项

- 路径含空格时命令必须加引号
- 找不到 `r2` 可能是 PATH 刚更新，开新终端再试
- 可疑样本动态调试前先确认用户意图
- 不要只罗列命令不解释为什么这么做

## 八、验证

- [ ] 侦察结果准确（`r2 -A` 后 `iI`/`iS`/`ii` 输出格式、架构、入口点、字符串、导入正确）
- [ ] 关键函数定位有据（字符串引用 `ts`、导入调用 `i~`、入口流程 `af @ entry` 交叉验证）
- [ ] patch 后反汇编验证正确（`wp` 写补丁后 `pdf`/`pdr` 反汇编无乱码，逻辑通顺）
- [ ] r2 脚本执行无报错（`r2 -i script.r2` 运行完成，产出预期标注）
- [ ] 函数边界识别正确（`af` 分析后函数 prologue/epilogue 完整，无漏切）

## 八·五、代码骨架：r2 自动化分析脚本

> 可运行的 r2 脚本骨架，自动侦察、标注关键函数、导出函数清单。

```r2
# r2_auto.r2 — radare2 自动化分析骨架
# 用法：r2 -A -i r2_auto.r2 <target>

# 1. 全量分析（自动加载、反汇编、函数识别）
e scr.color=0
e scr.utf8=true
aa

# 2. 侦察输出
echo ==== 侦察 ====
iI          # 文件信息
iS          # 段信息
ii          # 导入表
iS~.text     # 代码段

# 3. 字符串与导入交叉定位关键函数
echo ==== 关键函数定位 ====
# 搜字符串引用（如 "flag"、"verify"、"check"）
ts~flag
ts~verify
ts~check

# 对每个命中的字符串地址，找引用它的函数
# ts flag | s <addr> | af @ <addr>

# 4. 标注关键函数（重命名含校验特征的函数）
# 遍历函数，对含 cmp/call 导入的函数重命名
f~cmp @ function_name
# 实际用 r2 的 af + 重命名

# 5. 导出函数清单
echo ==== 函数清单 ====
afcl          # 列出所有函数
afcl~interesting  # 过滤关键函数

# 6. 保存分析结果
wf analyzed.r2  # 保存为 r2 脚本（可复用）
```

运行：`r2 -A -i r2_auto.r2 target_binary`。验证：侦察输出完整，关键函数被标注，`analyzed.r2` 可复用。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §三 r2 核心命令使用
