# IDA Pro 逆向（ida-reverse）

目标：用 IDA Pro 对 PE/ELF/APK/DLL/SO/Macho/固件做深度反编译与分析。**先概况后深入，持续加注释重命名，从反汇编推导方案。**

## 一、适用场景

- 分析 exe/dll/so/elf/macho/sys 等二进制
- 破解、找密码、漏洞分析、病毒分析、固件分析
- 需要 Hex-Rays 风格伪代码、深度反编译

> 若只需 CLI 快速侦察，用 `radare2.md`；若只需动态插桩，用 `linux-dynamic.md`。

## 二、核心工作流

### Step 1: 全局概览
先 survey 看概况，不急着深入：
- 架构（x86/x64/ARM）
- 入口点（main/WinMain/DllMain）
- 有趣字符串（URL、路径、错误消息）
- 导入分类（加密函数？网络 API？文件操作？）
- 热门函数（高 xref 计数的函数通常是关键逻辑）

### Step 2: 深入关键函数
对关键函数做反编译+反汇编，理解逻辑。

### Step 3: 数据流与交叉引用
发现有趣的数据/字符串，查谁引用了它，追踪数据流。

### Step 4: 记录与优化
分析过程中持续加注释、重命名函数/变量，提升后续分析准确性。

### Step 5: 输出报告
分析完成后生成报告，记录发现和步骤。

## 三、核心分析操作

### 概况分析
- survey：快速概况（函数数、字符串、段、入口点、导入分类）
- 列函数 / 列全局变量 / 统一查询（functions/globals/imports/strings/names）

### 反编译与反汇编
- 反编译为伪代码、反汇编、综合分析（伪代码+字符串+常量+调用者+被调用者+块）
- 函数概要指标

### 交叉引用与数据流
- 查谁引用目标地址（xrefs_to）
- 子函数列表、调用图（callgraph）
- 数据流追踪（forward/backward）

### 搜索
- 正则搜字符串、反汇编列表搜文本、字节模式搜索（支持 ?? 通配符）
- 高级搜索（立即数/字符串/引用）

### 内存与数据
- 读原始字节、读字符串、读整数值、读全局变量值
- 读结构体字段值、搜索结构体

### 修改操作
- 添加/追加注释（反汇编+反编译双向同步）
- 批量重命名（函数/全局/局部/栈变量）
- Patch 汇编指令 / Patch 字节
- 定义函数、取消定义、将字节转为代码

### 类型系统
- 声明 C 结构体/枚举/联合体
- 应用类型到函数/全局/局部
- 推断类型、查询/查看类型详情

### 栈帧
- 查看栈帧变量、声明/删除栈变量

### 签名
- 为地址/函数生成唯一字节签名
- 为引用地址的代码生成签名

## 四、Prompt 工程准则

1. **不要手动算进制** — 转换数字用内置进制转换工具
2. **先 survey 后深入** — 先看概况再针对性分析
3. **持续加注释和重命名** — 分析中不断更新函数名和变量名
4. **跟踪交叉引用** — 发现有趣数据/字符串，查谁引用了它
5. **遇到混淆代码** — 先做字符串解密、导入哈希去除、控制流平坦化去除等预处理
6. **C++ STL 代码** — 用 FLIRT/Lumina 识别库函数后，再分析业务逻辑
7. **不要暴力破解** — 从反汇编推导解决方案，用简单 Python 辅助计算
8. **遇到 "No database bound"** — 还没打开二进制，先打开文件
9. **遇到 "Failed to open database"** — 旧数据库文件被锁，自动降级到临时副本
10. **带自动分析打开 GUI/复杂样本** — 设置足够超时，不要把长时间分析误判成卡死

## 五、环境与安装

IDA Pro 是商业软件，需手动安装：
1. 设置 `IDADIR` 环境变量指向 IDA 安装目录
2. 安装 IDA 的 MCP 插件（从 GitHub 安装，注意 PyPI 上的同名包是另一个项目，不要装错）
3. 在 IDA 中安装插件，选择 Streamable HTTP 模式
4. 重启 IDA Pro，打开目标文件，插件自动监听本地端口

## 六、与 radare2 的分工

| 场景 | 用哪个 |
|---|---|
| CLI 快速侦察、轻量 patch | `radare2.md` |
| Hex-Rays 伪代码、深度反编译、复杂数据流 | 本技能（IDA） |
| 无 GUI 环境 | `radare2.md` / GDB / angr |

## 七、验证

- 反编译伪代码与反汇编一致
- 关键函数的交叉引用和数据流可追溯
- 注释和重命名覆盖关键逻辑

## 八、IDA Pro MCP 工具速查（idapro_*，HTTP 模式）

服务器名 `idapro`，工具前缀 `idapro_*`，共 72 个工具。

### 启动与会话管理

```powershell
# 启动 MCP HTTP 服务器（后台静默），输出 OK:72 表示就绪
powershell -File "scripts/start.ps1"
# 打开目标文件（绕过 schema 校验），输出 OK:filename:session_id
powershell -File "scripts/open.ps1" -Path "C:\target.exe"
# 大文件/GUI 程序加超时
powershell -File "scripts/open.ps1" -Path "C:\big.exe" -TimeoutSeconds 600
# 跳过自动分析（快速打开）
powershell -File "scripts/open.ps1" -Path "C:\huge.sys" -NoAutoAnalysis
```

| 工具 | 用途 |
|---|---|
| `idapro_idalib_list()` | 列出所有 session |
| `idapro_idalib_current()` | 当前绑定的 session |
| `idapro_idalib_switch(session_id)` | 切换 session（多文件对比） |
| `idapro_idalib_close(session_id)` | 关闭 session |
| `idapro_idalib_save(path)` | 保存数据库 |
| `idapro_idalib_health(session_id)` | 检查 worker 状态 |
| `idapro_server_health()` | 服务器健康检查 |
| `idapro_server_warmup()` | 预热子系统 |

### 全局概览

```
idapro_survey_binary(detail_level="minimal")   # minimal/standard/full
# 返回：架构、入口点、函数总数、字符串统计、段信息、导入分类、高 xref 热门函数

idapro_list_funcs(queries=[{"offset": 0, "limit": 50}])
idapro_list_funcs(queries=[{"filter": "crypt", "offset": 0, "limit": 20}])

idapro_entity_query(kind="imports", filter="Create")
idapro_entity_query(kind="strings", filter="http")
idapro_entity_query(kind="names", filter="")
```

### 反编译与反汇编

```
idapro_decompile(addr="main")
idapro_decompile(addr="0x140001000")
idapro_disasm(addr="0x401000", max_instructions=100)
# 综合分析（推荐）：伪代码+字符串+常量+调用者+被调用者+块
idapro_analyze_function(addr="main", include_asm=false)
idapro_func_profile(queries=["main", "sub_401000", "sub_402000"])
```

### 交叉引用与调用图

```
idapro_xrefs_to(addrs=["sub_401000"])
idapro_xref_query(addr="0x401000", direction="to")    # 谁引用我
idapro_xref_query(addr="0x401000", direction="from")  # 我引用谁
idapro_callees(addrs=["main"])
idapro_callgraph(roots=["main"], max_depth=3)
idapro_trace_data_flow(addr="0x401050", direction="backward", max_depth=5)
idapro_trace_data_flow(addr="0x401050", direction="forward", max_depth=5)
```

### 搜索

```
idapro_find_regex(pattern="https?://", limit=20)
idapro_find_regex(pattern="key|password|secret|token", limit=20)
idapro_search_text(pattern="call    sub_")
idapro_find_bytes(patterns=["48 8B 05"], limit=10)
idapro_find_bytes(patterns=["48 89 ?? 24 ??"], limit=10)   # ?? 通配符
idapro_find(type="immediate", targets=["0xDEADBEEF"])
idapro_find(type="string", targets=["password"])
```

### 内存与数据读取

```
idapro_get_bytes(addrs=[{"addr": "0x401000", "size": 64}])
idapro_get_string(addrs=["0x404000", "0x404100"])
idapro_get_int(queries=[{"addr": "0x405000", "size": 4}])
idapro_get_global_value(queries=["g_flag", "g_key_size"])
idapro_read_struct(queries=[{"addr": "0x405000", "type": "HEADER"}])
idapro_search_structs(filter="FILE")
```

### 修改操作

```
idapro_set_comments(items=[{"addr": "0x401000", "comment": "解密函数入口"}])
idapro_append_comments(items=[{"addr": "0x401000", "comment": "补充：密钥长度 16"}])
idapro_rename(batch={"func": [{"addr": "sub_401000", "name": "decrypt_payload"}]})
idapro_rename(batch={"global": [{"addr": "0x405000", "name": "g_encryption_key"}]})
idapro_rename(batch={"local": [{"func": "decrypt_payload", "old": "v1", "name": "plaintext_buf"}]})
# Patch 汇编
idapro_patch_asm(items=[{"addr": "0x401050", "asm": "nop"}])
idapro_patch_asm(items=[{"addr": "0x401060", "asm": "jmp 0x401080"}])
idapro_patch_asm(items=[{"addr": "0x401000", "asm": "mov eax, 1"}, {"addr": "0x401005", "asm": "ret"}])
# Patch 字节
idapro_patch(patches=[{"addr": "0x401050", "bytes": "9090909090"}])
```

### 类型系统

```
idapro_declare_type(decls=[{"name": "PacketHeader",
    "decl": "struct PacketHeader { uint32_t magic; uint16_t type; uint16_t length; uint8_t data[0]; };"}])
idapro_set_type(edits=[{"addr": "sub_401000", "type": "int __fastcall decrypt(void *buf, int size, const char *key)"}])
idapro_set_type(edits=[{"addr": "0x405000", "type": "PacketHeader"}])
idapro_infer_types(addrs=["sub_401000", "sub_402000"])
idapro_type_query(queries=["Packet"])
idapro_type_inspect(queries=["PacketHeader"])
```

### 栈帧与签名

```
idapro_stack_frame(addrs=["main", "sub_401000"])
idapro_declare_stack(items=[{"func": "sub_401000", "offset": -0x20, "name": "local_buf", "type": "char [32]"}])
idapro_make_signature(addrs=["0x401000"])
idapro_make_signature_for_function(addrs=["decrypt_payload"])
idapro_find_xref_signatures(addrs=["0x405000"])
```

### 进制转换（永远用工具，不要手算）

```
idapro_int_convert(inputs=["0x401000"])
idapro_int_convert(inputs=["4198400"])
idapro_int_convert(inputs=["0xDEAD", "0xBEEF", "12345"])
```

### 导出与脚本

```
idapro_export_funcs(addrs=["main", "sub_401000"], format="json")
idapro_export_funcs(addrs=["main", "sub_401000"], format="c_header")
idapro_export_funcs(addrs=["main", "sub_401000"], format="prototypes")
idapro_py_eval(code="import idautils; print(list(idautils.Functions())[:10])")
idapro_py_eval(code="import idc; print(idc.get_segm_name(0x401000))")
idapro_py_eval(code="import ida_funcs; f=ida_funcs.get_func(0x401000); print(f.size())")
```

### 典型分析流程

**恶意软件分析：**
```
1. survey_binary → 看导入（网络API? 加密? 注册表?）
2. find_regex("http|socket|connect") → 找网络字符串
3. xrefs_to(网络字符串地址) → 找引用函数
4. decompile(引用函数) → 看通信逻辑
5. trace_data_flow(加密参数, "backward") → 追踪密钥来源
6. set_comments + rename → 标注发现
```

**注册验证破解：**
```
1. find_regex("serial|license|register|valid") → 找验证字符串
2. xrefs_to(验证字符串) → 定位验证函数
3. analyze_function(验证函数) → 理解逻辑
4. callgraph(验证函数, 2) → 看调用链
5. patch_asm(条件跳转地址, "jmp always_pass") → patch
```

**CTF 逆向：**
```
1. survey_binary → 确认架构和入口
2. decompile("main") → 看主逻辑
3. find_regex("flag|correct|wrong") → 找判断点
4. trace_data_flow(判断点, "backward") → 追踪输入变换
5. Python 辅助计算/解密 → 得到 flag
```

**漏洞分析：**
```
1. entity_query(kind="imports", filter="strcpy|sprintf|gets") → 找危险函数
2. xrefs_to(危险函数) → 找调用点
3. analyze_function(调用点所在函数) → 看上下文
4. stack_frame(函数) → 确认缓冲区大小
5. trace_data_flow(危险参数, "backward") → 确认用户可控
```

### 常见错误与解决

| 错误 | 原因 | 解决 |
|---|---|---|
| "No database bound" | 没有打开文件 | 执行 `open.ps1` |
| "Failed to open database" | 旧库被锁 | `open.ps1` 自动降级到 Temp |
| schema 校验失败 | MCP 客户端 BUG | 用 `open.ps1` 代替 `idalib_open` |
| 工具超时 | 大文件分析中 | 加 `-TimeoutSeconds 600` |
| "ERR:timeout" (start.ps1) | 服务器启动失败 | 检查 Python/idalib-mcp 安装 |
| 进制转换错误 | 手动计算出错 | 用 `idapro_int_convert` |
| 函数名找不到 | 名称不精确 | 用 `list_funcs` + filter 先搜索 |
