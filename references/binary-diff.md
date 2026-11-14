# 二进制差分 / 跨版本符号迁移（binary-diff）

目标：有旧版本符号/逆向结果，需要快速迁移到新版本。**用 LLM 做结构化差异比对，程序化输入输出，成本极低。**

## 一、适用场景

1. 内核/驱动缺 PDB — 有旧版符号，新版 PDB 下架，用旧版符号推导新版非导出函数地址
2. 程序更新后符号迁移 — 曾逆向过，程序更新了，不想重新逆一遍
3. 保护机制更新 — 旧版有完整逆向结果，新版快速定位同一函数新偏移

## 二、核心原理

```text
旧版函数（有符号）          新版同一函数（无符号）
    ↓                              ↓
导出反汇编 + 伪代码          导出反汇编 + 伪代码
    └──────── LLM 结构化比对 ────────┘
              ↓
       输出 YAML（符号映射表）
              ↓
    程序化解析 → 批量应用到新版 IDB
```

关键点：prompt 固定模板程序化填充，输入输出格式确定，LLM 只负责"看两段代码找对应关系"。

## 三、工作流

### Step 1: 准备数据
- 旧版二进制加载到 IDA（有 PDB/符号）
- 新版二进制加载到 IDA（无符号）
- 找两个版本相同的锚点函数（导出函数、字符串引用等）

### Step 2: 批量导出
- 旧版导出：锚点函数的反汇编+伪代码（含符号名）
- 新版导出：同一锚点函数的反汇编+伪代码（无符号名）

### Step 3: LLM 比对
- 用 prompt 模板填充数据，调 LLM API
- 解析返回的 YAML

### Step 4: 应用结果
- YAML 符号映射批量应用到新版 IDB
- 用 IDAPython / idapro_rename 批量重命名

### Step 5: 迭代
- 第一轮迁移的函数成为新锚点，进入内部继续对比，重复直到覆盖目标

## 四、锚点选择策略

| 锚点类型 | 可靠性 | 说明 |
|---|---|---|
| 导出函数 | 最高 | 名字不变，地址可能变 |
| 字符串引用 | 高 | 内容不变，引用位置可能变 |
| 常量/魔数 | 中 | 特征值不变 |
| 代码模式 | 中 | 结构相似但地址全变 |

## 五、YAML 输出的 5 种符号类型

| 类型 | 含义 | 关键字段 |
|---|---|---|
| `found_vcall` | 虚函数调用（间接 call） | `vfunc_offset`, `func_name` |
| `found_call` | 直接函数调用 | `insn_va`, `func_name` |
| `found_funcptr` | 函数指针引用 | `insn_va`, `funcptr_name` |
| `found_gv` | 全局变量引用 | `insn_va`, `gv_name` |
| `found_struct_offset` | 结构体偏移引用 | `offset`, `struct_name`, `member_name` |

应用动作：
```text
found_call      → rename(call_target, func_name)
found_vcall     → set_comment(insn_va, "vcall: {func_name} @ +{offset}")
found_funcptr   → rename(funcptr_target, funcptr_name)
found_gv        → rename(gv_addr, gv_name)
found_struct_offset → set_comment(insn_va, "{struct_name}.{member_name}")
```

## 六、LLM 选择建议

| 模型 | 适合场景 | 成本 |
|---|---|---|
| DeepSeek V3 | 中小函数(<200行)，批量 | 极低 |
| GPT-4o | 超大函数，复杂控制流 | 中 |
| Claude Sonnet | 中大函数，需推理 | 中 |

推荐：默认 DeepSeek，context 超限或结果不准时升级。

## 七、注意事项

- **不要把整个二进制丢给 LLM** — 一次只比对一个函数
- **锚点必须可靠** — 锚点对错，后续全白费
- **结果需人工抽检** — 关键符号要验证
- **缓存中间结果** — 避免重复调用浪费 token
- **注意 context 限制** — 超大函数(>1000行)需拆分或大 context 模型

## 八、验证

- 迁移后的符号名在新版中位置正确
- 抽查关键函数，反汇编/伪代码与旧版逻辑对应
- 批量重命名无错位
