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

- [ ] 迁移后的符号名在新版中位置正确（重命名后的函数在新版对应偏移处，反汇编验证地址匹配）
- [ ] 抽查关键函数，反汇编/伪代码与旧版逻辑对应（抽 5-10 个关键函数，新版伪代码与旧版逻辑语义一致）
- [ ] 批量重命名无错位（重命名清单中每个符号在新版的偏移正确，无错位/遗漏）
- [ ] 差分结果可追溯（diff 输出标注每个变化点的位置、旧值、新值，可回溯）
- [ ] 符号迁移覆盖率达标（关键符号迁移率 ≥ 90%，未迁移的标注原因）

## 八·五、代码骨架：二进制差分脚本

> 可运行的 Python 骨架，对两个版本二进制做差分，输出变化点。关键路径按样本替换。

```python
# binary_diff.py — 二进制差分骨架（Python）
# 对两个版本二进制做字节级差分，输出变化点位置与内容

import sys
import hashlib

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def diff_binaries(old_path, new_path, block_size=16):
    """对两个二进制做块级差分，输出变化点"""
    with open(old_path, "rb") as old, open(new_path, "rb") as new:
        old_data = old.read()
        new_data = new.read()

    min_len = min(len(old_data), len(new_data))
    changes = []

    # 块级比对
    for i in range(0, min_len, block_size):
        old_chunk = old_data[i:i+block_size]
        new_chunk = new_data[i:i+block_size]
        if old_chunk != new_chunk:
            changes.append({
                "offset": i,
                "old": old_chunk.hex(),
                "new": new_chunk.hex(),
            })

    # 长度差异
    length_diff = len(new_data) - len(old_data)
    if length_diff != 0:
        changes.append({"offset": min_len, "note": f"length diff: {length_diff}"})

    return changes

def main():
    old_bin = "[OLD_VERSION]"
    new_bin = "[NEW_VERSION]"

    print(f"[info] old: {sha256_file(old_bin)[:16]}...")
    print(f"[info] new: {sha256_file(new_bin)[:16]}...")

    changes = diff_binaries(old_bin, new_bin)

    print(f"\n=== 差分结果 ===")
    print(f"变化点数量: {len(changes)}")

    # 输出前 20 个变化点
    for c in changes[:20]:
        print(f"  offset=0x{c['offset']:x}")
        if "old" in c:
            print(f"    old: {c['old']}")
            print(f"    new: {c['new']}")
        else:
            print(f"    {c['note']}")

    if len(changes) > 20:
        print(f"  ... 共 {len(changes)} 个变化点，详见完整输出")

    # 保存完整结果
    with open("diff_result.txt", "w") as f:
        for c in changes:
            f.write(f"0x{c['offset']:x}: {c.get('old','')} -> {c.get('new',c.get('note',''))}\n")
    print(f"\n完整结果已保存: diff_result.txt")

if __name__ == "__main__":
    main()
```

运行：`python3 binary_diff.py`。验证：差分输出变化点位置与内容，`diff_result.txt` 可追溯，符号迁移后偏移验证正确。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §三 二进制差分工作流使用
