# 通用逆向方法论（re-methodology）

适用于 PE / ELF / MACH-O / APK / SO / 固件 / JS 等任意目标。四阶段循环。

## 阶段 0：建档与基线

```bash
sha256sum target
file target
readelf -h target      # ELF；PE 用 pefile；Mach-O 用 otool
readelf -S -l target   # 段、程序头
readelf -d target      # 动态依赖、NEEDED
strings -a target | head -100
```

记录：文件类型、架构（x86/x64/ARM/ARM64）、编译器与优化级别、安全标志（PIE/NX/canary/RELRO/CFI）、入口点、导入表。

## 阶段 1：静态侦察

```bash
r2 -A -q -c 'aaa; afl; axt' target      # r2 全量分析 + 函数列表 + 交叉引用
r2 -q -c 'iI; iS~entropy' target        # 信息 + 段熵值（判断是否加壳）
objdump -d target | less                 # 反汇编
nm target                               # 符号表（未 strip）
```

- 熵值 > 7.0 → 疑似加壳/加密（转 `unpacking.md`）
- 函数极少 + 大量 `call [reg]` → 混淆/VM（转 `deobfuscation.md` / `vm-bytecode.md`）
- 有 `v.m.p`/`abcd`/小 DEX/`libabcd.so` → 壳（转 `elf-apk-patch.md`）

## 阶段 2：动态验证

静态看不清的（自解密、运行时 DEX、动态调用）用动态补：

```bash
strace -tt -T ./target 2>&1 | tee /tmp/strace.log
ltrace -e strcmp,memcmp,EVP_*,AES_* ./target
gdb -q ./target
frida -f ./target -l hook.js
```

动态优先看：
- `open`/`read`：密钥文件、配置、运行时 DEX
- `mprotect(EXEC)`：自解码/脱壳触发点
- `strcmp`/`memcmp`：密码/校验比较
- 加密库函数：算法识别

## 阶段 3：定位与还原

- **定位 CHECK_FN**：找校验/激活/注册入口。线索：字符串 "register/license/key/激活"、`strcmp` 热点、返回值分支。
- **还原算法**：识别加密/哈希/签名算法（见 `deobfuscation.md` 算法特征表），还原成可复现的 Python/C 实现。
- **还原结构**：vtable、结构体布局、类型重建（见 `linux-dynamic.md` 结构体恢复）。

## 阶段 4：交付与验证

- 打补丁：记录 `OFFSET` + `PATCH_BYTE`，保留原始副本，验证字节级差异仅在目标处。
- 写注册机：还原算法后，用独立实现生成有效序列号/卡密，回填验证。
- 重建镜像：脱壳/重组后，验证可运行 + 行为等价。

**完成标准**：不是"能安装"，而是"校验通过 + 行为符合预期 + 有验证证据"。

## 常用命令速查

| 目的 | 命令 |
|---|---|
| 看入口/段 | `readelf -h -l target` |
| 看导入 | `readelf -d target` / `rabin2 -i target` |
| 反汇编函数 | `objdump -d target` / `r2 pdf @ sym` |
| 找字符串引用 | `r2 axt @ <addr>` |
| 搜字节 | `r2 /x <hex>` / GDB `find` |
| 看内存映射 | `cat /proc/<pid>/maps` / pwndbg `vmmap` |
| 查算法常数 | `strings` + 常数表（0xd76aa478=MD5，0x63=AES S-box） |
