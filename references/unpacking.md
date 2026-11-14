# 脱壳（unpacking）

目标：剥掉压缩/保护壳，拿到原始代码。**先识别，再脱壳，脱完验证。**

## 一、识别加壳

```bash
# 熵值检测：> 7.0 疑似加壳/加密
python3 -c "
import math, collections, sys
d=open(sys.argv[1],'rb').read()
f=collections.Counter(d)
h=-sum((c/len(d))*math.log2(c/len(d)) for c in f.values())
print(f'entropy={h:.4f}', 'PACKED' if h>7.0 else 'normal')" target

# 特征字符串
strings -a target | grep -iE "upx|vmprotect|themida|vmp|themida|ollvm|petite|aspack"

# 段分析
readelf -S target | grep -iE "upx|vmp|themida"
r2 -q -c 'iS~entropy; iS' target
```

| 特征 | 判断 | 处置 |
|---|---|---|
| `UPX!` 魔数 + UPX0/UPX1 段 | UPX | `upx -d` |
| 段名 `.vmp0/.vmp1` + 高熵 | VMProtect | 动态 dump（见下） |
| `.themida`/`.enigma` 段 | Themida/Enigma | 动态 dump |
| 段极少（2-3 段）+ 高熵 | 通用压缩壳 | 动态 dump |
| 高熵段 + 小解压 stub | 自定义压缩壳 | 动态 dump |

## 二、UPX 脱壳（最简单）

```bash
upx -t target            # 自检
upx -d target -o unpacked
file unpacked            # 确认变回正常 ELF
r2 -A unpacked           # 重新分析
```

UPX 用 `strings` 命中即 100% 确认，无需进一步验证。

## 三、商业壳/自定义壳动态脱壳

核心：在代码解密完成后、原始入口执行前，dump 内存。

**方法 A：mprotect 断点 + 单步到 OEP**

```bash
# 在 mprotect 被调用时停下，之后程序会解密代码
gdb -q ./target
(gdb) catch syscall mprotect
(gdb) run
# 多次触发后，从最后一次 mprotect 继续单步，直到跳到原始入口(OEP)
(gdb) x/16i $pc
(gdb) dump binary memory dumped.bin START END
```

**方法 B：Frida 内存扫描（找解密后的代码/字符串）**

```javascript
// frida_dump.js — 启动后扫描可打印字符串或代码段
Java.perform(() => {}); // 桌面无需
const start = Date.now();
let last = null;
setInterval(() => {
  const ranges = Process.enumerateRanges('r--');
  for (const r of ranges) {
    const mem = r.base.readByteArray(Math.min(r.size, 0x100000));
    if (mem) { /* 扫描明文字符串/代码特征，命中则 dump */ }
  }
}, 500);
```

```bash
frida -f ./target -l frida_dump.js --no-pause
```

**方法 C：导入表重建（找 OEP 后修复 IAT）**

dump 到 OEP 后，原始导入表可能被破坏，用以下工具重建：
- `ImportREC`（Windows PE）
- `ilya` / 自写脚本解析 `.dynamic`（ELF）
- r2 `idp` / `wav` 修复

## 四、Android DEX 壳（壳内 DEX 恢复）

APK 壳特征：小 `classes.dex`、`libabcd.so`、`assets/lib*Protect*`、`v.m.p`/`abcd655xx`、运行时才 materialize 真实 DEX。

```bash
# Frida 抓运行时 DEX
frida -U -f com.target.app -l capture_dex.js
```

```javascript
// capture_dex.js — 扫描进程内存中的 DEX 头 (\xde\x00\x00\x00 或 dey)
const DEX_MAGIC = [0xde,0x00,0x00,0x00]; // dex\0
Process.enumerateRanges('r--').forEach(r => {
  const buf = r.base.readByteArray(Math.min(r.size, 0x2000000));
  if (!buf) return;
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length - 4; i++) {
    if (bytes[i]===0xde && bytes[i+1]===0x00 && bytes[i+2]===0x00 && bytes[i+3]===0x00) {
      console.log('DEX @', r.base.add(i).toString());
      // 完整 dump 该 DEX（按 header.file_size）
    }
  }
});
```

脱完壳后转 `elf-apk-patch.md` 做重组签名，或 `deobfuscation.md` 继续。

## 五、脱壳验证

- 脱壳后文件熵值回落到正常（< 6.5）
- `file` 识别为正常 ELF/PE
- 能正常运行，功能与原程序一致
- 静态分析能看到完整函数与字符串
