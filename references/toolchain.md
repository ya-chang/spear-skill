# 工具链装配（toolchain）

目标：在 Linux（含 aarch64 proot）上补齐逆向渗透所需工具。**缺什么装什么，别一次性全装。**

## 一、基础探测（先看看现成有什么）

```bash
for t in gdb r2 radare2 objdump readelf nm strings file rabin2 frida adb apktool baksmali upx angr; do
  which $t >/dev/null 2>&1 && echo "$t: OK" || echo "$t: MISSING"
done
python3 - <<'EOF'
for m in ["frida","angr","capstone","pwntools","androguard","unicorn","keystone","r2pipe"]:
    try: __import__(m); print(m,"OK")
    except Exception: print(m,"MISSING")
EOF
```

## 二、apt 安装（系统级工具）

```bash
sudo apt-get update
sudo apt-get install -y \
  binutils file gdb strace ltrace \
  radare2 upx-bin \
  build-essential python3-pip
```

- `binutils`：objdump / readelf / nm / strings / addr2line
- `file`：识别文件类型
- `gdb`：动态调试（aarch64 主机可用 `gdb-multiarch` 跨架构）
- `radare2`：r2 / rabin2，静态+动态一体
- `upx-bin`：UPX 脱壳

跨架构调试（在 x86 上调 ARM，或反之）：
```bash
sudo apt-get install -y gdb-multiarch
```

## 三、pip 安装（Python 库与插桩框架）

```bash
pip install --user frida frida-tools angr pwntools capstone keystone unicorn r2pipe androguard
```

- `frida`：动态插桩，跨平台，Android/iOS/桌面通吃
- `angr`：符号执行，CFG 恢复、路径枚举
- `pwntools`：pwn 工具链（ROP、格式串、shellcode）
- `capstone`：反汇编引擎（自写工具用）
- `androguard`：APK/DEX 静态分析
- `r2pipe`：从 Python 调 r2

## 四、Android 工具（做 APK/壳时）

需要 JDK + Android build-tools + platform-tools：

```bash
sudo apt-get install -y openjdk-17-jdk
# 下载 Android platform-tools（含 adb）与 build-tools（含 apksigner/zipalign）
# 或直接 pip install androguard 做静态；真机调试需 adb + frida
```

- `adb`：真机/模拟器通信
- `apktool` / `baksmali`：APK 解码、smali 修改
- `apksigner` + `zipalign`：重打包签名对齐
- `keytool`（JDK 自带）：生成 keystore

## 五、.NET 工具

- `dnSpy` / `ILSpy`：.NET 反编译（GUI，需桌面环境）
- 无 GUI 环境可用 `monodis` / `ikdasm`（命令行 IL 反汇编）：
  ```bash
  sudo apt-get install -y mono-utils
  ```

## 六、工具选择速查

| 任务 | 首选 | 辅助 |
|---|---|---|
| 通用动态调试 | GDB + pwndbg | r2 |
| 系统调用追踪 | strace | ltrace |
| 库函数追踪 | ltrace / Frida | GDB 断点 |
| 纯静态 stripped | r2 `aaa` | angr CFGFast |
| 符号执行 | angr | GDB + Python |
| 动态库 Hook | LD_PRELOAD / Frida | GDB |
| 内存错误 | Valgrind | GDB watchpoint |
| 性能热点 | perf | GDB |
| 内核态追踪 | bpftrace / perf | — |

## 七、环境限制说明

- **无 GUI 环境**（手机 proot）：IDA Pro / Ghidra / dnSpy 跑不了，用 r2 / GDB / angr / 命令行工具替代。
- **真机调试**：adb 需要连真机或模拟器，纯本机只能做静态 + 本机动态。
- **跨架构**：调 ARM 二进制在 x86 用 `gdb-multiarch` + `set architecture arm64`。
