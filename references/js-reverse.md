# 前端 JS 逆向（js-reverse）

目标：定位接口签名、加密参数、风控字段，把页面 JS 的算法链路还原到本地可复现。**Observe-first，Hook-preferred，Rebuild-oriented，证据优先。**

## 一、适用范围

- 定位接口签名、加密参数、风控字段
- 观察页面请求链路与脚本来源
- 运行时抓取函数入参与返回值
- 追踪 XHR/Fetch/WebSocket 触发点
- 把页面证据带回 Node 做本地复现与补环境

> 目标若是二进制/APK/PE/ELF/SO，转 `linux-dynamic.md`、`elf-apk-patch.md`。

## 二、五阶段工作流

### 1. Observe（观察）
先确认目标请求、相关脚本、候选函数，不猜环境。

- 浏览器 DevTools → Network 找目标请求，右键 "Search in content" 或 "Copy as fetch"
- Sources 面板看加载的脚本，用 Ctrl+Shift+F 全局搜关键词
- 用 `get_request_initiator` 思路回溯调用来源（DevTools 的 "Initiator" 标签）

必须产出：目标请求 URL/特征、initiator 线索、可疑脚本 URL、初始任务记录。

### 2. Capture（采样）
对目标请求做最小侵入采样，拿参数样例、调用顺序、运行时证据。

- 在 XHR/Fetch 触发点下断点（DevTools Sources → XHR/Fetch breakpoints）
- 命中后看调用栈、参数、返回值
- 必要时在目标函数下文本断点

### 3. Rebuild（重建）
把页面证据整理成本地可迭代的 Node 复现材料。

- 本地补环境必须以页面观测证据为依据
- 不允许空想式补 `window/document/navigator/crypto/storage`
- 每次只记录一个最小因果补丁决策

### 4. Patch（补环境）
按报错和 first divergence 驱动补环境，直到本地脚本稳定跑出目标参数。

- 先看缺什么，再补什么
- 一次只做一个最小补丁决策
- 每次补丁后立即复测，写入任务记录

### 5. DeepDive（深挖）
本地跑通后，做去混淆、控制流还原、业务逻辑提纯。

- 只出签名可降级此阶段
- 要长期复用算法链路必须做

## 三、核心工具

| 工具 | 用途 |
|---|---|
| 浏览器 DevTools | Network/Sources/断点，第一取证面 |
| CDP（Chrome DevTools Protocol） | 程序化控制浏览器、下断点、取栈 |
| Frida | 运行时 hook JS 引擎函数 |
| Node.js | 本地补环境复现 |
| mitmproxy / Burp | 抓改 HTTP 流量 |

## 四、常见签名链路定位

### 加密参数定位
1. Network 找到带加密参数的请求（如 `sign`、`token`、`data` 是密文）
2. Sources 全局搜参数名，定位加密函数
3. 在加密函数下断点，看输入（明文）和输出（密文）
4. 记录算法：MD5/SHA/AES/RSA/自定义

### 补环境复现骨架
```javascript
// Node 本地复现：逐步补环境，直到跑出与页面一致的 sign
const crypto = require('crypto');
// 按页面观测到的算法还原
function genSign(params) {
    // 还原的签名算法
    return sign;
}
```

## 五、AST 去混淆（必要时）

- 控制流平坦化：找 dispatcher，用覆盖率还原真实块
- 字符串加密：hook 解密函数出口收集明文
- 变量名混淆：靠调用关系和字符串引用推断

## 六、验证

- [ ] 本地复现的签名与页面运行时一致（Node 脚本生成的签名与浏览器请求的 sign 值逐字符相等）
- [ ] 多组输入验证稳定（10+ 组不同输入，本地签名与运行时全部匹配）
- [ ] 算法链路可独立复用（提取的算法不依赖原页面环境，脱离浏览器可运行）
- [ ] 补环境后无报错（FakeEnv/补环境脚本运行无未定义变量/函数缺失）
- [ ] 加密参数可独立复现（密钥、IV、盐值从样本提取，本地加密结果与运行时一致）

## 六·五、代码骨架：JS 签名复现 Node 脚本

> 可运行的 Node 脚本骨架，复现从 JS 逆向提取的签名算法。关键参数按样本替换。

```javascript
// js_sign_repro.js — JS 签名复现骨架（Node.js）
// 从浏览器 JS 逆向提取的签名算法，本地复现

// 占位：从样本提取的常量与算法
const SECRET_KEY = "[SECRET_KEY]";       // 密钥/盐值
const SIGN_ALGORITHM = "md5";            // md5/sha256/自定义

// MD5 实现（或引入 md5 库：npm i md5）
const md5 = require('md5');

// 签名函数（按逆向结果还原）
function computeSign(params) {
    // 1. 参数排序（按 key 字典序）
    const sortedKeys = Object.keys(params).sort();
    // 2. 拼接 key=value&key=value
    const str = sortedKeys.map(k => `${k}=${params[k]}`).join('&');
    // 3. 拼接密钥
    const signed = str + SECRET_KEY;
    // 4. 哈希
    return md5(signed);
}

// 验证：与浏览器运行时对比
function verify() {
    const testCases = [
        { params: { uid: "123", ts: "1700000000", q: "abc" }, expected: "[EXPECTED_SIGN_1]" },
        { params: { uid: "456", ts: "1700000001", q: "xyz" }, expected: "[EXPECTED_SIGN_2]" },
    ];

    let pass = 0;
    for (const tc of testCases) {
        const got = computeSign(tc.params);
        const ok = got === tc.expected;
        console.log(`${ok ? "PASS" : "FAIL"}: sign=${got} expected=${tc.expected}`);
        if (ok) pass++;
    }
    console.log(`\n${pass}/${testCases.length} passed`);
    return pass === testCases.length;
}

if (require.main === module) {
    verify();
}

module.exports = { computeSign, verify };
```

运行：`npm i md5 && node js_sign_repro.js`。验证：输出全 PASS，本地签名与浏览器运行时一致。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §四 签名链路还原使用

## 七、WASM/字节码加密

```javascript
// Hook WASM 导出函数
const origInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = function(buffer, imports) {
  console.log('[WASM] 加载模块，大小:', buffer.byteLength);
  return origInstantiate.call(this, buffer, imports).then(result => {
    const exports = result.instance.exports;
    console.log('[WASM] 导出函数:', Object.keys(exports));
    for (const [name, fn] of Object.entries(exports)) {
      if (typeof fn === 'function') {
        const origFn = fn;
        exports[name] = function(...args) {
          console.log(`[WASM.${name}] 入参:`, args);
          const result = origFn.apply(this, args);
          console.log(`[WASM.${name}] 返回:`, result);
          return result;
        };
      }
    }
    return result;
  });
};
// 下载 .wasm 文件后用 wasm-decompile / Ghidra 静态分析
```

### 7.1 WASM 自写解析器（工具链缺失时的兜底）

`wasm2wat` / `wabt` 装不上时，直接写 Python 解析器拆段：按 **type / function / code / data** 四个核心段逐个解析，就能把模块结构读出来。实战案例：98 字节原始 WASM 被膨胀到 6.8MB（塞诱饵语料），解析后真身只有 9 个函数——膨胀不改变段结构，自写解析器照样拆得开。

### 7.2 导出别名识别：函数海里找真身

导出表里大量别名指向同一个函数是常见干扰（实战案例：258 个导出，250 个是指向同一个函数的别名）。识别方法：

```javascript
// JS 侧按 arity 遍历试调：别名导出通常共享同一真身
const names = Object.keys(exports);
for (const name of names) {
    const fn = exports[name];
    if (typeof fn === 'function' && fn.length === 2) {  // 按实际签名过滤
        try {
            const r = fn(probeArg1, probeArg2);           // 探针调用
            console.log(name, '->', r);
        } catch (e) { /* 记录异常，继续 */ }
    }
}
// 命中真身后再用导出名做交叉确认
```

要点：别名共享真身 → 试调第一个命中即真身；导出名（如 `enclave_export_fad0_N`）是掩护，不看名字看行为。

### 7.3 离线校验器回环自证

逆出 WASM 算法后，**不碰原 WASM、用纯软件复刻校验逻辑**，再做回环验证：

1. 用构建源码（或已知答案）造 fixture：已知 key + 已知 flag，走完整加密流程；
2. 用复刻的 checker 还原 salt/rounds/commit，并把 flag 解回来；
3. 比对 fixture 的 salt/rounds/commit 与真实数据，`FLAG ROUNDTRIP: PASS` 才算逆对。

回环自证的前提是**不 trust 自己的理解**——用作者构建源码当标准答案对拍，而不是拿自己的逆推当答案。

### 7.4 WASM 内嵌常量直接 dump

WASM 的 data 段是明文常量，焊死的数据（如加密打包的 header/cipher、明文承诺 commit、SHA-256 的 K 常数表 + IV）直接按地址 dump：

```
data@0      加密打包的 header+cipher（被 mask XOR 保护）
data@12288 明文承诺 COMMIT（对应 seal.json 的 revision）
data@16384 SHA-256 K 常数表 + IV
```

dump 出常量后，算法全公开、数据全暴露——剩下的变量只有 key，这决定了下一步是撞 key、撞 flag 还是找泄露（见 crack-workflow §六）。

> 更新：2026-11-18 · 来源：看雪帖 2138186《加固个屁：BLA v9 逆向吐槽及逆向过程》（脱壳破解区）

## 八、JS 混淆还原工具

```bash
# synchrony - javascript-obfuscator 专用
npm install -g synchrony
synchrony deobfuscate input.js -o output.js

# webcrack - webpack + obfuscator 还原
npm install -g webcrack
webcrack input.js -o output_dir

# de4js - 在线反混淆器: https://lelinhtinh.github.io/de4js/
# JStillery - 常量折叠 + 死代码消除
```

**动态调试技巧：**
1. Sources 面板 → 搜索 `encrypt` / `sign` / `hash`
2. 在匹配函数第一行打断点
3. 触发登录/请求 → 断点命中 → 查看调用栈
4. 沿调用栈向上找到密钥、IV 等参数来源

## 九、密钥提取技巧

```javascript
// 1. 硬编码在 JS 中（最常见）
// 搜索 Base64 字符串
curl -s https://example.com/static/js/app.js | \
  grep -oP '["'"'"'][A-Za-z0-9+/=]{16,}["'"'"']' | sort -u

// 2. 从页面 HTML 中提取
document.querySelectorAll('[data-key], [data-token], [data-secret], [name="csrf"]')

// 3. 从接口响应获取（首次加载时后端下发密钥/公钥）

// 4. 从 Cookie 中获取
document.cookie.split(';').forEach(c => console.log(c.trim()))
```

## 十、加密分析工具速查

| 工具 | 用途 | 命令/入口 |
|---|---|---|
| **synchrony** | javascript-obfuscator 反混淆 | `synchrony deobfuscate input.js -o out.js` |
| **webcrack** | webpack + obfuscator 还原 | `webcrack input.js -o dir` |
| **de4js** | 在线 JS 反混淆器 | 网页工具 |
| **CyberChef** | 编码/解码/加解密瑞士军刀 | 网页工具 / 本地 |
| **jwt.io** | JWT 在线解码调试 | 网页工具 |
| **hashcat** | 哈希破解 | `hashcat -m 0 hash.txt wordlist` |
| **openssl** | 证书/密钥/加密命令行 | `openssl enc -aes-256-cbc -in plain -out enc` |
| **wasm-decompile** | WASM 反编译 | `wasm-decompile module.wasm` |

---

## 十一、补环境方法论与 WASM/JSVMP 黑盒实战

### 一、目标定位：先找"加密入口"，不要读整个 bundle

按性价比排序的入口定位法：

1. **搜索提交的字段名**（`password`、`sign`、`encrypt`、`token`），只保留赋值处，不要搜定义处。
2. **XHR/fetch hook 反查调用栈**：在 `XMLHttpRequest.prototype.send` / `fetch` 里打断点，向上找第一帧业务代码（不是 SDK 帧）。
3. **对 `JSON.stringify` 入参做二次 hook**：在 `send` 处把 body 打印出来，与明文对比，定位差异字段。
4. **`Object.defineProperty` 监听 window 上的加密对象**（`window.xxx = ...` 被赋值的瞬间）。
5. 以上都不行 → 抓一份**真机通过的完整请求样本**，照样本构造，而不是猜算法。

> 找入口的时间应该占整个任务的 60%，且**永远不要从 `eval` 或超长单行文件的第一行开始读**。

### 二、补环境方法论

补环境的目标不是"让脚本跑起来"，是**让脚本在缺少浏览器的情况下做出和浏览器一样的判断**。

**缺什么补什么（错误驱动），不要一次补全**——一次补全套会产生大量"看起来对但值不对"的假环境，反而更难查。正确循环：

```
跑 → 报 "Cannot read property 'x' of undefined"
   → 补 stub（先返回 Proxy 兜底，记录所有被访问的属性）
   → 再跑
```

`Proxy` 兜底 + 访问日志是所有补环境的第一步，它同时给你**属性依赖清单**。

**日志 hook 优先级（按信息量排序）**：

| 优先级 | Hook 点 | 为什么 |
|---|---|---|
| ★★★ | `TextEncoder.prototype.encode` / `decode` | 明文进出加密函数的必经点 |
| ★★★ | `MessagePort.prototype.postMessage` / `worker.onmessage` | jsvmp/WASM 常把核心放 worker，主线程只传参 |
| ★★★ | `WebAssembly.instantiate` / `Instance.exports` | 拿到 wasm 导出名与内存，可直接改内存观察 |
| ★★ | `document.createElement`（返回对象全部方法打日志） | 指纹采集点 |
| ★★ | `CanvasRenderingContext2D.prototype.getImageData` / `toDataURL` | canvas 指纹 |
| ★★ | `Date.now` / `performance.now` | 时间戳参与签名，patch 成定值让签名稳定化 |
| ★ | `navigator` / `screen` / `Intl` 属性 getter | 指纹补充 |
| ★ | `crypto.subtle.*` | 少见于国内风控，一见说明有标准算法 |

**关键技巧**：把 `Date.now` 固定成常量。签名里的时间戳一固定，同样输入得到同样输出，可以反复 diff。

**跨 realm 陷阱（最容易白干）**：

| 陷阱 | 表现 | 解法 |
|---|---|---|
| `instanceof` 跨 realm 失效 | 在 Node 里 `arr instanceof Array` 为 false，数组来自 vm 沙箱 | 用 `Array.isArray` / `Object.prototype.toString.call` |
| `Uint8Array` 跨 realm | 传进 wasm 报类型错 | 在**目标 realm 内**创建：`vm.runInContext('new Uint8Array(n)')` |
| Proxy 包装破坏原生检测 | `toString` 返回 `[object Object]` 被检测出非原生 | 伪造 `Function.prototype.toString`，返回 `function () { [native code] }` |
| 原型链被 sandbox 隔离 | 修改 `Object.prototype` 影响不到目标 | 在目标 context 内注入 |

### 三、时序与竞态（很多"算法不对"其实是时序不对）

真实翻车：伪造 WebSocket 时用 `setTimeout(0)` 派发消息，真实实现是 `setInterval(50)` 轮询——消息到达顺序错乱，签名永远对不上。

| 现象 | 根因 | 处理 |
|---|---|---|
| 真实浏览器有值，脚本里永远 undefined | 依赖 `requestAnimationFrame`/`setInterval` 轮询 | fake timer 手动推进，或按真实间隔重放 |
| 消息顺序错乱 | 同步派发 vs 队列派发 | 复刻真实实现：macro task 还是 micro task |
| 加密结果随请求次数变化 | 内部递增计数器/nonce 池 | 找到计数器变量，与真实样本对齐初值 |
| 一秒内两次请求第二次失败 | 服务端要求 nonce 单调递增或时间窗 | 保留真实时间，只冻结"参与哈希的那个时间" |

> **规律：凡是"逻辑看着对、结果就是不对"，先查时序和类型，再查算法。**

### 四、契约矩阵：入参类型 × 返回类型

不要"跑通一次"就写进代码。用矩阵取样，每格至少 3 个真实样本：

| 入参形态 | 返回形态 | 备注 |
|---|---|---|
| `Uint8Array` | `Uint8Array` | 二进制管道 |
| `string`(utf8) | `string`(base62) | 常见于签名 |
| `string`(base64) | `ArrayBuffer` | 常见于响应解密 |
| `object` | `string` | JSON → 序列化 → 加密 |

**自定义字母表**：base62 字母表可任意排列（真实案例是**小写在前**：`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`）。判断方法：拿已知明文的输出逐位反查 index，看与期望值是否同余；再暴力常见几种排列（标准/大小写互换/小写在前/数字在前）。

### 五、服务端错误文本 = 免费的结构文档

故意喂畸形输入，读错误信息：

| 错误文本 | 泄露的信息 |
|---|---|
| `unpack(b) received extra data` | 字段读完了但还有剩余字节 → **结构比你猜的短** |
| `invalid length: 33` | 长度字段被当成内容长度而非总长 |
| `bad magic` / `unknown version` | 头部有 magic + version，校验很靠前 |
| 空响应/直接断开 | 触发风控或格式检查更早失败 |
| 500 而不是 400 | 解析通过了，崩在业务层 → 结构是对的 |

执行方式：保留合法请求，只改一个字节/长度，记录错误码与文本，画"哪个字段被校验"的表。

### 六、瑞数 6（及同类动态 cookie）两阶段

```
① 首次请求（无 cookie）→ 返回混淆 JS → 在浏览器补环境执行 → 生成动态 cookie
② 后续请求带 cookie → 服务端校验 → 通过后返回业务数据
```

关键性质：cookie 里有一段**签名后缀**，**与 path 绑定**（换 path 必须重算）；**时间绑定 + 会话绑定**——不能算一次用一天，必须**每请求重算**；JS 每段时间会变——**不要把算好的 cookie 硬编码**，进程内保持"能算"的环境。

工程上正确做法：本地常驻一个 headless 环境（或 Node 补环境），对外暴露 `getCookie(path)`，业务侧按需调用。缓存 key 用 `(path, 时间窗)`。

### 七、滑块 / 行为验证

**核心结论：决定成败的是轨迹真实性，不是加密算法。**

| 观察 | 结论 |
|---|---|
| 真机样本 `transform(i) ≡ i`（5 次真实拖动验证） | 轨迹变换是恒等映射，不需要还原变换 |
| 真机 `touchList` 只有 1–2 条 `click` | **不要往里塞 mousedown/move/up**，那是错误的直觉 |
| x 整数单调、每 tick ≈ 4ms、y 轻微负漂移、中途有停顿 | 参数化生成器按这四条约束造 |
| 验证返回 16130 / 通用失败码 | 绝大多数是轨迹不像人，而不是签名错 |

工程顺序：**先用真机样本回放 → 通过后再参数化扰动**。不要一上手就写生成器。

### 八、jscvmp / 虚拟机型 JS 保护：只做"够用"的三件事

不做全量反虚拟化：

1. **找被比较的值**：在 `===` / `!==` / `charCodeAt` 比较处下断点，直接读**比较前一瞬**的寄存器/变量。不要从第一个字符开始追。
2. **找导出边界**：VM 一定有个"入口函数 + 出口返回"，记录入口参数和出口返回，之后当黑盒调用。
3. **常量 dump**：注入探针把 VM 的常量表、字节码数组 dump 出来，比读 3 万行 switch 有效。

### 九、WASM 加固：黑盒调用，不要复现公式

**这是最重要的一条。** 手写复现一个变换时容易把指令看错（真实翻车：把 `rotl` 当成 `shr`）。正确做法：只要 wasm 能 instantiate（补好 import），**它就是一台可调用的黑盒**：

```js
const { instance } = await WebAssembly.instantiate(bytes, imports);
const out = instance.exports.sub_1234(input);  // 直接用真实导出
```

| 目标 | 做法 |
|---|---|
| 求变换的输入输出关系 | 批量喂输入、收集输出、拟合 |
| 找密钥 | 把 key 参数改成可控，观察输出变化（差分） |
| 验证算法身份 | 与公开实现（AES/SM4/SHA-256）对拍 |
| 越过反调试 | wasm 反调试常检查 imports 提供的函数，直接提供"永远正常"的实现 |

**补 import 的顺序**：先全返回 0 的 stub 跑一遍 → 报缺哪个就补哪个（和补环境同一个循环）。

**规模体检（先判断真实信息量）**：真实案例 98 字节 WASM 被吹成 6.8MB（约 7 万倍）。体检指标：原始 .wasm 大小 vs 处理后大小（膨胀 >100× 说明主体是填充/分片/死代码）、导出函数数 vs `code` 段函数数（大量从不导出 = 诱饵）、`code` 段平均函数体大小（极小 = 分片壳）、字符串表（大量碎字符串 = 字符串分片保护）、JS 侧调用点数（只调 1~2 个导出 = 黑盒边界清晰）。信息量小 → 优先"黑盒调用 + 逐字节爆破"，不要读反汇编。

**常量提取**：`data` 段直接 dump（明文常量、S-Box、置换表常在这里）；**探针注入**——在 `i32.const`/`i64.const` 处插入 `call $log`，运行时把所有常量按出现顺序打出来，比重读字节码快十倍，且自带"执行的才是真的"过滤（死代码常量不会出现）。

**逐字节可除性爆破**：校验是"逐字节比较且提前返回"时，用时间/返回码把密钥一位一位切出来：

```
for pos in 0..n:
  for c in charset:
    if oracle(guess[0..pos] + c) 显示"又对了一位": guess[pos] = c
```

判据不能只看 true/false，要看**中间态**（返回码、输出长度、耗时、错误文案）。

**恒真条件与恒等变换**（识别后可整段消掉）：恒真谓词（如 `Math.imul(x, x+1) & 1 === 0`，相邻整数必一奇一偶，对 x 采样 0..255 恒为真即删）、恒等变换（多样本采样确认，案例用了 5 次真机拖动）、字符串分片恒真（9 段拼接+每段守卫，守卫全删只剩拼接）、无用算术链（`x = x*1 + 0; x ^= 0;` 常量折叠即可）。采样一定要**跨边界**（0、1、-1、最大值、NaN、undefined）。

**蜜罐与投毒**：蜜罐凭据（一堆像密钥的字符串、假 flag，任何候选 key 先做已知答案验证，一验就露馅）；认知投毒（SGX/TPM 飞地清单、高拟真影子状态机是给"读代码的人"看的，不参与真实路径，只信**执行轨迹**）；死代码陷阱（完整实现的假校验函数，用覆盖率/断点确认是否被执行）。

**无门之墙的识别（什么时候该停）**：密钥不在这份产物里。七条攻击路线（静态提取、动态 dump、差分、爆破、符号执行、补环境、hook）全部失败，因为密钥由服务端下发或用不可获得的硬件状态派生。识别信号：所有候选 key 都对不上任何已知答案；动态 dump 的"密钥"下次运行就变且与任何请求/时间无关联；关键常量在产物里搜不到且运行时由网络/系统 API 返回。这时正确产出是**写下七条路为什么都不通**，附上每条路的实验与结论——把问题定性，别人才不会重复踩。

### 验证

- [ ] 加密入口按字段名/XHR 调用栈/JSON.stringify 入参定位，未从 eval 或超长单行第一行开始读
- [ ] 补环境用错误驱动循环（Proxy 兜底 + 访问日志），跨 realm 陷阱已处理
- [ ] `Date.now` 冻结策略明确，时序/类型已对照真实样本排查，非直接怀疑算法
- [ ] 入参×返回契约矩阵每格 ≥3 真实样本；字母表按常见排列暴力验证
- [ ] WASM 走黑盒调用（真实导出），未复现公式；恒真/恒等/蜜罐已识别，只信执行轨迹
- [ ] 同一 session 连续 200 次请求成功率 > 98%，换 IP/UA/跨午夜各测一轮，畸形输入的错误行为与原服务端一致

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）
