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

- 本地复现的签名与页面运行时一致
- 多组输入验证稳定
- 算法链路可独立复用

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
