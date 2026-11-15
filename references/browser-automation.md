# 浏览器与桌面自动化（browser-automation）

目标：统一自动化入口——浏览器自动化（Playwright / agent-browser）和 Windows 桌面应用自动化（OpenReverse）。**网页用 Playwright，桌面应用用 OpenReverse，两者都需要就组合。**

## 一、适用范围

### 浏览器场景（Playwright / agent-browser）
- 打开网页并操作页面元素（点击、填表、提交）
- 爬取页面内容或截图
- 自动化登录流程
- 渗透测试中与 Web 页面交互（提交 payload、触发 XSS）
- 验证码页面的自动化处理
- 批量表单提交

### 桌面应用场景（OpenReverse）
- 操作 Windows 桌面应用（IDA Pro、x64dbg、Wireshark 等）
- 需要视觉驱动交互（CUA 模式）
- 需要结构化 UI 操作（UIA 模式）
- 桌面应用的网络流量观察（内置 mitmproxy）
- 自动化逆向工具的 GUI 操作
- 黑盒测试桌面软件

### 与其他工具的分工

| 场景 | 用什么 |
|------|--------|
| 操作网页（浏览器内） | **Playwright / agent-browser** |
| 操作桌面应用（Windows GUI） | **OpenReverse** |
| 抓包分析、HTTP 请求捕获 | anything-analyzer 或 OpenReverse network lane |
| JS 断点、Hook、CDP 调试 | jshookmcp |
| 定位签名算法、补环境复现 | js-reverse |

**简单判断：**
- 目标是网页 → Playwright
- 目标是 Windows 桌面应用 → OpenReverse
- 两者都需要 → 组合使用

## 二、浏览器自动化核心工作流（Playwright / agent-browser）

```bash
# 1. 打开页面
agent-browser open <url>

# 2. 获取可交互元素（返回 @e1, @e2... 引用）
agent-browser snapshot -i

# 3. 用引用操作元素
agent-browser click @e1
agent-browser fill @e2 "text"

# 4. 完成后关闭
agent-browser close
```

## 三、agent-browser 命令速查

### 导航与生命周期
```bash
# 打开页面
agent-browser open "https://target.com/login"

# 等待页面加载完成
agent-browser wait --load networkidle

# 关闭浏览器（必须执行，否则进程泄漏）
agent-browser close
```

### 页面快照
```bash
# 完整无障碍树（调试用）
agent-browser snapshot

# 仅可交互元素（推荐，返回 @e1, @e2... 引用）
agent-browser snapshot -i
```

### 元素交互
```bash
# 点击
agent-browser click @e1

# 填写文本框
agent-browser fill @e2 "admin"

# 逐字符输入（适合有 JS 监听的输入框）
agent-browser type @e2 "password123"

# 按键
agent-browser press Enter
agent-browser press Tab
agent-browser press Escape

# 滚动
agent-browser scroll down 500
agent-browser scroll up 300
```

### 信息获取
```bash
# 获取元素文本
agent-browser get text @e1

# 获取页面标题
agent-browser get title

# 获取当前 URL
agent-browser get url
```

### 等待策略
```bash
# 等待元素出现
agent-browser wait @e1

# 等待固定时间（毫秒）
agent-browser wait 2000

# 等待网络空闲
agent-browser wait --load networkidle

# 等待导航完成
agent-browser wait --load domcontentloaded
```

**注意事项：**
- 必须执行 `agent-browser close`，否则进程泄漏
- 操作前先 snapshot，不要猜元素引用
- 提交表单后用 `wait --load networkidle` 等页面稳定

## 四、渗透测试常用模式

### 自动化登录
```bash
agent-browser open "https://target.com/login"
agent-browser snapshot -i
agent-browser fill @username "admin"
agent-browser fill @password "password123"
agent-browser click @login_button
agent-browser wait --load networkidle
agent-browser get url                    # 确认是否跳转到后台
```

### XSS Payload 注入
```bash
agent-browser open "https://target.com/search"
agent-browser snapshot -i
agent-browser fill @search_input "<script>alert(1)</script>"
agent-browser click @search_button
agent-browser wait --load networkidle
agent-browser snapshot                   # 检查 payload 是否被渲染
```

### 表单批量提交（配合脚本）
```bash
payloads=("' OR 1=1--" "<img src=x onerror=alert(1)>" "{{7*7}}")
for p in "${payloads[@]}"; do
    agent-browser open "https://target.com/form"
    agent-browser snapshot -i
    agent-browser fill @input "$p"
    agent-browser click @submit
    agent-browser wait --load networkidle
    agent-browser snapshot              # 检查响应
done
agent-browser close
```

### Cookie / LocalStorage 提取

agent-browser 不直接暴露 cookie，需要用 Playwright 脚本模式：

```javascript
// playwright-extract.js
const { chromium } = require('playwright');
(async () => {
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto('https://target.com');

    // 提取 cookies
    const cookies = await context.cookies();
    console.log(JSON.stringify(cookies, null, 2));

    // 提取 localStorage
    const storage = await page.evaluate(() => JSON.stringify(localStorage));
    console.log(storage);

    await browser.close();
})();
```

### 截图取证
```javascript
// playwright 脚本模式
await page.screenshot({ path: 'evidence.png', fullPage: true });
```

## 五、Playwright Node.js API 速查

### 基础模板
```javascript
const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({
        headless: true,           // 无头模式
        // proxy: { server: 'http://127.0.0.1:8080' }  // 走 Burp 代理
    });
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,  // 忽略证书错误
        userAgent: 'Mozilla/5.0 ...',
    });
    const page = await context.newPage();

    await page.goto('https://target.com');
    // ... 操作 ...

    await browser.close();
})();
```

### 常用选择器
```javascript
// CSS 选择器
await page.click('#login-btn');
await page.fill('input[name="username"]', 'admin');

// 文本选择器
await page.click('text=Submit');
await page.click('button:has-text("Login")');

// XPath
await page.click('xpath=//button[@type="submit"]');

// 组合
await page.click('form >> input[type="submit"]');
```

### 网络拦截
```javascript
// 拦截请求
await page.route('**/api/**', route => {
    console.log('API call:', route.request().url());
    route.continue();
});

// 修改请求
await page.route('**/api/auth', route => {
    route.continue({
        headers: { ...route.request().headers(), 'X-Admin': 'true' }
    });
});

// 拦截响应
await page.route('**/api/user', async route => {
    const response = await route.fetch();
    const json = await response.json();
    json.role = 'admin';  // 篡改响应
    route.fulfill({ response, json });
});
```

### 等待与断言
```javascript
// 等待元素
await page.waitForSelector('#result');
await page.waitForSelector('.error', { state: 'visible' });

// 等待网络请求
const [response] = await Promise.all([
    page.waitForResponse('**/api/login'),
    page.click('#login-btn'),
]);
console.log(response.status(), await response.json());

// 等待导航
await Promise.all([
    page.waitForNavigation(),
    page.click('a[href="/admin"]'),
]);
```

## 六、桌面应用自动化（OpenReverse）

### 概述

[OpenReverse](https://github.com/zhexulong/openreverse) 是面向 AI Agent 的桌面交互与证据采集框架，支持：
- **UIA 模式**：Windows UI Automation，结构化桌面控件操作
- **CUA 模式**：视觉驱动交互（Computer Use Agent），适合复杂 GUI
- **网络观察**：内置 mitmproxy 代理 + 本地抓取

### 交互模式选择

| 模式 | 适合场景 | 底层 |
|------|---------|------|
| UIA | 目标应用有标准 Windows 控件（按钮、文本框、列表） | Windows UI Automation API |
| CUA | 目标应用 UI 复杂或非标准控件（IDA 的反汇编视图、自定义渲染界面） | 视觉识别 + 鼠标键盘 |

### 网络观察模式

| 模式 | 适合场景 |
|------|---------|
| Proxy Lane | 目标应用可以配置代理（推荐） |
| Local Lane | 目标应用无法走代理，需要本地抓取 |

### 模式选择速查

| 模式 | 命令前缀 | 适合场景 |
|------|---------|---------|
| UIA | `openreverse uia ...` | 标准 Windows 控件（按钮、文本框、列表） |
| CUA | `openreverse cua ...` | 复杂/非标准 GUI（IDA 反汇编视图、自定义渲染界面） |

### UIA 模式（结构化控件操作）
```bash
# 启动应用
openreverse uia launch "C:\Tools\x64dbg\x64dbg.exe"

# 获取窗口树
openreverse uia tree

# 点击按钮
openreverse uia click "Button:Open"

# 填写文本框
openreverse uia fill "Edit:FilePath" "C:\sample.exe"

# 选择菜单
openreverse uia menu "File > Open"

# 获取控件文本
openreverse uia get-text "Edit:Output"
```

### CUA 模式（视觉驱动交互）
```bash
# 截图当前屏幕
openreverse cua screenshot

# 点击屏幕坐标
openreverse cua click 500 300

# 双击
openreverse cua dblclick 500 300

# 输入文本
openreverse cua type "search string"

# 按键
openreverse cua key "ctrl+g"    # IDA: Go to address
openreverse cua key "F5"        # IDA: Decompile
openreverse cua key "F9"        # x64dbg: Run
```

### 网络观察（mitmproxy）
```bash
# 启动代理模式观察
openreverse network start --mode proxy --port 8888

# 启动本地抓取模式
openreverse network start --mode local --filter "target.exe"

# 获取捕获的请求
openreverse network list

# 导出为 HAR
openreverse network export har output.har

# 停止观察
openreverse network stop
```

## 七、逆向工具自动化组合

### IDA Pro 自动化（OpenReverse + ida-reverse）
```text
场景：批量分析多个样本

1. openreverse cua launch "ida64.exe"
2. 对每个样本：
   a. openreverse cua key "ctrl+o"        # 打开文件对话框
   b. openreverse uia fill "Edit:FileName" "sample_N.exe"
   c. openreverse uia click "Button:Open"
   d. 等待分析完成（轮询 IDA 标题栏）
   e. 通过 ida-reverse MCP 工具提取结果
   f. openreverse cua key "ctrl+w"        # 关闭数据库
```

### x64dbg 自动化调试
```text
场景：自动化断点设置与数据采集

1. openreverse uia launch "x64dbg.exe"
2. openreverse cua key "F3"               # 打开文件
3. openreverse uia fill "Edit:FileName" "target.exe"
4. openreverse uia click "Button:Open"
5. openreverse cua key "ctrl+g"           # Go to address
6. openreverse cua type "0x401000"
7. openreverse cua key "F2"               # 设置断点
8. openreverse cua key "F9"               # 运行
9. openreverse cua screenshot             # 截图保存状态
```

## 八、按需自举（On-Demand Bootstrap）

### 自动化能力边界

| 工具 | 可自动安装 | 安装方式 | 说明 |
|------|-----------|---------|------|
| Playwright | ✓ | npm + npx playwright install | 浏览器自动化引擎 |
| agent-browser CLI | ✓ | npm install -g agent-browser | 浏览器操作 CLI |
| Node.js | ✓ | winget | 前置依赖 |
| OpenReverse | ✗ | 手动 clone + npm install | 实验阶段，依赖较重 |
| mitmproxy | ✗ | 手动安装 | OpenReverse 网络观察依赖 |

### 自举触发
- 浏览器操作缺 Playwright → 自动 bootstrap
- 桌面操作需要 OpenReverse → 引导用户手动安装（给出完整步骤）

### OpenReverse 手动安装引导

如果检测到需要桌面应用自动化但 OpenReverse 未安装：

```markdown
⚠️ **需要 OpenReverse 进行桌面应用自动化**

**安装步骤**：
1. `git clone https://github.com/zhexulong/openreverse.git`
2. `cd openreverse && npm install`
3. `npm run init:agents -- --target=all <你的项目路径>`
4. 如需视觉模式：`npm run install:cua-runtime`
5. 如需网络观察：`npm run install:mitmproxy`

**验证**：`npm run doctor:cua-runtime` 和 `npm run doctor:network`
```

## 九、安装与依赖

### Playwright
```bash
# 安装 Node.js（如果没有）
winget install OpenJS.NodeJS.LTS

# 安装 Playwright
npm install -g playwright
npx playwright install          # 下载浏览器引擎

# 安装 agent-browser CLI
npm install -g agent-browser
```

### OpenReverse
```bash
git clone https://github.com/zhexulong/openreverse.git
cd openreverse
npm install
npm run init:agents -- --target=all <项目路径>

# 可选：CUA 运行时
npm run install:cua-runtime
npm run doctor:cua-runtime

# 可选：网络观察
npm run install:mitmproxy
npm run doctor:network
```

## 十、常见问题与解决

| 问题 | 原因 | 解决 |
|------|------|------|
| agent-browser 无响应 | 进程泄漏 | 先 `agent-browser close`，再重新 open |
| 元素引用失效 | 页面已刷新 | 重新 `snapshot -i` 获取新引用 |
| 填表无效 | JS 监听 input 事件 | 用 `type` 代替 `fill` |
| HTTPS 证书错误 | 自签名证书 | Playwright: `ignoreHTTPSErrors: true` |
| 页面加载超时 | 网络慢/资源多 | 增加 timeout 或用 `domcontentloaded` |
| UIA 找不到控件 | 应用使用自绘控件 | 切换到 CUA 模式 |
| CUA 点击偏移 | 分辨率/DPI 不匹配 | 先 screenshot 确认坐标 |

## 十一、相关资源

| 资源 | 说明 | 链接 |
|------|------|------|
| Playwright 官方文档 | API 参考 | https://playwright.dev/docs/intro |
| OpenReverse | 桌面自动化框架 | https://github.com/zhexulong/openreverse |
| mitmproxy | HTTP/HTTPS 代理 | https://mitmproxy.org/ |
| Windows UI Automation | UIA 文档 | https://learn.microsoft.com/en-us/windows/win32/winauto/entry-uiauto-win32 |

## 十二、路由上下文

**上游入口**：`skills/SKILL.md`（总控）、`routing.md`
**适用场景**：任何需要自动化操作浏览器或桌面应用的任务
**下游出口**：
- 抓到的请求需要分析 → `anything-analyzer` 或 `js-reverse`
- 需要 JS 调试/Hook → `jshookmcp`
- 需要还原签名算法 → `js-reverse`
- 桌面应用是逆向工具 → `ida-reverse/`

**同级关联模块**：`js-reverse`（浏览器操作后可能需要分析 JS）、`ida-reverse`（OpenReverse 可以自动化操作 IDA GUI）

## 十三、验证

- 浏览器自动化能完成登录、表单提交、XSS 注入、截图取证等操作
- Playwright 脚本能拦截/修改请求与响应，选择器与等待策略正确
- OpenReverse UIA/CUA 模式能操作目标桌面应用，网络观察能捕获流量
- 逆向工具（IDA/x64dbg）自动化组合能完成批量分析与断点调试
- 所有操作后正确关闭浏览器/应用，无进程泄漏
