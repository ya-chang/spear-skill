# API 安全测试（api-security）

目标：覆盖 REST / GraphQL / WebSocket / SOAP 全协议，从发现到利用。**先发现端点，再测认证授权，最后测业务逻辑。**

## 一、10 阶段测试流程

### Phase 1: API 发现与侦察
```bash
# 主动发现
# Vespasian：无头浏览器爬取 → OpenAPI/GraphQL SDL
# Kiterunner / ffuf：爆破未文档化端点
# 检查常见路径：/swagger.json /openapi.json /graphql /api-docs
```

GraphQL 内省三级尝试：标准内省查询 → 精简查询（绕 WAF）→ 仅查 `__schema { types { name } }`。

### Phase 2: 认证测试
**JWT**（jwt_tool / Burp）：
- `alg:none` 攻击：头部改 `"alg":"none"`，清空签名
- 密钥混淆：RS256 公钥 → HS256 对称密钥
- 弱 HMAC 爆破：`jwt_tool -C -d wordlist.txt`
- 声明篡改：改 `exp`/`iat`/`sub`/`role`
- `kid` 注入：`../../etc/passwd` → HMAC 签名绕过

**OAuth 2.0**：redirect_uri 操控、state 缺失 CSRF、Token 在 Referer 泄漏、PKCE 缺失。

### Phase 3: 授权测试（BOLA/IDOR/BFLA）
- **BOLA**：遍历数字 ID `/user/1→/user/2`、UUID、用户名/邮箱；Burp Autorize 双会话对比
- **BFLA**：普通用户执行管理员 API、HTTP 方法切换、API 版本降级、批量操作注入

### Phase 4: GraphQL 专项
内省泄漏、别名过载 DoS、批查询 DoS、字段重复、指令过载、循环查询、字段建议信息泄漏、GraphiQL 暴露、GET 突变 CSRF、追踪模式元数据泄漏。

### Phase 5: REST 输入验证
- HTTP 方法切换、Content-Type 篡改、NoSQL 注入 `{"$gt":""}`、SSRF via URL、XXE、参数污染、批量赋值

### Phase 6: 业务逻辑与差分测试
多角色权限矩阵、优惠券/积分/价格操控、竞态条件 TOCTOU。

### Phase 7: WebSocket 测试
端点发现、消息注入、超大消息、类型混淆、跨站点 WebSocket 劫持（CSWH）。

### Phase 8: 限速与 DoS
限速绕过（X-Forwarded-For）、路径变体、Slowloris、GraphQL 批查询 DoS、IP 轮换。

### Phase 9: 数据暴露
响应过度暴露、分页枚举、错误消息泄漏、GraphQL 嵌套越权、OpenAPI 暴露敏感端点。

### Phase 10: CI/CD 集成
spec 变更自动重跑、按严重度阈值阻断构建、发现持久化为回归测试。

## 二、工具链

| 工具 | 用途 |
|---|---|
| Vespasian | 流量→OpenAPI/GraphQL 规范 |
| Entropy | LLM 生成攻击场景 |
| jwt_tool | JWT 全面测试 |
| Burp Autorize | 双会话授权对比 |
| FireTail | GraphQL 专项测试 |
| ffuf / Kiterunner | 端点爆破 |

## 三、验证

- 每个漏洞给出可复现 PoC（请求/响应）
- 授权漏洞用双会话对比确认
- 限速绕过用多 IP 验证
