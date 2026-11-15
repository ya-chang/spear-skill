# 供应链安全测试（supply-chain-security）

目标：软件供应链安全评估——SBOM / SCA / CI/CD 管道 / 依赖溯源 / 容器镜像 / 构建完整性。**先建档，再分层治理，SCA 告警必须做可达性验证。**

## 一、适用场景

- 软件供应链安全评估
- 开源依赖漏洞扫描与验证
- CI/CD 管道安全审计
- 容器镜像安全分析
- 第三方组件合规审查
- 构建产物溯源与完整性验证

## 二、六层供应链治理框架

```text
Layer 1: 源码信任评估 → 上游仓库/维护者/发布历史审查
Layer 2: 构建管道集成 → CI/CD 安全门禁、签名验证
Layer 3: 制品分发完整性 → 签名、校验和、SBOM 附加
Layer 4: 运行时保护 → 容器扫描、准入控制
Layer 5: 持续监控 → CVE 实时追踪、漏洞可达性分析
Layer 6: 事件响应 → 供应链攻击应急、回滚策略
```

## 三、工作流

### 1. SBOM 生成与审计

```text
生成 SBOM：
□ CycloneDX 格式: cdxgen → bom.json
□ SPDX 格式: sbom-tool generate
□ Syft: syft <image|dir> -o spdx-json

审计要点：
□ 是否存在未知/未授权的依赖
□ 是否存在已废弃/停止维护的包
□ 许可证冲突检测
□ 直接依赖 vs 传递依赖清单
□ 每个组件的发布时间线和维护者状态
```

### 2. 软件组成分析（SCA）

```bash
# OSV-Scanner（免费、Google 维护）
osv-scanner scan -r . --format json

# OWASP Dependency-Track（企业级持续监控）
docker run -p 8080:8080 dependencytrack/apiserver
# → 上传 SBOM → 自动匹配 NVD/OSV/GitHub Advisory

# Snyk（商业）
snyk test --all-projects
snyk monitor  # 持续监控

# Trivy（容器 + 依赖 + IaC）
trivy fs .          # 文件系统扫描
trivy image nginx   # 容器镜像
trivy config .      # IaC 配置
```

### 3. 漏洞可达性验证

```text
SCA 告警 ≠ 实际风险！大多数 SCA 工具只有 ~15% 的告警是实际可达的。

验证步骤：
1. 用 Dependency-Track 或 Trivy 获取 CVE 列表
2. 筛选 CVSS ≥ 7.0 的漏洞
3. 对有 PoC 的 CVE 做可达性分析
   - Code Property Graph 切片: 追踪用户输入到漏洞函数的路径
   - DEPTEX 方法: EPD (Execution Path Dominance) + LLM 语义验证
4. 在隔离环境中验证 PoC
5. 对可达的漏洞按实际影响排序修复优先级
```

工具参考：
- CodeQL: GitHub 代码查询 → 数据流分析
- Snyk Code: 可达性标记
- DEPTEX: LLM 辅助上下文感知风险评估

### 4. CI/CD 管道安全

```text
安全检查点：
□ 代码提交 → pre-commit hook: gitleaks (密钥扫描)
□ PR 阶段 → SCA 扫描 (Trivy/OSV-Scanner)
□ 构建阶段 → 制品签名 (cosign)
□ 推送阶段 → SBOM 附加 (syft + attest)
□ 部署阶段 → 准入控制 (OPA/Kyverno + 镜像扫描)
□ 运行时 → 持续漏洞监控 (Dependency-Track)

管道自身安全：
□ Pipeline as Code 审计（GitHub Actions / GitLab CI 配置注入）
□ Runner 隔离（防止恶意构建突破容器）
□ 密钥管理（Actions Secrets / Vault，禁止硬编码）
□ 第三方 Action 审查（锁定 commit SHA，非 tag）
```

### 5. 容器镜像安全

```bash
# Dockerfile 审计
hadolint Dockerfile

# 镜像扫描（多层：OS + 应用依赖 + 配置）
trivy image --severity HIGH,CRITICAL nginx:latest

# 最小基础镜像
# 优先: distroless → alpine → slim → 避免 latest
docker scout quickview nginx:latest

# 镜像签名
cosign sign --key cosign.key myimage:tag
cosign verify --key cosign.pub myimage:tag
```

### 6. 第三方依赖审查

```text
新增依赖 Checklist：
□ 维护状态：最近 6 个月有提交？维护者活跃度？
□ 安全历史：过去有无被植入恶意代码？
□ 依赖树：引入后新增多少传递依赖？
□ 许可证：与项目许可证兼容？
□ 替代方案：有无更安全的替代（Snyk Advisor / Socket.dev 评分）？

风险评估矩阵：
  高维护 × 低依赖数 × 兼容许可证 → 低风险
  低维护 × 高依赖数 × 许可证冲突 → 高风险
```

## 四、SBOM 标准对比

| 标准 | 格式 | 生态 | 推荐场景 |
|------|------|------|---------|
| SPDX | JSON/YAML/tag-value | Linux Foundation、Yocto | 许可证合规优先 |
| CycloneDX | JSON/XML | OWASP、Kubernetes | 安全分析优先 |
| SWID | XML | ISO 标准 | 企业资产管理 |

## 五、SBOM 生成工具链

```bash
# cdxgen: 从源码生成 CycloneDX SBOM
cdxgen -o bom.json -t cyclonedx

# Syft: 从容器/文件系统生成
syft nginx:latest -o spdx-json > sbom.spdx.json

# SBOM-Tool: 微软工具链
sbom-tool generate -b ./build -bc ./src -pn MyApp -pv 1.0
```

## 六、SCA 工具对比

| 工具 | 免费 | 速度 | 数据库 | 可达性 |
|------|:--:|------|--------|:--:|
| OSV-Scanner | ✅ | 极快 | OSV.dev | ❌ |
| Trivy | ✅ | 快 | 多源 | ❌ |
| Dependency-Track | ✅ | 中 | NVD+OSV+GitHub | ❌ (需插件) |
| Snyk | ❌ | 中 | 专有 | ✅ |
| CodeQL | ✅ | 慢 | 代码级 | ✅ |

## 七、漏洞优先级策略

```text
CVSS ≥ 9.0 + 有公开 PoC + 可达 → P0 立即修复
CVSS ≥ 7.0 + 有 PoC + 可达 → P1 本周修复
CVSS ≥ 7.0 + 无 PoC 或不可达 → P2 下个迭代修复
其余 → 按常规流程
```

## 八、手工验证三步法

```bash
# 1. 确认版本（不要盲信 SBOM 字段）
# 容器内: dpkg -l | grep <package>
# Node: cat node_modules/<pkg>/package.json | jq .version
# Python: pip show <package>

# 2. 确认漏洞
# 搜索 CVE: https://osv.dev / https://nvd.nist.gov
# 查看受影响版本范围
# 找到 GitHub Advisory / oss-security 邮件列表

# 3. 验证影响
# 搜索公开 PoC: GitHub/Exploit-DB
# 分析利用条件: 是否需要认证/本地访问/特定配置
# 在隔离环境验证: docker run --rm -it vulnerable-image bash
```

## 九、CI/CD 管道安全审计

### 管道攻击面（STRIDE）
```text
□ 欺骗: 伪造构建/签名/来源
□ 篡改: 修改源代码/构建产物/依赖
□ 否认: 无审计日志的恶意操作
□ 信息泄露: 管道日志/构建产物泄漏密钥
□ 拒绝服务: 耗尽 CI 资源/破坏构建
□ 权限提升: Runner 逃逸/密钥窃取
```

### 1. Pipeline as Code 配置

```yaml
# GitHub Actions 审计要点
# ❌ 危险模式
on:
  pull_request_target:  # 可访问 secrets 的 PR 触发
    types: [opened]

# ❌ 脚本注入
- run: echo "${{ github.event.issue.title }}"  # 用户输入 → shell

# ❌ 不受限的 token 权限
permissions: write-all

# ✅ 安全模式
on:
  pull_request:  # 无 secrets 访问
    types: [opened]

# ✅ 固定到 SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

# ✅ 最小权限
permissions:
  contents: read
```

### 2. 密钥管理

```bash
# 扫描历史提交中的密钥
gitleaks detect --source . --verbose
trufflehog git file://. --only-verified

# 检查 Actions Secrets 使用
gh secret list
# 确认: 无硬编码密钥、定期轮换、最小权限

# 运行时密钥注入
# ✅ 使用 OIDC 替代长期密钥
# ✅ Secrets 仅在需要时暴露到特定步骤
```

### 3. 构建完整性

```bash
# 构建溯源
# 生成不可篡改的构建记录（SLSA L2+）
slsa-provenance generate --source . --output provenance.json

# 产物签名
cosign sign-blob --key cosign.key artifact.tar.gz

# 验证
cosign verify-blob --key cosign.pub --signature artifact.tar.gz.sig artifact.tar.gz
```

### 4. Runner 安全

```text
□ 是否使用 GitHub-hosted runner？（推荐，每次全新环境）
□ Self-hosted runner: 是否在隔离的 VM/容器中运行？
□ 是否运行过 fork PR？（self-hosted runner 风险极高）
□ Runner 是否有网络出站限制？
□ 构建缓存是否可能跨构建泄漏？
```

### 5. 依赖拉取安全

```text
□ npm: package-lock.json 是否提交？ 禁止 --force / --legacy-peer-deps
□ pip: requirements.txt 是否冻结版本？ 禁止 pip install <未验证来源>
□ Docker: FROM 是否固定 digest？ 禁止 latest tag
□ Go: go.sum 是否提交？
□ 私有包: 注册表认证是否用短期 token？
```

## 十、自动化检查 Pipeline

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SBOM Generate
        run: |
          npm install -g @cyclonedx/cdxgen
          cdxgen -o sbom.json

      - name: OSV Scan
        run: |
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest
          osv-scanner scan --sbom sbom.json --format sarif > osv-results.sarif

      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Secret Scan
        run: |
          docker run --rm -v $PWD:/src ghcr.io/gitleaks/gitleaks:latest \
            detect --source /src --verbose

      - name: Dependency-Track Upload
        run: |
          curl -X POST https://dtrack.example.com/api/v1/bom \
            -H "X-Api-Key: ${{ secrets.DTRACK_API_KEY }}" \
            -F "autoCreate=true" -F "project=myapp" -F "bom=@sbom.json"
```

## 十一、工具链

| 工具 | 用途 | 获取 |
|------|------|------|
| OWASP Dependency-Track | 企业级持续 SCA | `docker pull dependencytrack/apiserver` |
| OSV-Scanner | 免费 SCA（OSV.dev 生态） | `go install github.com/google/osv-scanner` |
| Trivy | 镜像 + 依赖 + IaC 扫描 | `apt install trivy` |
| Syft | SBOM 生成 | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh` |
| cdxgen | CycloneDX SBOM 生成 | `npm install -g @cyclonedx/cdxgen` |
| Cosign | 容器签名 | `go install github.com/sigstore/cosign/v2/cmd/cosign` |
| Gitleaks | 密钥/凭证扫描 | `go install github.com/gitleaks/gitleaks/v8` |
| Snyk | 商业 SCA + 可达性 | `npm install -g snyk` |
| CodeQL | 代码查询 + 数据流 | GitHub Actions 内置 |

## 十二、持续监控

```yaml
# 每日 SBOM 更新 + 扫描
schedule:
  - cron: "0 6 * * *"  # 每天早上 6 点
    steps:
      - cdxgen -o bom.json
      - osv-scanner scan --sbom bom.json
      - trivy fs --exit-code 1 --severity CRITICAL .
```

## 十三、验证

- SBOM 完整覆盖直接依赖与传递依赖，无未知组件
- SCA 告警经可达性验证后按优先级排序，无"告警即修复"的误判
- CI/CD 管道无硬编码密钥、Action 锁定 SHA、Runner 隔离
- 容器镜像扫描无 HIGH/CRITICAL 未修复项，基础镜像最小化
- 供应链攻击应急与回滚策略已文档化并验证

来源：OWASP CycloneDX、SPDX、Google OSV、CISA SBOM Guidance、SLSA Framework、OWASP CI/CD Top 10
