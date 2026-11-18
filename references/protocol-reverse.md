# 协议逆向（protocol-reverse）

目标：对网络协议、自定义通信格式做抓包、结构分析、序列化格式还原、重放与文档化。**从流量入手，识别格式，还原结构，能复现。**

## 一、流量捕获

| 协议 | 工具 | 方法 |
|---|---|---|
| HTTP/HTTPS | mitmproxy / Burp Suite | 代理拦截 + SSL 绕过 |
| WebSocket | DevTools / mitmproxy | WS 面板 / addon 脚本 |
| TCP/UDP | Wireshark / tcpdump | 抓包过滤器 |
| BLE | nRF Sniffer + Wireshark | GATT 服务分析 |
| USB | USBPcap + Wireshark | 设备通信分析 |

**mitmproxy 脚本骨架：**
```python
from mitmproxy import http, ctx
class LogAddon:
    def request(self, flow: http.HTTPFlow):
        ctx.log.info(f"[REQ] {flow.request.method} {flow.request.url}")
    def response(self, flow: http.HTTPFlow):
        ctx.log.info(f"[RSP] {flow.response.status_code}")
```

## 二、协议结构分析

**识别模式：**
```
┌──────────┬──────────┬──────────────────────┐
│  Header  │  Length  │     Payload          │
│ (固定)    │ (变长)    │  (Length 指定)        │
└──────────┴──────────┴──────────────────────┘
```
- 长度字段：固定长度 / TLV / 分隔符 / 长度前缀
- 字节序：大端（网络标准）/ 小端（x86）

**Python struct 解析：**
```python
import struct
msg_type, msg_len = struct.unpack('>HH', data[:4])  # 大端 2x16位
payload = data[4:4+msg_len]
```

**识别加密：** 用熵分析检测，检查是否有长度字段编码。发送已知值（如 0x12345678）观察字节排列判断字节序。

## 三、序列化格式逆向

| 格式 | 识别特征 | 解码工具 |
|---|---|---|
| Protobuf | `0x0a` 开头，varint 编码 | `protoc --decode_raw` / blackboxprotobuf |
| MessagePack | `0xc0-0xdf` 前缀 | msgpack Python 库 |
| Thrift | `0x80` 开头 | Thrift IDL |
| CBOR | major type 前 3 bit | cbor2 Python 库 |

**Protobuf 逆向（无需 .proto）：**
```python
import blackboxprotobuf
data = open('sample.bin', 'rb').read()
message, typedef = blackboxprotobuf.decode_message(data)
```

**gRPC 反射：**
```bash
grpcurl -plaintext localhost:50051 list              # 列出服务
grpcurl -plaintext localhost:50051 describe pkg.Svc  # 描述服务
```

## 四、协议重放

```python
from scapy.all import *
pkt = IP(dst="10.0.0.1") / TCP(dport=8080) / Raw(load=b"\x01\x00\x05hello")
resp = sr1(pkt)
```

## 五、协议文档化

**字段表模板：**
```markdown
| 偏移 | 长度 | 类型 | 字段名 | 说明 |
|------|------|------|--------|------|
| 0x00 | 2 | uint16 BE | msg_type | 消息类型 |
| 0x02 | 2 | uint16 BE | msg_len | 数据长度 |
```

**端点文档模板：**
```markdown
### POST /api/v1/login
- 用途：用户登录
- 参数：{ username: string, password: string }
- 认证：无
- 响应：{ code: 0, data: { token: string, expires_in: int } }
```

## 六、Python 复现客户端骨架

```python
import requests

class ProtocolClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 ...',
            'Accept': 'application/json',
        })

    def login(self, username, password):
        resp = self.session.post(f'{self.base_url}/api/login', json={
            'username': username, 'password': password,
        })
        data = resp.json()
        if data.get('code') == 0:
            self.session.headers['Authorization'] = f"Bearer {data['data']['token']}"
        return data

    def get_data(self, page=1, size=20):
        return self.session.get(f'{self.base_url}/api/data',
            params={'page': page, 'size': size}).json()
```

## 七、常见错误

| 错误 | 正确做法 |
|---|---|
| 假设明文传输 | 用熵分析检测加密，检查长度字段编码 |
| 忽略字节序 | 发送已知值观察字节排列 |
| 混淆序列化格式 | protobuf 开头 0x0a，msgpack 前缀 0xc0-0xdf |
| 忽略压缩 | 有些协议先压缩后加密，解密后还需 zlib/gzip 解压 |

## 八、工具速查

| 工具 | 用途 |
|---|---|
| Wireshark | 全协议抓包分析 |
| mitmproxy | HTTP(S) 代理 + 脚本 |
| tcpdump | 命令行抓包 |
| Scapy | 包构造/重放/Fuzzing |
| blackboxprotobuf | Protobuf 无 proto 解码 |
| grpcurl | gRPC 反射探测 |
| protoc | Protobuf 编解码 |

## 九、验证

- [ ] 协议结构文档与实际抓包一致（字段名/类型/顺序与 HAR/PCAP 实际数据匹配）
- [ ] 序列化格式解码正确，字段可读（JSON/Protobuf/TLV 解码后字段语义清晰，无乱码）
- [ ] 重放脚本能复现原始请求并得到预期响应（Python 脚本发送请求，响应与原抓包一致）
- [ ] Python 客户端能独立完成完整业务流程（登录→请求→响应全链路跑通，不依赖原环境）
- [ ] 加密参数可独立复现（签名/加密值本地生成，与运行时一致）

## 九·五、代码骨架：协议重放 Python 脚本

> 可运行的协议重放骨架，从抓包数据构造请求并重放。关键字段按样本替换。

```python
# protocol_replay.py — 协议重放骨架（Python + requests）
# 从抓包（HAR/PCAP）提取请求，本地重放，验证响应一致性

import requests
import json

# 占位：目标端点与抓包提取的请求参数
TARGET_URL = "[TARGET_URL]"
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "[UA]",
    "Cookie": "[COOKIE]",
}

def build_request(params):
    """构造重放请求（按逆向的序列化格式）"""
    # 占位：按样本的序列化格式构造 body
    # JSON 示例：
    body = json.dumps(params)
    return {
        "url": TARGET_URL,
        "headers": HEADERS,
        "data": body,
    }

def replay_and_verify(original_response):
    """重放请求并验证响应一致性"""
    # 占位：从抓包提取的原始参数
    params = {"field1": "[VAL1]", "field2": "[VAL2]"}

    req = build_request(params)
    resp = requests.post(**req, timeout=10)

    # 验证：响应状态码与原始一致
    assert resp.status_code == original_response["status"], \
        f"status mismatch: {resp.status_code} != {original_response['status']}"

    # 验证：响应体关键字段一致
    resp_json = resp.json()
    for key, expected in original_response["fields"].items():
        assert resp_json.get(key) == expected, \
            f"field mismatch: {key} = {resp_json.get(key)} != {expected}"

    print(f"[replay] OK: status={resp.status_code}, fields match")
    return resp

if __name__ == "__main__":
    # 占位：原始抓包响应
    original = {"status": 200, "fields": {"code": 0, "msg": "ok"}}
    replay_and_verify(original)
```

运行：`pip install requests && python3 protocol_replay.py`。验证：重放响应与原始抓包一致，断言全过。

> 更新：2026-11-17 · 来源：骨架为通用模板，配合 §五 重放验证使用

## 十、RPC 协议逆向（补充）

### gRPC
```bash
# gRPC over HTTP/2
# 识别：HTTP/2 帧，Content-Type: application/grpc
# 帧格式：[1B compressed][4B length][NB message]

# 反射
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe package.Service

# 无需反射时：抓包分析 protobuf 编码的请求/响应
```

### JSON-RPC 2.0
```json
// 请求
{"jsonrpc":"2.0","method":"getUser","params":{"id":1},"id":1}
// 响应
{"jsonrpc":"2.0","result":{"name":"test"},"id":1}
// 特征：固定 jsonrpc 字段，method/params/id 结构
```

### IPC 机制
```bash
# Named Pipes (Windows)
# 特征：\\.\pipe\pipename
# 工具：Pipe Monitor, Process Monitor

# Unix Domain Sockets (Linux)
# 特征：/tmp/.X11-unix/X0 等 socket 文件
strace -e trace=connect -f target_program

# D-Bus (Linux)
dbus-monitor --session   # 监控会话总线
dbus-monitor --system    # 监控系统总线
busctl list              # 列出总线连接
```

## 十一、蓝牙与 IoT 协议

### BLE 分析
```bash
# nRF Connect（手机 App）扫描 BLE 设备
# Wireshark 导入 BLE 抓包
# 关键：GATT Service UUID → Characteristic UUID → Read/Write/Notify

# BLE 特征码
# Service: 0x1800 (Generic Access), 0x1801 (Generic Attribute)
# 常见：0x180A (Device Information), 0x180F (Battery)
```

### MQTT
```bash
# 订阅所有主题
mosquitto_sub -h broker.example.com -t '#' -v

# 发布消息
mosquitto_pub -h broker.example.com -t 'test/topic' -m 'hello'

# 抓包分析：Wireshark MQTT dissector
# 关键：CONNECT/SUBSCRIBE/PUBLISH 包，topic，payload
```

### Modbus
```bash
# 功能码：01=读线圈，02=读离散输入，03=读保持寄存器，04=读输入寄存器
# 05=写单个线圈，06=写单个寄存器

# Wireshark 过滤
modbus && ip.addr == 192.168.1.100

# Python Modbus 客户端
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('192.168.1.100', port=502)
result = client.read_holding_registers(0, 10, slave=1)
print(result.registers)
```

## 十二、Wireshark 过滤器速查

```bash
# 基础过滤
ip.addr == 192.168.1.100
tcp.port == 8080
http.request.method == "POST"

# 协议过滤
http
tls
modbus
mqtt
dbus
bluetooth

# 组合过滤
modbus && ip.addr == 192.168.1.100
http && tcp.port == 8080
```

**跟踪 TCP/HTTP 流：** 右键 → Follow → TCP Stream
**导出 HTTP 对象：** File → Export Objects → HTTP
**会话统计：** Statistics → Conversations
**协议分层：** Statistics → Protocol Hierarchy

## 十三、字节序判断

```python
# 方法：发送已知值，观察字节排列
# 值 0x12345678
# 大端：12 34 56 78
# 小端：78 56 34 12
# 通常：网络协议用大端，x86 本地程序用小端

import struct
# 大端序解析
struct.unpack('>I', data[:4])
# 小端序
struct.unpack('<I', data[:4])
# 常见格式：>I (大端32位), <H (小端16位), >Q (大端64位)
```

---

## 十二、私有协议帧推演（VPN/私有 TCP/WSS 实战）

### 一、第一步：确认"它到底是不是 HTTP"

很多私有协议跑在 443 或 80 上，但和 HTTP 毫无关系。**判定实验**：抓首个出站包，看前 4~8 字节。

| 前几字节 | 判断 |
|---|---|
| `GET ` / `POST` / `HTTP/1.` | 是 HTTP |
| `16 03 01` / `17 03 03` | TLS 记录层（里面可能是私有协议） |
| `F0 F0 F0 F0` | **不是 HTTP**（真实案例：登录响应魔数，UserID 在偏移 +44） |
| `C1 92 A4 D6` / `FE FC EF BE` | 私有协议，不同魔数往往代表**不同代际** |

> 真实教训：先假定"登录是 HTTP 请求"，绕了很久才发现响应根本不是 HTTP，而是自定义帧。

### 二、魔数即代际：先找"官方/开源实现"

不同魔数很可能对应不同协议版本。这一步的价值：

1. **一个魔数往往能在网上搜到协议名** → 直接拿到开源实现或文档。
2. 新旧两版并存时，老版实现通常**更简单且字段更全**，先跑通老版再升级。
3. 官方客户端在别的平台（Linux/macOS/ARM）的同名二进制，**协议字段是一致的** → 交叉验证的最佳对照物。

**如果已有开源实现**：不要重写，先跑通它，再逐字节比对差异。比从零推字段快一个数量级。

### 三、帧格式的推演顺序

```
1. 长度字段：找"值 = 剩余字节数"或"值 = 总长"的字段
   - 验证：改一个字节，看解析是否报"长度不符"
2. 类型字段：小的枚举值（0x01/0x02/0x10...），改它看服务端反应
3. 序列号/会话号：单调递增的 2/4 字节
4. 负载：剩余部分（可能压缩/加密）
5. 校验：末尾 2/4 字节，改一位看是否被拒
```

**错误文本是最便宜的结构文档**：喂畸形帧，读返回的错误码/文案。`invalid length`、`bad magic`、`unknown type` 直接告诉你字段在哪。

### 四、会让人卡很久的真实坑

**首包必须带身份**：TCP 连上后第一帧不带 UserID → 服务端直接 `KICKOUT`。表现：连接成功、发什么都断、抓包看不出原因。排查：对比官方客户端首帧与你首帧的**逐字节差异**（不是"看起来差不多"）。

**纯 ACK 包被中间设备丢弃**：协议第 N 帧是 40 字节纯 ACK（无负载），网关当成"异常小包"吞掉 → 客户端永远等不到确认 → 卡死。**解法**：补 4 字节 TCP NOP 选项，把包撑到 44 字节。判据：**长度是整十/整百附近且无负载的帧，最容易被中间设备特殊处理。**

**MSS / 分片**：私有协议常把 MSS 设成非标准值（如 1200）控制单帧边界；自己实现不设置默认 1460，会出现"官方能跑我不能"。分片重组要按**协议层长度字段**，不要按 TCP 段边界。

**顺序与并发**：有"必须成对"的帧（请求/响应、开始/结束），有"可以乱序"的帧（心跳、事件通知）。画状态机时把两类分开标，否则实现出来偶发死锁。

### 五、WebSocket 私有协议

| 要点 | 说明 |
|---|---|
| **必须回 PONG** | 不回 → 几秒后静默断开，容易被误判成网络问题 |
| **permessage-deflate** | 解压后原始 deflate 流尾部是 `00 00 FF FF`；拼接/裁剪时不能丢也不能留 |
| **opcode 分流** | 二进制帧 vs 文本帧；混淆实现常把二进制塞进文本（base62/latin1） |
| **心跳间隔** | 必须复刻，太快被判机器，太慢被踢 |
| **子协议协商** | `Sec-WebSocket-Protocol` 不对会被拒 |
| **掩码** | 客户端发出的帧必须掩码，服务端不掩码；自己实现时容易漏 |

**重建步骤**：1) DevTools → Network → WS → Messages，**导出全量帧**（含时间戳与方向）；2) 按 opcode 分类，逐帧标注：握手/心跳/业务/ACK；3) 画状态机；4) Node `ws` 起步：**先只发心跳**，能活 5 分钟再发业务帧。

### 六、加密与压缩层

| 层 | 特征 | 处理 |
|---|---|---|
| TLS | 标准握手 | 有客户端证书就导出；否则走"接管出口"（hook 明文处） |
| 应用层对称加密 | 帧头后有 IV/长度 | 找 key（常是 MD5(设备号)[:16] 之类） |
| 应用层压缩 | 高熵但可解 | 试 zlib/gzip/zstd（魔数 `78 9C` / `1F 8B` / `28 B5 2F FD`） |
| **自研容器** | 有 magic + 分段 | 见 `game-cheat.md` 引擎资源容器分析法 |

**握手阶段的密钥交换**是最值得花时间的地方：抓到"客户端生成 → 服务端确认"的那一对值，往往就是会话密钥的来源。

### 七、交叉验证（提高结论可信度）

| 手段 | 做法 |
|---|---|
| **跨平台同名二进制** | 官方 Linux 版/ARM 版解析同一字段，逻辑一致 → 字段语义确认 |
| **开源实现对照** | 逐字节 diff 自己发的帧与开源实现发的帧 |
| **双向对照** | 既解服务端响应，也构造客户端请求，两侧都能被对方接受 |
| **旧版本客户端** | 老版协议通常更简单，字段更全，便于反推 |
| **重放验证** | 把抓到的帧原样重放，能复现结果 → 说明帧完整 |

### 验证

- [ ] 已确认协议**不是 HTTP**（首包魔数判定），魔数代际已分辨
- [ ] 帧结构按"长度→类型→序号→负载→校验"顺序推演，每步有改字节实验证据
- [ ] 首包带身份、纯 ACK 补 NOP、MSS 按协议值设置，与官方客户端首帧逐字节 diff
- [ ] WSS 必回 PONG、deflate 尾巴 `00 00 FF FF` 保留、心跳间隔复刻
- [ ] 连续 100~200 次连接成功率 > 98%，长跑 >30 分钟不掉线，断线重连可恢复，跨网络环境（NAT/高延迟）成立

> 更新：2026-11-18 · 来源：看雪帖 2138362（52pojie.cn 逆向技能包）
