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

- 协议结构文档与实际抓包一致
- 序列化格式解码正确，字段可读
- 重放脚本能复现原始请求并得到预期响应
- Python 客户端能独立完成完整业务流程
