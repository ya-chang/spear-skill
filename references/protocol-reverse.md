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
