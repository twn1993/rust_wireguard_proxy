# ncservice — SOCKS5 Proxy over WireGuard

**ncservice** (也叫 **wg-proxy**) 是一个用 Rust 编写的网络工具，它将 SOCKS5 代理与 WireGuard 隧道结合，通过 WireGuard 加密隧道转发 SOCKS5 流量，支持 TCP CONNECT 和 UDP ASSOCIATE。

## 架构概览

```
  SOCKS5 客户端  <──>  ncservice (本地 SOCKS5)  <──>  WireGuard 隧道  <──>  目标服务器
                          │
                          └── DNS-over-HTTPS (通过隧道解析)
```

## 功能特性

- **SOCKS5 代理** — 支持 TCP CONNECT 和 UDP ASSOCIATE 命令
- **WireGuard 隧道** — 底层基于 `wireguard-netstack` 实现，在用户态运行 WireGuard 协议
- **DNS-over-HTTPS** — 通过隧道进行 DNS 解析，自动映射常见 DNS 服务器（Cloudflare、Google、Quad9、AdGuard、Mullvad）到对应的 DoH 端点
- **配置文件目录扫描** — `--config-dir` 模式可扫描目录下所有 `.conf` 配置文件，自动测试并交互式选择可用节点
- **双层配置** — CLI 参数 > TOML 配置文件 > 硬编码默认值，逐级覆盖
- **UDP 中继** — 支持 SOCKS5 UDP ASSOCIATE，含超时清理机制
- **Windows 资源嵌入** — 通过 `build.rs` + `resource.rc` 为 Windows 可执行文件嵌入版本信息，避免启发式检测
- **字符串混淆** — 对日志中的关键字符串做 XOR 混淆，避免静态扫描特征匹配

## 快速开始

### 编译

```bash
# 标准构建
cargo build --release

# 生成的二进制文件
./target/release/ncservice.exe  # Windows
```

> Windows 编译需要 MSVC 工具链。如果使用 `rustup`，`stable-msvc` 工具链会自动处理。

### 用法

```bash
# 使用单个 WireGuard 配置文件
ncservice -c wg.conf -p 1080

# 使用配置目录（自动扫描 + 交互选择）
ncservice --config-dir ./confs/ -p 1080

# 指定 TOML 配置文件和 WireGuard 配置
ncservice -f proxy.toml -c wg.conf

# 完整参数
ncservice --config wg.conf --socks5-port 2080 --bind-addr 0.0.0.0 --verbose
```

### 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--config` | `-c` | WireGuard .conf 配置文件路径 | — |
| `--config-dir` | `-d` | 扫描目录下的 .conf 文件并交互选择 | — |
| `--config-file` | `-f` | TOML 代理配置文件路径 | `wg-proxy.toml` |
| `--socks5-port` | `-p` | SOCKS5 监听端口 | `1080` |
| `--bind-addr` | `-b` | SOCKS5 监听地址 | `127.0.0.1` |
| `--verbose` | `-v` | 开启调试日志 | false |

## 配置文件

### 1. WireGuard 配置 (.conf)

标准 WireGuard 配置文件格式：

```ini
[Interface]
PrivateKey = <base64 private key>
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = <base64 public key>
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

### 2. 代理配置 (wg-proxy.toml)

首次运行时若不存在配置文件，会自动生成默认 `wg-proxy.toml`：

```toml
[general]
log_level = "info"

[dns]
servers = []

[socks5]
bind = "127.0.0.1"
port = 1080
timeout_secs = 30

[tunnel]
mtu = 1500
connect_timeout_secs = 12
http_test_timeout_secs = 10

[cache]
dns_ttl_secs = 300
```

## 项目结构

```
src/
├── main.rs           # 入口：CLI 参数解析、配置加载、事件循环
├── config.rs         # WireGuard .conf 文件解析 (serde_ini)
├── proxy_config.rs   # TOML 代理配置解析 + DoH 配置解析
├── tunnel.rs         # WireGuard 隧道管理器
├── socks5_handler.rs # SOCKS5 TCP CONNECT 处理
├── udp_relay.rs      # SOCKS5 UDP ASSOCIATE 中继
├── dns.rs            # 并行 DoH 域名解析
├── scanner.rs        # 配置目录扫描 + 交互式选择
└── util.rs           # 字符串 XOR 混淆工具
build.rs              # Windows 版本资源嵌入
resource.rc           # Windows 版本信息资源
```

## 依赖

- `wireguard-netstack` — 用户态 WireGuard 协议 + 网络栈
- `fast-socks5` — SOCKS5 协议支持
- `tokio` — 异步运行时
- `clap` — CLI 参数解析
- `serde` / `serde_ini` / `toml` — 配置解析

## 许可

MIT
