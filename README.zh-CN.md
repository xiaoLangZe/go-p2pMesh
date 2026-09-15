# go-p2pmesh

[English](README.md) | [简体中文](README.zh-CN.md)

基于 Go 的 P2P 网状网络（mesh）库，构建为服务端与客户端两个二进制，共用同一个模块。

> 状态：仍在积极开发中，接口可能发生变化。

## 概述

- **服务端（Server）**：部署在拥有公网 IPv4 的机器上。负责信令、房间管理、节点发现
  与端口授权，并提供 REST API 供外部管理面板调用。**不转发业务数据**。
- **客户端（Client）**：部署在 NAT 之后的机器上。与其他节点建立 P2P 隧道、创建虚拟
  网卡，并执行端口访问规则。

## 特性

- 控制面走 TCP + Noise（IK）握手；引导服务器只负责发现与打洞协调。
- 数据面走 UDP + KCP 可靠层，UDP 完全不可用时回退 TCP；可选 TURN 中继作为最后手段。
- NAT 穿越：优先 IPv6 直连，其次 UDP 打洞，并针对对称 NAT 做端口预测。
- 跨平台虚拟网卡（TUN），支持 Windows / Linux / macOS，统一使用同一个 IPv6 ULA 前缀。
- 房间隔离与按节点的端口访问控制。
- 可插拔存储后端，默认 SQLite。

## 构建

```bash
go build -o gop2pmesh-server ./cmd/server
go build -o gop2pmesh-client ./cmd/client
```

交叉编译无需 CGO：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gop2pmesh-server ./cmd/server
```

## 使用

```bash
# 使用默认配置启动服务端
gop2pmesh-server

# 指定配置文件
gop2pmesh-server -c /etc/gop2pmesh.ini

# 使用默认配置启动客户端
gop2pmesh-client

# 指定引导服务器
gop2pmesh-client -bootstrap 203.0.113.10:29683
```

两个二进制都支持 `-install` 安装为系统服务、`-uninstall` 卸载。

## 配置文件

两个二进制都通过 `-c` 指定 INI 配置文件，默认文件名分别为 `server.ini` 与
`client.ini`；文件不存在时使用内置默认值。`configs/` 目录下提供了带注释的模板。

### 服务端（`server.ini`）

`[server]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | `0.0.0.0` | 控制面监听地址。 |
| `port` | `29683` | 控制面端口，用于信令与节点发现。 |
| `mesh_peers` | 无 | 需要互相同步的其他引导服务器，逗号分隔。 |

`[api]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 是否启用 REST 管理 API。 |
| `host` | `0.0.0.0` | API 监听地址。 |
| `port` | `29684` | API 监听端口。 |
| `cert_file` | `server.crt` | 提供 HTTPS 所用的 TLS 证书。 |
| `key_file` | `server.key` | 该证书对应的 TLS 私钥。 |
| `client_ca_file` | `clients_ca.crt` | 用于校验客户端证书的 CA（mTLS）。 |
| `jwt_secret` | 自动生成 | JWT 签名密钥；留空时首次启动自动生成。 |
| `token_ttl_hours` | `24` | 签发的 API 令牌有效期。 |
| `admin_user` | `admin` | 初始管理员账号，首次启动时创建。 |
| `admin_password` | 自动生成 | 初始管理员密码；留空时随机生成。 |

`[database]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `type` | `sqlite` | 取值 `sqlite`、`mysql`、`postgresql`、`mongodb`。 |
| `dsn` | `data/gop2pmesh.db` | 对应驱动的连接字符串。 |
| `max_open_conns` | `50` | 连接池最大打开连接数。 |
| `max_idle_conns` | `10` | 连接池最大空闲连接数。 |

`[network]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `cidr` | `fd00:9bd8::/64` | 分配给节点的内部 IPv6 ULA 前缀。 |

`[security]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `root_key_file` | `root.key` | 签发节点证书的根密钥；首次启动自动生成。 |
| `trust_on_first_use` | `false` | 未经验证证书链时，是否在首次接触即信任该节点。 |
| `node_timeout` | `90s` | 节点多久无响应后被标记为离线。 |

`[log]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `level` | `info` | 取值 `debug`、`info`、`warn`、`error`。 |
| `file` | 空 | 日志文件路径；留空输出到标准输出。 |

### 客户端（`client.ini`）

`[client]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `bootstrap` | 无 | 引导服务器地址，逗号分隔；自动选择延迟最低的一个。 |
| `listen_port` | `0` | 本机作为子引导服务器供其他客户端连接的端口；`0` 表示关闭。 |
| `node_id` | 自动生成 | 节点标识；留空时首次启动生成并持久化。 |

`[room]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `auto_join` | 空 | 启动时自动加入的房间。 |
| `room_key` | 空 | 该房间的端到端加密密钥。 |

`[stun]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `servers` | 公共 STUN 列表 | 用于 NAT 探测的第三方 STUN 服务器。 |
| `timeout_ms` | `3000` | 单次 STUN 请求超时，单位毫秒。 |
| `predict_samples` | `8` | 用于 NAT 端口预测的采样次数。 |
| `ipv6` | `true` | 是否同时探测 IPv6 链路。 |

`[holepunch]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `predict_window` | `64` | 预测端口窗口大小。 |
| `predict_parallel` | `256` | 并行打洞尝试次数。 |
| `turn` | `false` | 是否启用 TURN 中继作为最后手段。 |
| `turn_addr` | 空 | TURN 服务器地址；启用 `turn` 时必填。 |

`[tunnel]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `mtu` | `1280` | 隧道接口的 MTU，不得小于 `576`。 |
| `kcp_window` | `256` | KCP 收发窗口大小。 |

`[network]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `cidr` | `fd00:9bd8::/64` | 内部 IPv6 ULA 前缀，必须与服务端一致。 |

`[portcontrol]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `default_policy` | `deny` | `deny` 拒绝所有未配置端口，`allow` 则全部放行。 |
| `db_file` | `portcontrol.db` | 保存端口规则的 SQLite 文件。 |

`[identity]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `key_file` | `identity.key` | 标识本节点的私钥；首次启动自动生成。 |

`[log]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `level` | `info` | 取值 `debug`、`info`、`warn`、`error`。 |
| `file` | 空 | 日志文件路径；留空输出到标准输出。 |

### 命令行覆盖

| 参数 | 适用 | 作用 |
| --- | --- | --- |
| `-c` | 两者 | 配置文件路径。 |
| `-install`、`-uninstall` | 两者 | 安装或卸载系统服务。 |
| `-host`、`-port` | 服务端 | 控制面监听地址。 |
| `-db.type`、`-db.dsn` | 服务端 | 存储后端与连接字符串。 |
| `-log.level` | 两者 | 日志级别。 |
| `-bootstrap` | 客户端 | 引导服务器地址，逗号分隔。 |
| `-listen` | 客户端 | 子引导服务器监听端口。 |
| `-room`、`-roomkey` | 客户端 | 启动时加入的房间及其密钥。 |

## 作为 Go 库使用

```go
import (
    "github.com/yourorg/go-p2pmesh/pkg/server"
    "github.com/yourorg/go-p2pmesh/pkg/client"
)

srv, _ := server.New(server.WithHost("0.0.0.0"), server.WithPort(29683))
go srv.Start()
defer srv.Stop()
```

## 许可证

MIT，详见 [LICENSE](LICENSE)。
