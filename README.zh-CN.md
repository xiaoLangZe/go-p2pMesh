# go-p2pmesh

[English](README.md) | [简体中文](README.zh-CN.md)

基于 Go 的 P2P 网状网络（mesh）库，构建为服务端与客户端两个二进制，共用同一个模块。

> 状态：仍在积极开发中，接口可能发生变化。

## 概述

- **服务端（Server）** —— 部署在拥有公网 IPv4 的机器上。负责信令、房间管理、
  节点发现与端口授权，并提供 REST API 供外部管理面板调用。**不转发业务数据**。
- **客户端（Client）** —— 部署在 NAT 之后的机器上。与其他节点建立 P2P 隧道、
  创建虚拟网卡，并执行端口访问规则。

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

配置可从 `configs/server.ini.example` 或 `configs/client.ini.example` 复制，
文件内的注释说明了全部选项。

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
