# Go Port Rocket

<p align="center">
  <img src="website/img/logo.png" alt="Go Port Rocket Logo" width="180">
  <br>
  <b>高性能端口扫描与网络服务分析工具</b>
</p>

Go Port Rocket 是一款强大的端口扫描工具，使用 Go 语言开发，为网络安全评估和故障排查提供全面支持。

## 官方网站

**📚 详细文档和使用说明请访问我们的官方网站：[https://cyberspacesec.github.io/go-port-rocket/](https://cyberspacesec.github.io/go-port-rocket/)**

## 核心功能

- 高性能 TCP/UDP 扫描
- 服务版本检测（内置指纹数据库）
- 操作系统识别
- HTML 报告生成与可视化
- HTTP API 和 MCP（多行命令处理）
- 协议数据解析

## 快速开始

### 安装

```bash
# 通过 Go
go install github.com/cyberspacesec/go-port-rocket@latest

# 或访问官网获取更多安装选项
```

### 基本使用

```bash
# TCP 扫描
go-port-rocket scan -t example.com -p 80,443

# 查看更多示例和高级功能，请访问官方网站
```

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。 