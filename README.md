# Go Port Rocket

Go Port Rocket 是一个功能强大的端口扫描工具，支持 TCP/UDP 扫描、服务识别、操作系统检测等功能。它提供命令行界面和 HTTP API 两种使用方式。

<p align="center">
  🚀<br>
  <b>Go Port Rocket</b>
</p>

## 官方网站和文档

我们提供了完整的文档和指南，包括安装方法、使用示例、API 参考等。请访问我们的官方网站：

**[https://go-port-rocket.cyberspacesec.com](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/index.html)**

## 快速导航

- [安装指南](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/installation.html)
  - [Windows 安装](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/windows-install.html)
  - [Linux 安装](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/linux-install.html)
  - [macOS 安装](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/macos-install.html)
- [CLI 文档](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/cli.html)
- [HTTP API 文档](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/http-api.html)
- [Golang API 文档](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/golang-api.html)
- [MCP 文档](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/docs/mcp.html)

## 功能特点

- 支持 TCP 和 UDP 端口扫描
- 服务版本检测（内置指纹数据库，无需安装Nmap）
- 操作系统识别（内置指纹数据库，无需安装Nmap）
- 多种输出格式 (文本、JSON、XML、HTML)
- HTML报告生成与过滤功能
- HTTP API 支持
- 任务队列和并发控制
- JWT 认证
- Redis 持久化
- 多行命令处理 (MCP) 支持，方便 AI 系统调用

## 演示

访问 [演示页面](https://github.com/cyberspacesec/go-port-rocket/blob/main/website/demo-report.html) 查看扫描报告示例。

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

## 指纹识别功能

Go Port Rocket 内置了简化版的 Nmap 指纹数据库，可以直接进行服务和操作系统识别，而无需安装 Nmap。内置的指纹数据包括：

- 常见操作系统指纹数据（Windows、Linux、macOS、BSD等）
- 常见服务探测规则（HTTP、SSH、FTP、SMTP等）
- 端口服务映射数据

这些内置数据可以满足大多数扫描场景的需求，识别常见的操作系统和服务。如果您有特殊需求，也可以通过自定义指纹数据来增强识别能力。

## 安装

### 通过 Homebrew 安装 (推荐，macOS)

```bash
# 添加 tap（首次使用）
brew tap cyberspacesec/go-port-rocket

# 安装工具
brew install go-port-rocket
```

### Linux 安装

Linux 用户可以通过多种方式安装 Go Port Rocket，包括：

- 通过 Linuxbrew (Homebrew 的 Linux 版本)
- 通过 DEB 包 (Debian/Ubuntu)
- 通过 RPM 包 (RedHat/Fedora/CentOS)
- 从源码编译

详细的 Linux 安装指南请查看 [LINUX_INSTALL.md](LINUX_INSTALL.md)

### Windows 安装

Windows 用户可以通过多种方式安装 Go Port Rocket，包括：

- 通过 Scoop 安装：
  ```powershell
  # 添加仓库
  scoop bucket add go-port-rocket https://github.com/cyberspacesec/go-port-rocket
  
  # 安装
  scoop install go-port-rocket
  ```

- 通过 Chocolatey 安装：
  ```powershell
  # 添加仓库
  choco source add -n=go-port-rocket -s="https://github.com/cyberspacesec/go-port-rocket/releases/latest/download/" -p=1
  
  # 安装
  choco install go-port-rocket
  ```

- 使用 MSI 安装程序（图形界面安装）
- 使用便携版（无需安装）

详细的 Windows 安装指南请查看 [WINDOWS_INSTALL.md](WINDOWS_INSTALL.md)

### 通过 Go 安装

```bash
go install github.com/cyberspacesec/go-port-rocket@latest
```

### 从源码编译

```bash
git clone https://github.com/cyberspacesec/go-port-rocket.git
cd go-port-rocket
go build -o go-port-rocket
```

> 注意：由于使用了 libpcap 库，从源码编译时需要先安装 libpcap 开发包：
> - macOS: `brew install libpcap`
> - Ubuntu/Debian: `sudo apt install libpcap-dev`
> - CentOS/RHEL: `sudo yum install libpcap-devel`

## 命令行使用

### 基本扫描

```bash
# TCP 扫描
go-port-rocket scan -t 192.168.1.1 -p 80,443 -s tcp

# UDP 扫描
go-port-rocket scan -t 192.168.1.1 -p 53 -s udp

# 端口范围扫描
go-port-rocket scan -t 192.168.1.1 -p 1-1024 -s tcp

# 指定输出格式
go-port-rocket scan -t 192.168.1.1 -p 80,443 -s tcp -f json -o result.json --pretty
```

### 高级选项

```bash
# 启用服务检测
go-port-rocket scan -t 192.168.1.1 -p 80,443 -s tcp --service-detection

# 启用操作系统检测
go-port-rocket scan -t 192.168.1.1 -p 80,443 -s tcp -O

# 完整扫描
go-port-rocket scan -t 192.168.1.1 -p 1-1024 -s tcp -O --service-detection --version-intensity 9
```

### 多行命令处理 (MCP)

多行命令处理功能允许通过 JSON 配置文件或输入流提供复杂的扫描参数，非常适合 AI 系统调用。

```bash
# 使用配置文件
go-port-rocket mcpscan -i scan_config.json

# 使用命令行提供配置数据
go-port-rocket mcpscan -c '{"target":"192.168.1.1","ports":"80,443","scan_type":"tcp","os_detection":true}'

# 通过标准输入提供配置
echo '{"target":"192.168.1.1","ports":"80,443","scan_type":"tcp"}' | go-port-rocket mcpscan

# MCP API 服务启动
go-port-rocket mcpapi -i api_config.json
```

#### MCP 扫描配置示例

```json
{
  "target": "192.168.1.1",
  "ports": "80,443",
  "scan_type": "tcp",
  "timeout": "5s",
  "workers": 100,
  "format": "json",
  "output": "result.json",
  "pretty": true,
  "os_detection": true,
  "service_detection": true,
  "version_intensity": 9,
  "guess_os": true,
  "limit_os": false
}
```

#### MCP API 配置示例

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "jwt_secret": "your-jwt-secret",
  "redis_addr": "localhost:6379",
  "redis_password": "",
  "redis_db": 0,
  "max_workers": 10,
  "queue_size": 100,
  "enable_auth": true
}
```

## HTTP API 服务

### 启动服务

```bash
# 基本启动
go-port-rocket api --port 8080

# 启用认证
go-port-rocket api --port 8080 --enable-auth --jwt-secret your-secret-key

# 配置 Redis
go-port-rocket api --port 8080 --redis-addr localhost:6379 --redis-pass your-password

# 完整配置
go-port-rocket api \
  --port 8080 \
  --enable-auth \
  --jwt-secret your-secret-key \
  --redis-addr localhost:6379 \
  --redis-pass your-password \
  --redis-db 0 \
  --max-workers 10 \
  --queue-size 100
```

### API 端点

#### 认证

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

#### 创建扫描任务

```http
POST /api/v1/scan
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "192.168.1.1",
  "ports": "80,443",
  "scan_type": "tcp",
  "timeout": "5s",
  "workers": 100,
  "output_format": "json",
  "pretty_output": true,
  "enable_os": true,
  "enable_service": true,
  "version_intensity": 7
}
```

#### 获取任务列表

```http
GET /api/v1/scan/tasks
Authorization: Bearer <token>
```

#### 获取任务详情

```http
GET /api/v1/scan/tasks/{task_id}
Authorization: Bearer <token>
```

#### 获取任务结果

```http
GET /api/v1/scan/tasks/{task_id}/result
Authorization: Bearer <token>
```

#### 取消任务

```http
DELETE /api/v1/scan/tasks/{task_id}
Authorization: Bearer <token>
```

#### 系统状态

```http
GET /api/v1/system/status
Authorization: Bearer <token>
```

#### 系统指标

```http
GET /api/v1/system/metrics
Authorization: Bearer <token>
```

## 配置说明

### 扫描选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| -t, --target | 扫描目标 (IP地址或域名) | - |
| -p, --ports | 端口范围 (例如: 80,443 或 1-1024) | - |
| -s, --scan-type | 扫描类型 (tcp 或 udp) | tcp |
| --timeout | 超时时间 | 5s |
| -w, --workers | 工作线程数 | 100 |
| -f, --format | 输出格式 (text, json, xml, html) | text |
| -o, --output | 输出文件路径 | - |
| -P, --pretty | 美化输出 | false |
| -O, --os-detection | 启用操作系统检测 | false |
| --service-detection | 启用服务检测 | false |
| --version-intensity | 版本检测强度 (0-9) | 7 |
| --guess-os | 推测操作系统 | false |
| --limit-os | 限制操作系统扫描 | false |

### MCP 扫描选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| -i, --input | 输入配置文件路径 (JSON格式) | - |
| -o, --output | 输出文件路径 | - |
| -c, --config | 直接提供JSON配置数据 | - |

### API 服务选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| --host | API服务监听地址 | 0.0.0.0 |
| --port | API服务监听端口 | 8080 |
| --jwt-secret | JWT密钥 | - |
| --redis-addr | Redis服务器地址 | localhost:6379 |
| --redis-pass | Redis密码 | - |
| --redis-db | Redis数据库编号 | 0 |
| --max-workers | 最大工作线程数 | 10 |
| --queue-size | 任务队列大小 | 100 |
| --enable-auth | 启用认证 | true |

### MCP API 服务选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| -i, --input | 输入配置文件路径 (JSON格式) | - |
| -c, --config | 直接提供JSON配置数据 | - |

## 开发说明

### 目录结构

```
.
├── cmd/                    # 命令行工具
│   ├── root.go            # 根命令
│   └── commands.go        # 子命令实现
├── pkg/                    # 核心包
│   ├── api/               # HTTP API实现
│   ├── fingerprint/       # 指纹识别
│   ├── output/            # 输出处理
│   └── scanner/           # 扫描实现
├── go.mod                 # Go模块文件
├── go.sum                 # 依赖版本锁定
└── README.md             # 说明文档
```

### 依赖管理

```bash
# 更新依赖
go mod tidy

# 添加新依赖
go get github.com/example/package

# 更新特定依赖
go get -u github.com/example/package
```

### 编译

```bash
# 本地编译
go build -o go-port-rocket

# 交叉编译 (Linux)
GOOS=linux GOARCH=amd64 go build -o go-port-rocket

# 交叉编译 (Windows)
GOOS=windows GOARCH=amd64 go build -o go-port-rocket.exe
```

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 示例

项目的 `examples` 目录中包含了各种使用示例，包括：

- MCP 扫描配置示例 (`mcpscan_config.json`)
- MCP API 服务配置示例 (`mcpapi_config.json`)
- 详细的使用说明文档

查看 `examples/README.md` 以获取更多关于如何使用 MCP 功能的信息。

## Docker 使用

### 构建 Docker 镜像

#### 使用构建助手脚本（推荐）

我们提供了一个构建助手脚本，可以帮助检测常见的构建问题并提供解决方案：

```bash
# 给脚本添加执行权限
chmod +x build-docker.sh

# 基本用法
./build-docker.sh

# 使用代理
./build-docker.sh --proxy http://127.0.0.1:7890

# 指定镜像名称和标签
./build-docker.sh --image my-rocket --tag v1.0.0

# 查看所有选项
./build-docker.sh --help
```

构建助手脚本会：
- 检查Docker安装和服务状态
- 检测网络连接问题
- 提供详细的错误分析和解决方案
- 显示镜像使用示例

#### 手动构建

如果您不想使用构建助手脚本，也可以直接使用Docker命令构建：

```bash
# 基本构建
docker build -t go-port-rocket .

# 如果遇到网络问题，可以尝试使用代理
export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890
docker build -t go-port-rocket .

# 不使用缓存重新构建
docker build --no-cache -t go-port-rocket .
```

### 常见构建问题及解决方案

#### 网络相关问题

如果在构建过程中遇到以下错误：
- "connection refused"
- "timeout"
- "TLS handshake timeout"
- "could not resolve"
- "failed to fetch"

可能原因是网络连接问题，可以尝试以下解决方案：
1. 检查您的网络连接
2. 使用代理构建
3. 如果使用公司网络，请确认防火墙设置
4. 尝试使用--no-cache选项重新构建

#### 平台架构问题

如果遇到"exec format error"或架构不兼容的错误：
- 确保Dockerfile中的平台标志与您的系统匹配
- 在ARM系统上，使用`--platform=linux/arm64`
- 在x86系统上，使用`--platform=linux/amd64`

您可以修改Dockerfile中的平台声明：
```
FROM --platform=linux/amd64 ubuntu:latest AS builder
```

#### Docker网络诊断工具

如果您遇到网络相关问题，我们提供了一个诊断工具来帮助定位和解决问题：

```bash
# 给脚本添加执行权限
chmod +x docker-network-test.sh

# 运行诊断
./docker-network-test.sh

# 使用代理进行诊断
./docker-network-test.sh --proxy http://127.0.0.1:7890
```

这个诊断工具会：
- 检查Docker安装和服务状态
- 测试基本网络连接
- 检查DNS解析
- 测试与Docker Hub的连接
- 提供详细的错误分析和解决方案

### 运行 Docker 容器

构建完成后，可以使用以下命令运行容器：

```bash
# 显示帮助信息
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN go-port-rocket

# 执行扫描（需要网络权限）
docker run --rm --network host --cap-add=NET_RAW --cap-add=NET_ADMIN go-port-rocket scan -t 192.168.1.1 -p 80,443,8080
```

注意：
- 必须添加 `--cap-add=NET_RAW --cap-add=NET_ADMIN` 参数，使容器能够执行原始套接字操作
- 使用 `--network host` 参数可以使容器直接使用主机网络，这对于网络扫描是必需的
- 如果仍然遇到权限问题，可以使用完全特权模式运行: `docker run --privileged`，但这种方式安全性较低
- 如果在ARM架构系统上构建，请确保Dockerfile中使用了正确的平台标志 