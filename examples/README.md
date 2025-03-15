# Go Port Rocket MCP 示例

本目录包含使用 Go Port Rocket 多行命令处理 (MCP) 功能的示例配置和使用说明。

## MCP 扫描

### 使用配置文件

```bash
# 使用示例配置文件执行扫描
go-port-rocket mcpscan -i mcpscan_config.json

# 指定输出文件覆盖配置中的输出设置
go-port-rocket mcpscan -i mcpscan_config.json -o custom_result.json
```

### 直接提供配置数据

```bash
# 直接通过命令行提供配置
go-port-rocket mcpscan -c '{"target":"example.com","ports":"80,443","scan_type":"tcp"}'
```

### 通过标准输入

```bash
# 通过管道提供配置
echo '{"target":"example.com","ports":"80,443","scan_type":"tcp"}' | go-port-rocket mcpscan

# 使用重定向提供配置
go-port-rocket mcpscan < mcpscan_config.json
```

## MCP API 服务

### 使用配置文件启动 API 服务

```bash
# 使用示例配置文件启动 API 服务
go-port-rocket mcpapi -i mcpapi_config.json
```

### 直接提供配置数据

```bash
# 直接通过命令行提供配置
go-port-rocket mcpapi -c '{"port":9090,"jwt_secret":"my-secret","enable_auth":true}'
```

## AI 集成使用

MCP 功能特别适合 AI 系统调用。AI 系统可以生成 JSON 配置，然后通过命令行直接执行扫描任务或启动 API 服务。

示例 AI 集成流程：

1. AI 生成扫描配置
2. 配置通过 `-c` 参数或标准输入传递给 `mcpscan` 命令
3. 命令执行，生成结果
4. AI 解析结果，提供分析和建议

这种方式使 AI 系统能够利用 Go Port Rocket 的强大功能，而不需要了解复杂的命令行参数。

## 配置字段说明

### MCP 扫描配置

| 字段 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| target | string | 扫描目标 (IP或域名) | (必填) |
| ports | string | 端口范围 | (必填) |
| scan_type | string | 扫描类型 (tcp或udp) | "tcp" |
| timeout | string | 超时时间 (例如: "5s") | "5s" |
| workers | int | 工作线程数 | 100 |
| format | string | 输出格式 (text, json, xml, html) | "text" |
| output | string | 输出文件路径 | (标准输出) |
| pretty | bool | 美化输出 | false |
| os_detection | bool | 启用操作系统检测 | false |
| service_detection | bool | 启用服务检测 | false |
| version_intensity | int | 版本检测强度 (0-9) | 7 |
| guess_os | bool | 推测操作系统 | false |
| limit_os | bool | 限制操作系统扫描 | false |

### MCP API 配置

| 字段 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| host | string | 监听地址 | "0.0.0.0" |
| port | int | 监听端口 | 8080 |
| jwt_secret | string | JWT 密钥 | (必填，如果启用认证) |
| redis_addr | string | Redis 地址 | "localhost:6379" |
| redis_password | string | Redis 密码 | "" |
| redis_db | int | Redis 数据库编号 | 0 |
| max_workers | int | 最大工作线程数 | 10 |
| queue_size | int | 任务队列大小 | 100 |
| enable_auth | bool | 启用认证 | true | 