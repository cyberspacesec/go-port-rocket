# Go Port Rocket 使用示例 / Go Port Rocket Examples

[中文](#中文说明) | [English](#english)

## 中文说明

本目录包含 Go Port Rocket 扫描器的各种使用示例，从简单的基础扫描到更复杂的高级应用场景。

### 运行说明

1. 某些扫描示例可能需要较长时间运行，特别是在扫描远程主机或执行多端口扫描时
2. 大多数示例都支持 `--fast` 或 `-f` 参数来启用快速模式，减少扫描端口数量以加快执行速度
3. 某些扫描类型（如 SYN 扫描、ACK 扫描等）需要管理员/root 权限才能运行
4. 请仅在获得授权的网络和系统上执行扫描
5. 对 Internet 主机进行扫描可能违反法律或服务条款

### 示例列表

#### 01_basic_tcp_scan
基本的TCP端口扫描示例，展示如何扫描指定目标的TCP端口。

使用方法: `cd 01_basic_tcp_scan; go run main.go`

#### 02_udp_scan
UDP端口扫描示例，展示如何扫描指定目标的UDP端口。

使用方法: `cd 02_udp_scan; go run main.go`

#### 03_service_detection
服务检测示例，展示如何在扫描时检测端口上运行的服务和版本信息。

使用方法: `cd 03_service_detection; go run main.go`

#### 04_os_detection
操作系统检测示例，展示如何通过TCP/IP指纹识别目标的操作系统类型。

使用方法: `cd 04_os_detection; go run main.go`

#### 05_output_formats
输出格式示例，展示如何以不同格式（文本、JSON、XML、CSV）保存扫描结果。

使用方法: `cd 05_output_formats; go run main.go`

#### 06_web_integration
Web服务集成示例，展示如何创建一个Web界面来运行和展示端口扫描结果。

使用方法: `cd 06_web_integration; go run main.go`

#### 07_syn_scan
SYN半开放扫描示例，展示如何执行不完成完整TCP连接的SYN扫描技术。(需要root权限)

使用方法: `sudo cd 07_syn_scan; sudo go run main.go`

#### 08_common_service_scan
常见服务扫描示例，展示如何针对特定服务类型进行有针对性的扫描与检测。

使用方法: `cd 08_common_service_scan; go run main.go`

#### 09_host_discovery
主机发现示例，展示如何使用多种技术发现网络中的活跃主机。

使用方法: `cd 09_host_discovery; go run main.go`

#### 10_firewall_detection
防火墙检测示例，展示如何通过不同的扫描技术检测防火墙和IDS/IPS系统。(部分功能需要root权限)

使用方法: `cd 10_firewall_detection; go run main.go`

#### 11_vulnerability_scan
漏洞扫描示例，展示如何识别常见服务中的安全问题和潜在漏洞。

使用方法: `cd 11_vulnerability_scan; go run main.go`

#### 12_batch_scan
批量扫描示例，展示如何从文件中读取多个目标并进行并行扫描。

使用方法: `cd 12_batch_scan; go run main.go`

#### 13_timing_stealth
定时和隐蔽扫描示例，展示如何控制扫描速度和使用隐蔽技术减少被检测风险。

使用方法: `cd 13_timing_stealth; go run main.go`

#### 14_ipv6_scan
IPv6扫描示例，展示如何扫描IPv6网络和地址。

使用方法: `cd 14_ipv6_scan; go run main.go`

### 许可证

这些示例遵循与主项目相同的许可证。详见项目根目录下的 LICENSE 文件。

### Docker容器中的使用

本项目所有示例都可以在Docker容器中运行，但需要注意以下几点：

1. **特权需求**：由于Go Port Rocket执行的是低级网络操作（如原始套接字、数据包捕获），在Docker容器中运行时需要额外的网络权限
2. **运行方式**：运行Docker容器时必须添加特定的网络权限（`--cap-add=NET_RAW --cap-add=NET_ADMIN`）或使用特权模式
3. **权限说明**：这些特权是必需的，因为：
   - 原始套接字（Raw Sockets）操作需要`NET_RAW`权限
   - 网络数据包捕获通过libpcap需要特殊权限
   - SYN/FIN/ACK等扫描需要直接操作TCP/IP协议栈

示例命令：
```bash
# 使用最小权限运行
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network host go-port-rocket scan -t 127.0.0.1 -p 80,443

# 如果上述命令不起作用，可以使用特权模式（不推荐，除非必要）
docker run --rm --privileged --network host go-port-rocket scan -t 127.0.0.1 -p 80,443
```

---

## English

This directory contains various examples of the Go Port Rocket scanner, from simple basic scans to more complex advanced application scenarios.

### Usage Notes

1. Some scanning examples may take a long time to run, especially when scanning remote hosts or performing multi-port scans
2. Most examples support the `--fast` or `-f` parameter to enable fast mode, reducing the number of ports scanned to speed up execution
3. Some scan types (such as SYN scan, ACK scan, etc.) require administrator/root privileges to run
4. Please only perform scans on networks and systems for which you have authorization
5. Scanning Internet hosts may violate laws or terms of service

### Examples List

#### 01_basic_tcp_scan
Basic TCP port scanning example, demonstrates how to scan TCP ports on a specified target.

Usage: `cd 01_basic_tcp_scan; go run main.go`

#### 02_udp_scan
UDP port scanning example, demonstrates how to scan UDP ports on a specified target.

Usage: `cd 02_udp_scan; go run main.go`

#### 03_service_detection
Service detection example, demonstrates how to detect services and version information running on ports during scanning.

Usage: `cd 03_service_detection; go run main.go`

#### 04_os_detection
Operating system detection example, demonstrates how to identify the target's operating system type through TCP/IP fingerprinting.

Usage: `cd 04_os_detection; go run main.go`

#### 05_output_formats
Output format example, demonstrates how to save scan results in different formats (text, JSON, XML, CSV).

Usage: `cd 05_output_formats; go run main.go`

#### 06_web_integration
Web service integration example, demonstrates how to create a web interface to run and display port scan results.

Usage: `cd 06_web_integration; go run main.go`

#### 07_syn_scan
SYN half-open scanning example, demonstrates how to perform SYN scanning techniques without completing a full TCP connection. (Requires root privileges)

Usage: `sudo cd 07_syn_scan; sudo go run main.go`

#### 08_common_service_scan
Common service scanning example, demonstrates how to perform targeted scanning and detection for specific service types.

Usage: `cd 08_common_service_scan; go run main.go`

#### 09_host_discovery
Host discovery example, demonstrates how to discover active hosts in a network using multiple techniques.

Usage: `cd 09_host_discovery; go run main.go`

#### 10_firewall_detection
Firewall detection example, demonstrates how to detect firewalls and IDS/IPS systems through different scanning techniques. (Some features require root privileges)

Usage: `cd 10_firewall_detection; go run main.go`

#### 11_vulnerability_scan
Vulnerability scanning example, demonstrates how to identify security issues and potential vulnerabilities in common services.

Usage: `cd 11_vulnerability_scan; go run main.go`

#### 12_batch_scan
Batch scanning example, demonstrates how to read multiple targets from a file and perform parallel scanning.

Usage: `cd 12_batch_scan; go run main.go`

#### 13_timing_stealth
Timing and stealth scanning example, demonstrates how to control scanning speed and use stealth techniques to reduce detection risk.

Usage: `cd 13_timing_stealth; go run main.go`

#### 14_ipv6_scan
IPv6 scanning example, demonstrates how to scan IPv6 networks and addresses.

Usage: `cd 14_ipv6_scan; go run main.go`

### License

These examples follow the same license as the main project. See the LICENSE file in the project root directory for details. 