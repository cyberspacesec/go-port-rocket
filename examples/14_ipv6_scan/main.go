package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	fmt.Println("====================================")
	fmt.Println("       IPv6扫描示例")
	fmt.Println("====================================")

	// 快速模式检查
	fastMode := false
	for _, arg := range os.Args {
		if arg == "--fast" || arg == "-f" {
			fastMode = true
			break
		}
	}

	// 检查参数
	if len(os.Args) < 2 || os.Args[1] == "--fast" || os.Args[1] == "-f" {
		fmt.Println("请提供IPv6目标地址或主机名")
		fmt.Println("用法: go run main.go [IPv6地址或主机名] [--fast]")
		fmt.Println("示例: go run main.go 2606:4700:4700::1111")
		fmt.Println("      go run main.go ipv6.google.com")
		fmt.Println()
		fmt.Println("未提供参数，将使用默认IPv6测试目标")
		fmt.Println()
	}

	// 默认测试目标
	var target string
	for i, arg := range os.Args {
		if i > 0 && arg != "--fast" && arg != "-f" {
			target = arg
			break
		}
	}

	if target == "" {
		// 使用Cloudflare公共DNS服务器作为默认目标
		target = "2606:4700:4700::1111" // Cloudflare DNS
	}

	// 常见IPv6服务端口
	var commonPorts string
	if fastMode {
		commonPorts = "53,80,443" // 快速模式下只扫描少量端口
		fmt.Println("快速模式：只扫描少量关键端口")
	} else {
		commonPorts = "21-23,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,8080,8443"
	}

	// 解析IPv6地址
	ipv6Addr, addrType := resolveIPv6Address(target)

	if ipv6Addr == "" {
		fmt.Printf("错误: 无法将 %s 解析为有效的IPv6地址\n", target)
		os.Exit(1)
	}

	fmt.Printf("目标: %s\n", target)
	fmt.Printf("IPv6地址: %s\n", ipv6Addr)
	fmt.Printf("地址类型: %s\n", addrType)
	fmt.Printf("扫描端口: %s\n", commonPorts)
	fmt.Println("====================================")

	// 检查IPv6支持
	if !checkIPv6Support() {
		fmt.Println("警告: 当前系统可能不支持IPv6或IPv6连接")
		fmt.Println("IPv6测试连接失败，但仍将尝试扫描")
		fmt.Println()
	}

	// 执行IPv6扫描
	fmt.Printf("开始扫描IPv6目标 %s...\n\n", ipv6Addr)
	startTime := time.Now()

	// 创建扫描选项
	scanOptions := &scanner.ScanOptions{
		Target:   ipv6Addr, // 使用IPv6地址
		Ports:    commonPorts,
		ScanType: scanner.ScanTypeTCP,
		Timeout:  time.Second * 2,
		Workers:  20,
		// IPv6支持应该由底层库提供
	}

	// 执行扫描
	results, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		fmt.Printf("扫描错误: %v\n", err)
		os.Exit(1)
	}

	// 处理结果
	fmt.Printf("扫描完成! 耗时: %.2f 秒\n\n", time.Since(startTime).Seconds())

	// 统计
	var openPorts, closedPorts, filteredPorts int
	for _, result := range results {
		switch result.State {
		case scanner.PortStateOpen:
			openPorts++
		case scanner.PortStateClosed:
			closedPorts++
		case scanner.PortStateFiltered:
			filteredPorts++
		}
	}

	fmt.Printf("端口统计: %d 开放, %d 关闭, %d 过滤\n",
		openPorts, closedPorts, filteredPorts)

	// 输出开放端口
	if openPorts > 0 {
		fmt.Println("\n开放端口:")
		fmt.Println("PORT     STATE     SERVICE")

		for _, result := range results {
			if result.State == scanner.PortStateOpen {
				serviceName := ""
				if result.Service != nil {
					serviceName = result.Service.Name
					if result.Service.Version != "" {
						serviceName += " " + result.Service.Version
					}
				}
				fmt.Printf("%-8d %-9s %s\n",
					result.Port, result.State, serviceName)
			}
		}
	} else {
		fmt.Println("\n未发现开放端口")
	}

	// IPv6安全提示
	fmt.Println("\nIPv6扫描注意事项:")
	fmt.Println("1. IPv6地址空间极其庞大，不建议进行大范围扫描")
	fmt.Println("2. 许多IPv6网络配置忽略ping请求，使主机发现更加困难")
	fmt.Println("3. IPv6扫描通常需要更长时间，因为地址更长且处理更复杂")
	fmt.Println("4. 一些旧版扫描工具可能不完全支持IPv6")

	// IPv6网络映射技巧
	fmt.Println("\nIPv6网络映射技巧:")
	fmt.Println("1. 使用DNS记录识别活跃IPv6主机")
	fmt.Println("2. 利用IPv6多播地址发现本地网络中的设备")
	fmt.Println("3. 针对特定子网或已知主机进行扫描")
	fmt.Println("4. 检查常见IPv6地址模式，如低字节地址（::1, ::2等）")
}

// 解析IPv6地址
func resolveIPv6Address(target string) (string, string) {
	// 检查输入是否已经是IPv6地址
	if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
		return classifyIPv6Address(ip.String())
	}

	// 尝试解析主机名
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", ""
	}

	// 查找IPv6地址
	for _, ip := range ips {
		if ip.To4() == nil {
			return classifyIPv6Address(ip.String())
		}
	}

	return "", ""
}

// 对IPv6地址进行分类
func classifyIPv6Address(ipv6Addr string) (string, string) {
	ip := net.ParseIP(ipv6Addr)
	if ip == nil {
		return ipv6Addr, "未知"
	}

	// 检查各种IPv6地址类型
	if ip.IsLoopback() {
		return ipv6Addr, "回环地址"
	}

	if ip.IsLinkLocalUnicast() {
		return ipv6Addr, "链路本地单播"
	}

	if ip.IsLinkLocalMulticast() {
		return ipv6Addr, "链路本地多播"
	}

	if ip[0] == 0xfe && ip[1] == 0x80 {
		return ipv6Addr, "唯一本地地址 (ULA)"
	}

	if ip[0] == 0x20 && ip[1] == 0x01 {
		return ipv6Addr, "全球单播 (Teredo)"
	}

	if ip[0] == 0x20 && ip[1] == 0x02 {
		return ipv6Addr, "6to4 隧道地址"
	}

	if ip[0] == 0x26 && ip[1] == 0x00 {
		return ipv6Addr, "全球单播 (6bone测试)"
	}

	if ip[0] == 0x24 && ip[1] == 0x00 {
		return ipv6Addr, "ORCHID地址"
	}

	return ipv6Addr, "全球单播"
}

// 检查系统IPv6支持
func checkIPv6Support() bool {
	// 尝试连接到知名的IPv6服务器
	conn, err := net.DialTimeout("tcp", "[2606:4700:4700::1111]:53", time.Second*2)
	if err != nil {
		// 尝试另一个服务器
		conn, err = net.DialTimeout("tcp", "[2001:4860:4860::8888]:53", time.Second*2)
		if err != nil {
			return false
		}
	}
	defer conn.Close()
	return true
}
