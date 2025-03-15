package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 检查是否有root/管理员权限（SYN扫描需要原始套接字访问权限）
	if os.Geteuid() != 0 {
		fmt.Println("警告: SYN扫描需要root/管理员权限才能使用原始套接字")
		fmt.Println("请使用sudo或管理员权限运行此示例")
		os.Exit(1)
	}

	// 创建SYN扫描选项
	scanOptions := &scanner.ScanOptions{
		Target:        "scanme.nmap.org",   // 扫描目标
		Ports:         "20-25,80,443",      // 常见端口范围
		ScanType:      scanner.ScanTypeSYN, // SYN扫描类型
		Timeout:       time.Second * 5,     // 超时设置
		Workers:       50,                  // 工作线程数
		EnableService: true,                // 启用服务检测
	}

	// 执行SYN扫描
	fmt.Println("开始SYN扫描（半开放连接扫描）...")
	fmt.Printf("目标: %s, 端口范围: %s\n", scanOptions.Target, scanOptions.Ports)
	fmt.Println("SYN扫描发送SYN包但不完成完整的TCP握手，可避免被某些简单防火墙和日志系统检测")
	startTime := time.Now()
	result, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		log.Fatalf("扫描过程中出错: %v", err)
	}
	duration := time.Since(startTime)

	// 打印扫描结果
	fmt.Println("\nSYN扫描结果:")
	fmt.Println("================================================")

	// 统计开放/关闭/过滤端口数量
	var openPorts, closedPorts, filteredPorts int
	for _, portResult := range result {
		switch portResult.State {
		case scanner.PortStateOpen:
			openPorts++
		case scanner.PortStateClosed:
			closedPorts++
		case scanner.PortStateFiltered:
			filteredPorts++
		}

		// 打印详细结果
		stateStr := string(portResult.State)
		fmt.Printf("端口 %d/tcp: %s", portResult.Port, stateStr)

		// 显示服务信息
		if portResult.State == scanner.PortStateOpen && portResult.ServiceName != "" {
			fmt.Printf(" (%s", portResult.ServiceName)
			if portResult.Service != nil && portResult.Service.Version != "" {
				fmt.Printf(" %s", portResult.Service.Version)
			}
			fmt.Printf(")")
		}
		fmt.Println()
	}

	// 打印统计信息
	fmt.Printf("\n扫描统计:\n")
	fmt.Printf("- 扫描时间: %.2f秒\n", duration.Seconds())
	fmt.Printf("- 总端口数: %d\n", len(result))
	fmt.Printf("- 开放端口: %d\n", openPorts)
	fmt.Printf("- 关闭端口: %d\n", closedPorts)
	fmt.Printf("- 过滤端口: %d\n", filteredPorts)

	fmt.Println("\nSYN扫描完成")
}
