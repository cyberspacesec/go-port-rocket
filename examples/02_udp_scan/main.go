package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 创建UDP扫描选项
	scanOptions := &scanner.ScanOptions{
		Target:   "scanme.nmap.org",   // 扫描目标，nmap官方提供的测试服务器
		Ports:    "53,161,123",        // UDP常用端口：DNS(53)、SNMP(161)、NTP(123)
		ScanType: scanner.ScanTypeUDP, // UDP扫描类型
		Timeout:  time.Second * 5,     // 超时设置
		Workers:  20,                  // 工作线程数
	}

	// 执行UDP扫描
	fmt.Println("开始UDP端口扫描...")
	result, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		log.Fatalf("扫描过程中出错: %v", err)
	}

	// 打印扫描结果
	fmt.Println("UDP扫描结果:")
	for _, portResult := range result {
		stateStr := "关闭"
		if portResult.State == scanner.PortStateOpen {
			stateStr = "开放"
		} else if portResult.State == scanner.PortStateFiltered {
			stateStr = "被过滤"
		}

		fmt.Printf("端口 %d/%s: %s", portResult.Port, "udp", stateStr)

		// 如果有服务信息，则显示
		if portResult.Service != nil {
			fmt.Printf(" (%s)", portResult.ServiceName)
		}
		fmt.Println()
	}

	fmt.Println("UDP扫描完成")
}
