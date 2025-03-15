package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 创建基础的TCP扫描选项
	opts := &scanner.ScanOptions{
		Target:   "scanme.nmap.org",   // 扫描目标，nmap官方提供的测试服务器
		Ports:    "22,80,443",         // 指定要扫描的端口
		ScanType: scanner.ScanTypeTCP, // 使用TCP扫描
		Timeout:  5 * time.Second,     // 超时时间
		Workers:  10,                  // 并发工作线程数
	}

	// 执行扫描 - 使用ExecuteScan函数而不是Scanner结构体
	fmt.Printf("开始基础TCP扫描，目标: %s，端口: %s\n", opts.Target, opts.Ports)
	results, err := scanner.ExecuteScan(opts)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 打印结果
	fmt.Println("扫描完成，结果:")
	for _, result := range results {
		stateStr := "关闭"
		if result.State == scanner.PortStateOpen {
			stateStr = "开放"
		} else if result.State == scanner.PortStateFiltered {
			stateStr = "被过滤"
		}

		fmt.Printf("端口 %d: %s\n", result.Port, stateStr)
	}
}
