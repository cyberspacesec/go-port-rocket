/*
  - Package test
    @Author: zhizhuo
    @IDE：GoLand
    @File: portscan_test.go
    @Date: 2025/8/12 下午2:04*
*/
package test

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// TestPortScan 端口扫描
func TestPortScan(t *testing.T) {
	fmt.Println("端口扫描测试")
	// 创建服务检测选项
	serviceOptions := &scanner.ServiceDetectionOptions{
		EnableVersionDetection: false,           // 禁用版本检测 - 避免超时
		VersionIntensity:       3,               // 降低版本检测强度
		EnableOSDetection:      false,           // 禁用操作系统检测
		BannerGrab:             true,            // 获取服务banner
		Timeout:                time.Second * 2, // 减少服务检测超时
	}
	// 创建简单的扫描配置
	scanOpts := &scanner.ScanOptions{
		Target:           "scanme.nmap.org",   // 扫描目标 - 使用可达的测试服务器替代172.18.6.253
		Ports:            "22,80,443",         // 要扫描的端口 - 只扫描几个常见端口
		ScanType:         scanner.ScanTypeTCP, // 使用TCP扫描
		Timeout:          3 * time.Second,     // 连接超时时间 - 优化超时时间
		Workers:          10,                  // 并发工作线程数 - 优化并发数
		EnableService:    false,               // 禁用服务检测 - 避免超时
		EnableOS:         false,               // 禁用操作系统检测 - 避免超时
		ServiceProbe:     false,               // 禁用服务探测 - 避免超时
		BannerProbe:      false,               // 禁用服务banner - 避免超时
		Service:          serviceOptions,      // 服务检测选项
		VersionIntensity: 0,                   // 禁用版本检测强度
	}

	// 执行扫描
	fmt.Println("开始扫描目标:", scanOpts.Target)
	results, err := scanner.ExecuteScan(scanOpts)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 输出结果
	fmt.Println("扫描结果:")
	for _, result := range results {
		state := "关闭"
		if result.State == scanner.PortStateOpen {
			state = "开放"
			fmt.Printf("端口 %d: %s\n", result.Port, state)
			r, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println("json：", string(r))
			if result.ServiceName != "" {
				fmt.Printf("  Service: %s\n", result.ServiceName)

			}
		}

	}
}
