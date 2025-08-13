package test

import (
	"encoding/json"
	"fmt"
	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
	"log"
	"testing"
	"time"
)

// TestSimplePortScan 简单端口扫描测试
func TestSimplePortScan(t *testing.T) {
	fmt.Println("简单端口扫描测试")
	// 创建服务检测选项
	serviceOptions := &scanner.ServiceDetectionOptions{
		EnableVersionDetection: true,            // 启用版本检测
		VersionIntensity:       7,               // 版本检测强度(0-9)，值越大检测越详细但耗时越长
		EnableOSDetection:      true,            // 启用操作系统检测
		BannerGrab:             true,            // 获取服务banner
		Timeout:                time.Second * 5, // 服务检测超时
	}
	// 创建简单的扫描配置
	scanOpts := &scanner.ScanOptions{
		Target:           "127.0.0.1",         // 扫描目标
		Ports:            "22,80,443",         // 要扫描的端口
		ScanType:         scanner.ScanTypeTCP, // 使用TCP扫描
		Timeout:          2 * time.Second,     // 连接超时时间
		Workers:          10,                  // 并发工作线程数
		EnableService:    true,                // 启用服务检测
		EnableOS:         true,                // 启用操作系统检测
		ServiceProbe:     true,                // 启用服务探测
		BannerProbe:      true,                // 获取服务banner
		Service:          serviceOptions,      // 服务检测选项
		VersionIntensity: 7,                   //版本检测强度 (0-9)，值越大越详细但速度越慢
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
		}
		fmt.Printf("端口 %d: %s\n", result.Port, state)
		if result.State == scanner.PortStateOpen {
			r, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println("json：", string(r))
			if result.ServiceName != "" {
				fmt.Printf("  Service: %s\n", result.ServiceName)
			}
		}
	}
}
