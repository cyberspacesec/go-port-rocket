package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 创建服务检测选项
	serviceOptions := &scanner.ServiceDetectionOptions{
		EnableVersionDetection: true,            // 启用版本检测
		VersionIntensity:       7,               // 版本检测强度(0-9)，值越大检测越详细但耗时越长
		EnableOSDetection:      true,            // 启用操作系统检测
		BannerGrab:             true,            // 获取服务banner
		Timeout:                time.Second * 5, // 服务检测超时
	}

	// 创建TCP扫描选项，启用服务检测
	scanOptions := &scanner.ScanOptions{
		Target:           "scanme.nmap.org",   // 扫描目标，nmap官方提供的测试服务器
		Ports:            "20-25,80,443",      // 扫描端口范围
		ScanType:         scanner.ScanTypeTCP, // TCP扫描类型
		Timeout:          time.Second * 10,    // 扫描超时
		Workers:          10,                  // 工作线程数
		EnableService:    true,                // 启用服务检测
		ServiceProbe:     true,                // 启用服务探测
		BannerProbe:      true,                // 获取服务banner
		VersionIntensity: 7,                   // 版本检测强度
		Service:          serviceOptions,      // 服务检测选项
		EnableOS:         true,                // 启用操作系统检测
	}

	// 执行扫描
	fmt.Println("开始扫描并检测服务...")
	fmt.Printf("目标: %s, 端口范围: %s\n", scanOptions.Target, scanOptions.Ports)
	fmt.Println("这可能需要一些时间，请耐心等待...")
	result, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		log.Fatalf("扫描过程中出错: %v", err)
	}

	// 打印扫描结果
	fmt.Println("\n扫描结果:")
	fmt.Println("================================================")
	for _, portResult := range result {
		// 端口状态
		stateStr := "关闭"
		if portResult.State == scanner.PortStateOpen {
			stateStr = "开放"
		} else if portResult.State == scanner.PortStateFiltered {
			stateStr = "被过滤"
		}

		fmt.Printf("端口 %d/%s: %s\n", portResult.Port, scanOptions.ScanType, stateStr)

		// 显示服务信息
		if portResult.Service != nil {
			fmt.Printf("  - 服务: %s\n", portResult.ServiceName)
			if portResult.Service.Product != "" {
				fmt.Printf("  - 产品: %s\n", portResult.Service.Product)
			}
			if portResult.Service.Version != "" {
				fmt.Printf("  - 版本: %s\n", portResult.Service.Version)
			}
			// 从Metadata中获取额外信息
			if portResult.Service.Metadata != nil {
				if extraInfo, ok := portResult.Service.Metadata["extra_info"]; ok {
					fmt.Printf("  - 额外信息: %s\n", extraInfo)
				}
			}
		}

		// 显示操作系统信息
		if portResult.OS != nil {
			fmt.Printf("  - 操作系统: %s", portResult.OS.Name)
			if portResult.OS.Version != "" {
				fmt.Printf(" %s", portResult.OS.Version)
			}
			fmt.Printf(" (置信度: %.1f%%)\n", portResult.OS.Confidence*100)
		}

		// 显示Banner信息
		if portResult.Banner != "" {
			fmt.Printf("  - Banner: %s\n", portResult.Banner)
		}

		fmt.Println("------------------------------------------------")
	}

	fmt.Printf("\n扫描完成，共检测 %d 个端口\n", len(result))
}
