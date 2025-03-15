package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 创建服务检测选项，专注于操作系统检测
	serviceOptions := &scanner.ServiceDetectionOptions{
		EnableVersionDetection: true,            // 启用版本检测
		EnableOSDetection:      true,            // 启用操作系统检测
		BannerGrab:             true,            // 获取服务banner
		Timeout:                time.Second * 5, // 服务检测超时
	}

	// 创建扫描选项，启用操作系统检测
	scanOptions := &scanner.ScanOptions{
		Target:      "scanme.nmap.org",   // 扫描目标，nmap官方提供的测试服务器
		Ports:       "22,80,443",         // 扫描常用端口以获取OS信息
		ScanType:    scanner.ScanTypeTCP, // TCP扫描类型
		Timeout:     time.Second * 10,    // 扫描超时
		Workers:     10,                  // 工作线程数
		EnableOS:    true,                // 启用操作系统检测
		GuessOS:     true,                // 尝试推测操作系统
		LimitOSScan: false,               // 不限制操作系统扫描
		Service:     serviceOptions,      // 服务检测选项
	}

	fmt.Println("开始扫描并检测操作系统...")
	fmt.Printf("目标: %s, 端口范围: %s\n", scanOptions.Target, scanOptions.Ports)
	fmt.Println("操作系统检测可能需要较长时间，请耐心等待...")

	// 执行扫描
	result, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		log.Fatalf("扫描过程中出错: %v", err)
	}

	// 收集所有发现的操作系统信息
	osInfoMap := make(map[string]float64) // 操作系统名称 -> 置信度

	// 打印扫描结果和OS信息
	fmt.Println("\n扫描结果与操作系统信息:")
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
		if portResult.ServiceName != "" {
			fmt.Printf("  - 服务: %s\n", portResult.ServiceName)
		}

		// 显示和收集操作系统信息
		if portResult.OS != nil {
			osName := portResult.OS.Name
			if portResult.OS.Version != "" {
				osName = fmt.Sprintf("%s %s", osName, portResult.OS.Version)
			}

			fmt.Printf("  - 检测到操作系统: %s (置信度: %.1f%%)\n", osName, portResult.OS.Confidence*100)

			// 收集OS信息，保留最高置信度
			existingConfidence, exists := osInfoMap[osName]
			if !exists || portResult.OS.Confidence > existingConfidence {
				osInfoMap[osName] = portResult.OS.Confidence
			}
		}

		// 显示TTL
		if portResult.TTL > 0 {
			fmt.Printf("  - TTL值: %d\n", portResult.TTL)
		}

		fmt.Println("------------------------------------------------")
	}

	// 汇总操作系统检测结果
	fmt.Println("\n操作系统检测结果汇总:")
	fmt.Println("================================================")
	if len(osInfoMap) > 0 {
		for osName, confidence := range osInfoMap {
			fmt.Printf("操作系统: %s (置信度: %.1f%%)\n", osName, confidence*100)
		}
	} else {
		fmt.Println("未能检测到操作系统信息")
	}

	fmt.Printf("\n扫描完成，共检测 %d 个端口\n", len(result))
}
