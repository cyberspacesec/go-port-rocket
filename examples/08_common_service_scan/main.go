package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// 常见服务及其默认端口
var commonServices = map[string][]int{
	"Web服务":  {80, 443, 8080, 8443},
	"数据库服务":  {3306, 5432, 1433, 1521, 27017, 6379},
	"远程访问服务": {22, 23, 3389, 5900},
	"邮件服务":   {25, 110, 143, 465, 587, 993, 995},
	"文件传输服务": {20, 21, 69, 115, 139, 445},
	"域名服务":   {53, 853},
	"网络管理服务": {161, 162, 199, 10000},
	"VPN服务":  {500, 1701, 1723, 4500},
	"流媒体服务":  {554, 1935, 5004, 5005},
	"版本控制服务": {9418, 2401, 3690},
}

func main() {
	target := "scanme.nmap.org" // 扫描目标
	serviceOptions := &scanner.ServiceDetectionOptions{
		EnableVersionDetection: true,
		VersionIntensity:       7,
		BannerGrab:             true,
		Timeout:                time.Second * 3,
	}

	fmt.Printf("开始对 %s 进行常见服务扫描\n", target)
	fmt.Println("====================================================")

	totalOpenPorts := 0

	// 针对每种服务类型进行扫描
	for serviceName, ports := range commonServices {
		// 将端口数组转换为端口范围字符串
		portsStr := ""
		for i, port := range ports {
			if i > 0 {
				portsStr += ","
			}
			portsStr += fmt.Sprintf("%d", port)
		}

		// 扫描选项
		scanOptions := &scanner.ScanOptions{
			Target:           target,
			Ports:            portsStr,
			ScanType:         scanner.ScanTypeTCP,
			Timeout:          time.Second * 5,
			Workers:          10,
			EnableService:    true,
			ServiceProbe:     true,
			BannerProbe:      true,
			VersionIntensity: 7,
			Service:          serviceOptions,
		}

		fmt.Printf("\n正在扫描 %s 相关端口: %s\n", serviceName, portsStr)

		// 执行扫描
		results, err := scanner.ExecuteScan(scanOptions)
		if err != nil {
			log.Printf("扫描 %s 端口时出错: %v", serviceName, err)
			continue
		}

		// 统计和显示结果
		openCount := 0
		for _, result := range results {
			if result.State == scanner.PortStateOpen {
				openCount++
				totalOpenPorts++

				fmt.Printf("✓ 端口 %d: 开放", result.Port)

				// 显示服务信息
				if result.ServiceName != "" {
					fmt.Printf(" - %s", result.ServiceName)
					if result.Service != nil && result.Service.Version != "" {
						fmt.Printf(" %s", result.Service.Version)
					}
					if result.Service != nil && result.Service.Product != "" {
						fmt.Printf(" (%s)", result.Service.Product)
					}
				}
				fmt.Println()

				// 显示Banner信息（如果有）
				if result.Banner != "" {
					// 截断过长的Banner
					banner := result.Banner
					if len(banner) > 80 {
						banner = banner[:77] + "..."
					}
					fmt.Printf("  Banner: %s\n", banner)
				}
			}
		}

		if openCount == 0 {
			fmt.Printf("✗ 未发现开放的%s端口\n", serviceName)
		}
	}

	fmt.Println("\n====================================================")
	fmt.Printf("扫描完成，共发现 %d 个开放端口\n", totalOpenPorts)

	// 扫描建议
	if totalOpenPorts > 0 {
		fmt.Println("\n安全建议:")
		fmt.Println("- 检查是否所有开放的服务都是必需的")
		fmt.Println("- 确保所有服务都使用最新版本并配置了安全选项")
		fmt.Println("- 考虑使用防火墙限制对非必需服务的访问")
	}
}
