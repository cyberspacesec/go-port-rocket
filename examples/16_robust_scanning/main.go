package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	fmt.Println("=== 稳定性扫描示例 ===")
	fmt.Println("展示工具如何在用户设置的参数下保持稳定运行")

	// 用户的原始配置（保持不变）
	fmt.Println("\n🎯 用户配置（工具会完全按此执行）:")
	userConfig := &scanner.ScanOptions{
		Target:           "127.0.0.1", // 使用本地测试避免网络问题
		Ports:            "22,80,443", // 简化测试
		ScanType:         scanner.ScanTypeTCP,
		Timeout:          2 * time.Second, // 用户设置的超时
		Workers:          10,              // 用户设置的并发数
		EnableService:    true,            // 用户启用的功能
		ServiceProbe:     true,
		BannerProbe:      true,
		VersionIntensity: 3, // 用户设置的强度
	}

	fmt.Printf("目标: %s\n", userConfig.Target)
	fmt.Printf("端口: %s\n", userConfig.Ports)
	fmt.Printf("并发: %d (用户设置，工具不会修改)\n", userConfig.Workers)
	fmt.Printf("超时: %v (用户设置，工具不会修改)\n", userConfig.Timeout)
	fmt.Printf("功能: 服务检测=%v, Banner抓取=%v\n", userConfig.ServiceProbe, userConfig.BannerProbe)

	// 工具会提供建议但不强制修改
	fmt.Println("\n💡 工具分析和建议:")
	advisor, err := scanner.NewScanAdvisor(userConfig)
	if err != nil {
		log.Fatalf("创建建议器失败: %v", err)
	}
	advisor.PrintSuggestions()

	// 执行扫描（按用户设置）
	fmt.Println("\n🚀 开始扫描（严格按用户配置执行）...")
	fmt.Println("   工具会:")
	fmt.Println("   ✅ 监控系统资源使用")
	fmt.Println("   ✅ 显示实时进度")
	fmt.Println("   ✅ 处理资源不足情况")
	fmt.Println("   ✅ 提供错误恢复机制")
	fmt.Println("   ❌ 不会修改用户的参数设置")

	startTime := time.Now()

	// 执行扫描
	results, err := scanner.ExecuteScan(userConfig)

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	if err != nil {
		fmt.Printf("❌ 扫描失败: %v\n", err)
		fmt.Println("\n🔧 故障排除建议:")
		fmt.Println("   • 检查系统资源限制: ulimit -n")
		fmt.Println("   • 降低并发数: --workers 20")
		fmt.Println("   • 增加超时时间: --timeout 10s")
		fmt.Println("   • 分批扫描: --ports 1-500")
		return
	}

	// 统计结果
	openPorts := 0
	for _, result := range results {
		if result.State == scanner.PortStateOpen {
			openPorts++
		}
	}

	fmt.Printf("\n✅ 扫描完成!\n")
	fmt.Printf("   总端口: %d\n", len(results))
	fmt.Printf("   开放端口: %d\n", openPorts)
	fmt.Printf("   用时: %v\n", duration.Round(time.Second))
	fmt.Printf("   平均速度: %.1f 端口/秒\n", float64(len(results))/duration.Seconds())

	// 显示开放端口详情
	if openPorts > 0 {
		fmt.Println("\n🔍 发现的开放端口:")
		count := 0
		for _, result := range results {
			if result.State == scanner.PortStateOpen {
				fmt.Printf("   Port %d: %s", result.Port, result.State)
				if result.ServiceName != "" {
					fmt.Printf(" (%s)", result.ServiceName)
				}
				if result.Version != "" {
					fmt.Printf(" - %s", result.Version)
				}
				fmt.Println()
				count++
				if count >= 10 { // 只显示前10个
					fmt.Printf("   ... 还有 %d 个开放端口\n", openPorts-10)
					break
				}
			}
		}
	}

	// 演示极端配置的处理
	fmt.Println("\n\n=== 极端配置测试 ===")
	fmt.Println("测试工具在极端参数下的稳定性")

	extremeConfig := &scanner.ScanOptions{
		Target:   "127.0.0.1",
		Ports:    "1-5000", // 更大范围
		ScanType: scanner.ScanTypeTCP,
		Timeout:  10 * time.Second, // 更长超时
		Workers:  200,              // 极高并发
	}

	fmt.Printf("\n🧪 极端配置测试:\n")
	fmt.Printf("   端口范围: %s\n", extremeConfig.Ports)
	fmt.Printf("   并发数: %d\n", extremeConfig.Workers)
	fmt.Printf("   超时: %v\n", extremeConfig.Timeout)

	// 分析极端配置
	extremeAdvisor, err := scanner.NewScanAdvisor(extremeConfig)
	if err != nil {
		log.Fatalf("创建建议器失败: %v", err)
	}

	fmt.Println("\n📊 极端配置分析:")
	extremeAdvisor.PrintSuggestions()

	fmt.Println("\n💪 工具的稳定性保证:")
	fmt.Println("   ✅ 自动资源监控和保护")
	fmt.Println("   ✅ 智能错误处理和恢复")
	fmt.Println("   ✅ 实时进度反馈")
	fmt.Println("   ✅ 资源不足时优雅降级")
	fmt.Println("   ✅ 详细的错误信息和建议")

	fmt.Println("\n🎯 总结:")
	fmt.Println("   • 工具尊重用户的所有参数设置")
	fmt.Println("   • 提供建议但不强制修改")
	fmt.Println("   • 通过内部优化保证稳定性")
	fmt.Println("   • 在资源不足时提供清晰的错误信息")
	fmt.Println("   • 用户可以根据建议自主调整参数")

	// 可选：执行一个小规模的极端配置测试
	fmt.Println("\n🔬 执行小规模极端配置测试...")
	smallExtremeConfig := &scanner.ScanOptions{
		Target:   "127.0.0.1",
		Ports:    "1-100",
		ScanType: scanner.ScanTypeTCP,
		Timeout:  time.Second,
		Workers:  50, // 相对于端口数来说很高的并发
	}

	testResults, err := scanner.ExecuteScan(smallExtremeConfig)
	if err != nil {
		fmt.Printf("   ⚠️  极端配置测试遇到问题: %v\n", err)
		fmt.Println("   这证明了工具会在资源不足时给出明确错误信息")
	} else {
		fmt.Printf("   ✅ 极端配置测试成功，扫描了 %d 个端口\n", len(testResults))
		fmt.Println("   工具在高并发下仍能稳定运行")
	}
}
