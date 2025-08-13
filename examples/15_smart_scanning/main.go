package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	fmt.Println("=== 智能扫描示例 ===")
	fmt.Println("展示工具如何自动优化扫描参数并提供建议")
	
	// 示例1: 用户的原始配置（可能有问题的配置）
	fmt.Println("\n1. 用户原始配置（类似截图中的配置）:")
	problematicConfig := &scanner.ScanOptions{
		Target:           "www.baidu.com",
		Ports:            "1-65535",        // 全端口扫描
		ScanType:         scanner.ScanTypeTCP,
		Timeout:          5 * time.Second,   // 超时过长
		Workers:          100,               // 并发过高
		EnableService:    true,              // 启用服务检测
		EnableOS:         true,              // 启用OS检测
		ServiceProbe:     true,              // 启用服务探测
		BannerProbe:      true,              // 启用Banner抓取
		VersionIntensity: 7,                 // 最高强度
	}
	
	fmt.Printf("目标: %s\n", problematicConfig.Target)
	fmt.Printf("端口: %s\n", problematicConfig.Ports)
	fmt.Printf("并发: %d\n", problematicConfig.Workers)
	fmt.Printf("超时: %v\n", problematicConfig.Timeout)
	
	// 创建建议器分析配置
	advisor, err := scanner.NewScanAdvisor(problematicConfig)
	if err != nil {
		log.Fatalf("创建建议器失败: %v", err)
	}
	
	fmt.Println("\n📊 配置分析结果:")
	advisor.PrintSuggestions()
	
	// 获取优化后的配置
	optimizedConfig := advisor.GetOptimizedConfig()
	fmt.Println("\n✅ 优化后的配置:")
	fmt.Printf("目标: %s\n", optimizedConfig.Target)
	fmt.Printf("端口: %s\n", optimizedConfig.Ports)
	fmt.Printf("并发: %d (原: %d)\n", optimizedConfig.Workers, problematicConfig.Workers)
	fmt.Printf("超时: %v (原: %v)\n", optimizedConfig.Timeout, problematicConfig.Timeout)
	fmt.Printf("启用OS检测: %v (原: %v)\n", optimizedConfig.EnableOS, problematicConfig.EnableOS)
	
	// 示例2: 推荐的测试配置
	fmt.Println("\n\n2. 推荐的测试配置:")
	recommendedConfig := &scanner.ScanOptions{
		Target:           "scanme.nmap.org",  // 官方测试服务器
		Ports:            "22,80,443,9929",   // 已知开放端口
		ScanType:         scanner.ScanTypeTCP,
		Timeout:          3 * time.Second,
		Workers:          5,                  // 低并发
		EnableService:    true,
		ServiceProbe:     true,
		BannerProbe:      true,
		VersionIntensity: 3,                  // 中等强度
	}
	
	fmt.Printf("目标: %s\n", recommendedConfig.Target)
	fmt.Printf("端口: %s\n", recommendedConfig.Ports)
	fmt.Printf("并发: %d\n", recommendedConfig.Workers)
	fmt.Printf("超时: %v\n", recommendedConfig.Timeout)
	
	// 分析推荐配置
	advisorRecommended, err := scanner.NewScanAdvisor(recommendedConfig)
	if err != nil {
		log.Fatalf("创建建议器失败: %v", err)
	}
	
	fmt.Println("\n📊 推荐配置分析:")
	advisorRecommended.PrintSuggestions()
	
	// 示例3: 本地测试配置
	fmt.Println("\n\n3. 本地测试配置:")
	localConfig := &scanner.ScanOptions{
		Target:           "127.0.0.1",
		Ports:            "1-1000",
		ScanType:         scanner.ScanTypeTCP,
		Timeout:          500 * time.Millisecond,
		Workers:          20,
		EnableService:    true,
		ServiceProbe:     true,
		BannerProbe:      true,
		VersionIntensity: 3,
	}
	
	fmt.Printf("目标: %s\n", localConfig.Target)
	fmt.Printf("端口: %s\n", localConfig.Ports)
	fmt.Printf("并发: %d\n", localConfig.Workers)
	fmt.Printf("超时: %v\n", localConfig.Timeout)
	
	// 分析本地配置
	advisorLocal, err := scanner.NewScanAdvisor(localConfig)
	if err != nil {
		log.Fatalf("创建建议器失败: %v", err)
	}
	
	fmt.Println("\n📊 本地配置分析:")
	advisorLocal.PrintSuggestions()
	
	fmt.Println("\n=== 总结 ===")
	fmt.Println("✅ 工具现在会自动:")
	fmt.Println("   • 检测不合理的参数配置")
	fmt.Println("   • 根据端口数量智能调整并发数")
	fmt.Println("   • 验证系统资源限制")
	fmt.Println("   • 提供优化建议")
	fmt.Println("   • 估算扫描时间")
	fmt.Println("   • 防止资源耗尽")
	
	fmt.Println("\n💡 这样用户就不会遇到:")
	fmt.Println("   • 文件描述符耗尽")
	fmt.Println("   • 内存使用过高")
	fmt.Println("   • 扫描时间过长")
	fmt.Println("   • 被目标服务器限制")
	
	// 可选：实际执行一个小规模测试
	fmt.Println("\n🧪 执行小规模测试扫描...")
	testConfig := &scanner.ScanOptions{
		Target:   "127.0.0.1",
		Ports:    "22,80,443",
		ScanType: scanner.ScanTypeTCP,
		Timeout:  time.Second,
		Workers:  3,
	}
	
	results, err := scanner.ExecuteScan(testConfig)
	if err != nil {
		fmt.Printf("测试扫描失败: %v\n", err)
	} else {
		fmt.Printf("测试扫描完成，发现 %d 个端口结果\n", len(results))
	}
}
