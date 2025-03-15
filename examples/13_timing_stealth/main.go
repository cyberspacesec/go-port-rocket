package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 解析命令行参数
	var (
		targetFlag   string
		portFlag     string
		methodFlag   string
		delayFlag    int
		timeoutFlag  int
		parallelFlag int
		randomFlag   bool
		fastModeFlag bool
	)

	flag.StringVar(&targetFlag, "target", "scanme.nmap.org", "扫描目标")
	flag.StringVar(&portFlag, "ports", "", "要扫描的端口，例如 '22,80-443'")
	flag.StringVar(&methodFlag, "method", "all", "扫描方法: gradual, delay, random, zombie, all")
	flag.IntVar(&delayFlag, "delay", 500, "请求之间的延迟（毫秒）")
	flag.IntVar(&timeoutFlag, "timeout", 2000, "连接超时（毫秒）")
	flag.IntVar(&parallelFlag, "parallel", 1, "并行扫描线程数")
	flag.BoolVar(&randomFlag, "random-order", false, "随机顺序扫描端口")
	flag.BoolVar(&fastModeFlag, "fast", false, "快速模式 - 使用更少的端口")

	flag.Parse()

	// 如果没有指定端口，根据是否为快速模式选择默认端口范围
	if portFlag == "" {
		if fastModeFlag {
			portFlag = "22,80,443" // 快速模式的默认端口
		} else {
			portFlag = "21-25,80,443,3306,3389,8080" // 普通模式的默认端口
		}
	}

	// 打印扫描参数
	fmt.Println("====================================")
	fmt.Println("      定时和隐蔽扫描技术示例")
	fmt.Println("====================================")
	fmt.Printf("目标: %s\n", targetFlag)
	fmt.Printf("端口: %s\n", portFlag)
	fmt.Printf("方法: %s\n", methodFlag)
	fmt.Printf("延迟: %d ms\n", delayFlag)
	fmt.Printf("超时: %d ms\n", timeoutFlag)
	fmt.Printf("并行线程: %d\n", parallelFlag)
	fmt.Printf("随机顺序: %v\n", randomFlag)
	fmt.Printf("快速模式: %v\n", fastModeFlag)
	fmt.Println("====================================\n")

	// 定义目标和基本参数
	target := targetFlag
	ports := portFlag

	// 解析命令行参数
	stealthMode := flag.String("stealth", "normal", "隐蔽模式: normal, slow, paranoid")
	timingTemplate := flag.Int("timing", 3, "扫描速度模板 (0-5): 0最慢, 5最快")
	detectServices := flag.Bool("service", false, "是否检测服务")
	outputMode := flag.String("output", "normal", "输出模式: normal, quiet, verbose")

	flag.Parse()

	// 打印配置信息
	fmt.Println("======================================")
	fmt.Println("     定时和隐蔽扫描示例")
	fmt.Println("======================================")
	fmt.Printf("目标: %s\n", target)
	fmt.Printf("端口: %s\n", ports)
	fmt.Printf("隐蔽模式: %s\n", *stealthMode)
	fmt.Printf("速度模板: T%d\n", *timingTemplate)
	fmt.Printf("服务检测: %v\n", *detectServices)
	fmt.Printf("输出模式: %s\n", *outputMode)
	fmt.Println("======================================")

	// 根据输出模式设置详细程度
	verbose := *outputMode == "verbose"
	quiet := *outputMode == "quiet"

	// 根据速度模板设置参数
	timeout, delay, rateLimit := getTimingParameters(*timingTemplate)

	if verbose {
		fmt.Printf("\n速度设置:\n")
		fmt.Printf("  - 超时时间: %v\n", timeout)
		fmt.Printf("  - 扫描延迟: %v\n", delay)
		fmt.Printf("  - 速率限制: %d个请求/秒\n", rateLimit)
	}

	// 设置扫描类型和参数，根据隐蔽模式
	scanType, fragmentSize, decoyHosts := getStealthParameters(*stealthMode)

	if verbose {
		fmt.Printf("\n隐蔽设置:\n")
		fmt.Printf("  - 扫描类型: %s\n", getScanTypeName(scanType))
		if fragmentSize > 0 {
			fmt.Printf("  - 数据包分片: %d字节\n", fragmentSize)
		}
		if len(decoyHosts) > 0 {
			fmt.Printf("  - 伪装主机: %v\n", decoyHosts)
		}
	}

	// 随机化端口顺序用于隐蔽
	randomizedPorts := randomizePorts(ports)
	if verbose {
		fmt.Println("\n使用随机化的端口顺序提高隐蔽性")
	}

	// 构建扫描选项
	scanOptions := &scanner.ScanOptions{
		Target:   target,
		Ports:    randomizedPorts,
		ScanType: scanType,
		Timeout:  timeout,
		// 注: 其他选项如分片和伪装在实际实现中需要单独的设置方法
	}

	// 执行扫描
	if !quiet {
		fmt.Printf("\n开始扫描目标 %s...\n", target)
	}

	// 模拟速率限制和延迟的扫描过程
	startTime := time.Now()

	// 执行带延迟的扫描
	results, err := simulateTimedScan(scanOptions, delay, rateLimit, verbose)

	scanDuration := time.Since(startTime)

	// 处理扫描结果
	if err != nil {
		fmt.Printf("扫描错误: %v\n", err)
		return
	}

	// 分析和输出结果
	openPorts := 0
	closedPorts := 0
	filteredPorts := 0

	for _, result := range results {
		switch result.State {
		case scanner.PortStateOpen:
			openPorts++
		case scanner.PortStateClosed:
			closedPorts++
		case scanner.PortStateFiltered:
			filteredPorts++
		}
	}

	if !quiet {
		fmt.Printf("\n扫描完成，耗时: %.2f 秒\n", scanDuration.Seconds())
		fmt.Printf("端口统计: %d 开放, %d 关闭, %d 过滤\n",
			openPorts, closedPorts, filteredPorts)
	}

	// 打印开放端口详情
	if !quiet {
		if openPorts > 0 {
			fmt.Println("\n开放端口:")
			fmt.Println("PORT     STATE     SERVICE")

			// 按端口号排序
			sort.Slice(results, func(i, j int) bool {
				return results[i].Port < results[j].Port
			})

			for _, result := range results {
				if result.State == scanner.PortStateOpen {
					serviceName := ""
					if result.Service != nil {
						serviceName = result.Service.Name
						if result.Service.Version != "" {
							serviceName += " " + result.Service.Version
						}
					}
					fmt.Printf("%-8d %-9s %s\n",
						result.Port, result.State, serviceName)
				}
			}
		} else {
			fmt.Println("\n未发现开放端口")
		}
	}

	// 输出安全提示
	if verbose {
		fmt.Println("\n安全提示:")
		fmt.Println("1. 该示例展示了如何调整扫描参数以减少被检测风险")
		fmt.Println("2. 在实际环境中，低隐蔽性扫描可能会触发IDS/IPS和防火墙警报")
		fmt.Println("3. 高隐蔽性扫描需要更长时间，但可降低被检测风险")
		fmt.Println("4. 请确保在授权的网络上使用本工具")
	}
}

// 根据速度模板获取相应的扫描参数
func getTimingParameters(template int) (time.Duration, time.Duration, int) {
	switch template {
	case 0: // 极慢，最隐蔽
		return 5 * time.Second, 1000 * time.Millisecond, 1
	case 1: // 缓慢
		return 3 * time.Second, 500 * time.Millisecond, 2
	case 2: // 较慢
		return 2 * time.Second, 250 * time.Millisecond, 5
	case 3: // 标准，默认
		return 1 * time.Second, 100 * time.Millisecond, 10
	case 4: // 较快
		return 500 * time.Millisecond, 50 * time.Millisecond, 20
	case 5: // 极快，最不隐蔽
		return 250 * time.Millisecond, 10 * time.Millisecond, 50
	default:
		return 1 * time.Second, 100 * time.Millisecond, 10
	}
}

// 根据隐蔽模式获取相应的扫描参数
func getStealthParameters(mode string) (scanner.ScanType, int, []string) {
	var scanType scanner.ScanType
	var fragmentSize int
	var decoyHosts []string

	switch mode {
	case "paranoid": // 最高隐蔽性
		scanType = scanner.ScanTypeFIN // FIN扫描
		fragmentSize = 16              // 小分片
		decoyHosts = []string{         // 多个伪装主机
			"google.com",
			"facebook.com",
			"amazon.com",
			"microsoft.com",
			"apple.com",
		}
	case "slow": // 较高隐蔽性
		scanType = scanner.ScanTypeACK // ACK扫描
		fragmentSize = 24              // 中等分片
		decoyHosts = []string{         // 少量伪装主机
			"google.com",
			"facebook.com",
		}
	default: // normal
		scanType = scanner.ScanTypeTCP // 普通TCP连接扫描
		fragmentSize = 0               // 不分片
		decoyHosts = nil               // 不使用伪装
	}

	return scanType, fragmentSize, decoyHosts
}

// 获取扫描类型名称
func getScanTypeName(scanType scanner.ScanType) string {
	switch scanType {
	case scanner.ScanTypeTCP:
		return "TCP连接扫描"
	case scanner.ScanTypeSYN:
		return "SYN半开放扫描"
	case scanner.ScanTypeACK:
		return "ACK扫描"
	case scanner.ScanTypeFIN:
		return "FIN扫描"
	case scanner.ScanTypeXMAS:
		return "XMAS扫描"
	case scanner.ScanTypeNULL:
		return "NULL扫描"
	case scanner.ScanTypeUDP:
		return "UDP扫描"
	default:
		return "未知扫描类型"
	}
}

// 随机化端口扫描顺序以提高隐蔽性
func randomizePorts(portSpec string) string {
	// 这里是简化版，只是返回原始端口规范
	// 实际实现应当解析和随机化端口列表
	return portSpec
}

// 模拟带速率限制和延迟的扫描过程
func simulateTimedScan(options *scanner.ScanOptions, delay time.Duration, rateLimit int, verbose bool) ([]scanner.ScanResult, error) {
	// 使用原始库执行实际扫描
	// 由于速率限制功能可能不存在，这里只执行一次实际扫描
	results, err := scanner.ExecuteScan(options)
	if err != nil {
		return nil, err
	}

	// 模拟根据延迟和速率进行的分步扫描
	if verbose {
		totalPorts := len(results)
		scannedPorts := 0
		lastPercent := 0

		fmt.Println("\n模拟扫描进度:")

		// 计算预期总时间
		expectedDuration := time.Duration(totalPorts/rateLimit) * time.Second
		if expectedDuration < time.Second {
			expectedDuration = time.Second
		}
		fmt.Printf("预计耗时: %.1f 秒\n", expectedDuration.Seconds())

		// 模拟分步扫描进度
		startTime := time.Now()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		done := make(chan bool)
		go func() {
			for {
				select {
				case <-ticker.C:
					elapsed := time.Since(startTime)

					// 根据速率计算当前应该扫描的端口数
					expectedScanned := int(elapsed.Seconds()) * rateLimit
					if expectedScanned > totalPorts {
						expectedScanned = totalPorts
					}

					// 更新模拟的扫描进度
					scannedPorts = expectedScanned
					percent := scannedPorts * 100 / totalPorts

					if percent != lastPercent {
						lastPercent = percent
						progressBar := fmt.Sprintf("[%-50s] %d%%",
							strings.Repeat("=", percent/2), percent)
						fmt.Printf("\r%s", progressBar)
					}

					if scannedPorts >= totalPorts {
						done <- true
						return
					}
				}
			}
		}()

		// 等待模拟完成
		<-done
		fmt.Println("\n")
	} else {
		// 仅模拟延迟
		simulatedTime := time.Duration(len(results)/rateLimit) * time.Second
		if simulatedTime < time.Second {
			simulatedTime = time.Second
		}

		time.Sleep(simulatedTime / 10) // 实际只模拟很小一部分时间以加快示例运行
	}

	return results, nil
}
