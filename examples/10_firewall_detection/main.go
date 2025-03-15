package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	fmt.Println("防火墙检测示例")
	fmt.Println("======================================")

	// 检查是否使用快速模式
	fastMode := false
	for _, arg := range os.Args {
		if arg == "--fast" || arg == "-f" {
			fastMode = true
			break
		}
	}

	// 定义扫描目标和端口
	target := "scanme.nmap.org"
	var ports string
	if fastMode {
		ports = "22,80,443"
		fmt.Println("使用快速模式 - 仅扫描少量端口 (使用 --fast 参数)")
	} else {
		ports = "21-25,53,80,110,135,139,443,445,3306,3389,8080"
		fmt.Println("使用完整模式 (添加 --fast 参数可加快扫描速度)")
	}

	fmt.Printf("目标: %s\n", target)
	fmt.Printf("端口: %s\n", ports)
	fmt.Println()

	// 定义多种扫描方式
	scanMethods := []struct {
		name        string
		scanType    scanner.ScanType
		ports       string
		description string
	}{
		{
			name:        "TCP Connect扫描",
			scanType:    scanner.ScanTypeTCP,
			ports:       "20-25,80,443",
			description: "完整的TCP连接, 对防火墙最容易检测",
		},
		{
			name:        "SYN半开放扫描",
			scanType:    scanner.ScanTypeSYN,
			ports:       "20-25,80,443",
			description: "仅发送SYN包，不完成完整握手，降低被检测风险",
		},
		{
			name:        "UDP扫描",
			scanType:    scanner.ScanTypeUDP,
			ports:       "53,123,161",
			description: "UDP扫描，能够发现开放的UDP服务",
		},
		{
			name:        "ACK扫描",
			scanType:    scanner.ScanTypeACK,
			ports:       "80,443",
			description: "用于探测防火墙规则，仅发送ACK包",
		},
		{
			name:        "FIN扫描",
			scanType:    scanner.ScanTypeFIN,
			ports:       "80,443",
			description: "发送FIN包，可能绕过某些简单的防火墙",
		},
		{
			name:        "NULL扫描",
			scanType:    scanner.ScanTypeNULL,
			ports:       "80,443",
			description: "发送不带任何标志位的包，尝试绕过防火墙",
		},
		{
			name:        "XMAS扫描",
			scanType:    scanner.ScanTypeXMAS,
			ports:       "80,443",
			description: "发送带有FIN/PSH/URG标志的包，尝试绕过防火墙",
		},
	}

	// 记录扫描结果
	type scanResult struct {
		method    string
		open      int
		closed    int
		filtered  int
		error     error
		duration  time.Duration
		detected  bool // 是否被防火墙检测到
		firewalls []string
	}

	results := make([]scanResult, len(scanMethods))
	var wg sync.WaitGroup

	// 执行所有扫描方法
	for i, method := range scanMethods {
		wg.Add(1)
		go func(idx int, m struct {
			name        string
			scanType    scanner.ScanType
			ports       string
			description string
		}) {
			defer wg.Done()

			fmt.Printf("[%s] 正在执行... (%s)\n", m.name, m.description)
			result := scanResult{
				method: m.name,
			}

			// 创建扫描选项
			scanOptions := &scanner.ScanOptions{
				Target:   target,
				Ports:    m.ports,
				ScanType: m.scanType,
				Timeout:  time.Second * 3,
				Workers:  10,
			}

			// 记录扫描开始时间
			startTime := time.Now()

			// 执行扫描
			scanResults, err := scanner.ExecuteScan(scanOptions)

			// 记录扫描结束时间和持续时间
			result.duration = time.Since(startTime)
			result.error = err

			if err != nil {
				fmt.Printf("[%s] 扫描出错: %v\n", m.name, err)
				results[idx] = result
				return
			}

			// 统计结果
			for _, r := range scanResults {
				switch r.State {
				case scanner.PortStateOpen:
					result.open++
				case scanner.PortStateClosed:
					result.closed++
				case scanner.PortStateFiltered:
					result.filtered++
				}
			}

			// 防火墙检测逻辑
			result.detected = detectFirewall(m.scanType, result.filtered, result.duration, scanResults)
			result.firewalls = guessFirewallType(scanResults, m.scanType, result.filtered, result.duration)

			results[idx] = result
		}(i, method)
	}

	// 等待所有扫描完成
	wg.Wait()

	// 显示扫描结果
	fmt.Println("\n扫描结果汇总:")
	fmt.Println("===============================================")
	fmt.Printf("%-15s %-6s %-6s %-8s %-10s %-10s %s\n",
		"扫描方法", "开放", "关闭", "过滤", "时间(秒)", "防火墙?", "防火墙类型")
	fmt.Println(strings.Repeat("─", 75))

	for _, r := range results {
		detectedStr := "否"
		if r.detected {
			detectedStr = "是"
		}

		firewallTypes := "无"
		if len(r.firewalls) > 0 {
			firewallTypes = ""
			for i, fw := range r.firewalls {
				if i > 0 {
					firewallTypes += ", "
				}
				firewallTypes += fw
			}
		}

		fmt.Printf("%-15s %-6d %-6d %-8d %-10.2f %-10s %s\n",
			r.method, r.open, r.closed, r.filtered, r.duration.Seconds(),
			detectedStr, firewallTypes)

		if r.error != nil {
			fmt.Printf("  └─ 错误: %v\n", r.error)
		}
	}

	// 综合分析
	fmt.Println("\n防火墙和IPS/IDS分析:")
	fmt.Println("===============================================")

	// 分析检测到的防火墙类型
	firewallTypes := make(map[string]int)
	for _, r := range results {
		for _, fw := range r.firewalls {
			firewallTypes[fw]++
		}
	}

	if len(firewallTypes) > 0 {
		fmt.Println("检测到的可能防火墙类型:")
		for fwType, count := range firewallTypes {
			confidence := float64(count) / float64(len(scanMethods)) * 100
			fmt.Printf("  - %s (置信度: %.1f%%)\n", fwType, confidence)
		}
	} else {
		fmt.Println("未检测到明显的防火墙特征")
	}

	// 特殊情况检测
	tcpFiltered := 0
	synFiltered := 0

	for _, r := range results {
		if r.method == "TCP Connect扫描" {
			tcpFiltered = r.filtered
		}
		if r.method == "SYN半开放扫描" {
			synFiltered = r.filtered
		}
	}

	if tcpFiltered > 0 && synFiltered == 0 {
		fmt.Println("\n⚠️ 特殊情况: 完整TCP连接被过滤但SYN扫描成功")
		fmt.Println("这通常表明存在有状态防火墙，但配置为仅阻止完整连接。")
	}

	if tcpFiltered == 0 && synFiltered > 0 {
		fmt.Println("\n⚠️ 特殊情况: SYN扫描被过滤但完整TCP连接成功")
		fmt.Println("这可能表明存在基于行为的入侵防御系统(IPS)在运行。")
	}

	fmt.Println("\n注意: 防火墙检测结果仅供参考，实际网络环境可能更为复杂。")
}

// 基于扫描结果检测防火墙存在
func detectFirewall(scanType scanner.ScanType, filteredCount int, duration time.Duration, results []scanner.ScanResult) bool {
	// 如果大部分端口被过滤，很可能存在防火墙
	if filteredCount > len(results)/2 {
		return true
	}

	// 如果扫描时间异常长，可能存在IPS在阻断或延迟响应
	if duration > 10*time.Second && len(results) < 20 {
		return true
	}

	// 根据扫描类型和结果特征进行判断
	switch scanType {
	case scanner.ScanTypeTCP:
		// TCP扫描对防火墙特征不太敏感
		return filteredCount > 0
	case scanner.ScanTypeSYN:
		// SYN扫描，大量的filtered结果表明存在SYN过滤
		return filteredCount > len(results)/3
	case scanner.ScanTypeACK, scanner.ScanTypeFIN, scanner.ScanTypeNULL, scanner.ScanTypeXMAS:
		// 这些扫描类型都是通过防火墙行为判断
		return filteredCount > 0
	case scanner.ScanTypeUDP:
		// UDP扫描，filtered结果普遍，不一定表示防火墙
		return filteredCount > len(results)*2/3
	default:
		return false
	}
}

// 尝试猜测防火墙类型
func guessFirewallType(results []scanner.ScanResult, scanType scanner.ScanType, filteredCount int, duration time.Duration) []string {
	firewalls := []string{}

	// 根据不同扫描类型的响应特征判断防火墙类型
	switch scanType {
	case scanner.ScanTypeSYN:
		if filteredCount > 0 {
			firewalls = append(firewalls, "状态防火墙")
		}
		if duration > 8*time.Second && len(results) < 15 {
			firewalls = append(firewalls, "速率限制IPS")
		}
	case scanner.ScanTypeACK:
		if filteredCount > len(results)/2 {
			firewalls = append(firewalls, "有状态防火墙")
		}
	case scanner.ScanTypeFIN, scanner.ScanTypeNULL, scanner.ScanTypeXMAS:
		if filteredCount > 0 {
			firewalls = append(firewalls, "Next-Gen防火墙")
		}
	case scanner.ScanTypeUDP:
		if filteredCount > len(results)*2/3 {
			firewalls = append(firewalls, "UDP过滤器")
		}
	}

	// 查找异常模式
	blockAll := true
	for _, r := range results {
		if r.State != scanner.PortStateFiltered {
			blockAll = false
			break
		}
	}

	if blockAll {
		firewalls = append(firewalls, "完全阻断防火墙")
	}

	return firewalls
}
