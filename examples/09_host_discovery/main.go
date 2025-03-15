package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// 定义要扫描的相关目标
var targets = []string{
	"scanme.nmap.org",
	"google.com",
	"github.com",
	"nonexistentdomainforsure.com", // 可能不存在的域名
}

// 定义用于主机发现的常用TCP端口
var commonPorts = []int{22, 80, 443, 25, 53}

func main() {
	fmt.Println("主机发现示例 - 使用多种方法检测主机是否在线")
	fmt.Println("===============================================")

	// 创建一个10秒超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	hostResults := make(map[string]map[string]bool)
	resultsMutex := sync.Mutex{}

	// 初始化结果映射
	for _, target := range targets {
		hostResults[target] = make(map[string]bool)
		methods := []string{"ICMP", "TCP", "DNS"}
		for _, method := range methods {
			hostResults[target][method] = false
		}
	}

	// 1. 使用ICMP ping进行发现
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("\n[1] 使用ICMP Ping进行主机发现中...")

		for _, target := range targets {
			ip, err := resolveHost(target)
			if err != nil {
				fmt.Printf("无法解析 %s 的IP地址: %v\n", target, err)
				continue
			}

			// 使用简单的ping命令检测
			alive := pingHost(ip)

			resultsMutex.Lock()
			hostResults[target]["ICMP"] = alive
			resultsMutex.Unlock()

			if alive {
				fmt.Printf("✓ %s (%s) 对ICMP Ping做出响应\n", target, ip)
			} else {
				fmt.Printf("✗ %s (%s) 未对ICMP Ping做出响应\n", target, ip)
			}
		}
	}()

	// 2. 使用TCP端口扫描进行发现
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("\n[2] 使用TCP端口扫描进行主机发现中...")

		for _, target := range targets {
			// 构建端口字符串
			portsStr := ""
			for i, port := range commonPorts {
				if i > 0 {
					portsStr += ","
				}
				portsStr += fmt.Sprintf("%d", port)
			}

			// 创建扫描选项
			scanOptions := &scanner.ScanOptions{
				Target:        target,
				Ports:         portsStr,
				ScanType:      scanner.ScanTypeTCP,
				Timeout:       time.Second * 3,
				Workers:       5,
				EnableService: false, // 只检测端口开放情况，不进行服务识别
			}

			// 执行扫描
			scanResults, err := scanner.ExecuteScan(scanOptions)
			if err != nil {
				fmt.Printf("TCP扫描 %s 失败: %v\n", target, err)
				continue
			}

			// 检查是否有任何开放端口
			openPorts := 0
			for _, result := range scanResults {
				if result.State == scanner.PortStateOpen {
					openPorts++
				}
			}

			isAlive := openPorts > 0
			resultsMutex.Lock()
			hostResults[target]["TCP"] = isAlive
			resultsMutex.Unlock()

			if isAlive {
				fmt.Printf("✓ %s 有 %d 个开放TCP端口，主机在线\n", target, openPorts)
			} else {
				fmt.Printf("✗ %s 没有发现开放的TCP端口\n", target)
			}
		}
	}()

	// 3. 使用DNS解析进行发现
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("\n[3] 使用DNS解析进行主机发现中...")

		for _, target := range targets {
			_, err := net.LookupHost(target)
			isResolvable := err == nil

			resultsMutex.Lock()
			hostResults[target]["DNS"] = isResolvable
			resultsMutex.Unlock()

			if isResolvable {
				ips, _ := net.LookupIP(target)
				ipStr := make([]string, 0, len(ips))
				for _, ip := range ips {
					ipStr = append(ipStr, ip.String())
				}
				fmt.Printf("✓ %s 可以解析DNS: %s\n", target, strings.Join(ipStr, ", "))
			} else {
				fmt.Printf("✗ %s 无法解析DNS: %v\n", target, err)
			}
		}
	}()

	// 启动goroutine来处理超时
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Println("\n[!] 扫描超时 - 已达到最大运行时间 (10秒)")
		}
	}()

	// 等待所有扫描完成
	wg.Wait()

	// 汇总结果
	fmt.Println("\n主机发现汇总结果:")
	fmt.Println("===============================================")
	fmt.Printf("%-30s %-10s %-10s %-10s %-10s\n", "目标", "ICMP", "TCP", "DNS", "综合判断")
	fmt.Println(strings.Repeat("-", 70))

	for _, target := range targets {
		icmpAlive := hostResults[target]["ICMP"]
		tcpAlive := hostResults[target]["TCP"]
		dnsAlive := hostResults[target]["DNS"]

		// 综合判断主机是否在线（至少一种方法成功）
		isAlive := icmpAlive || tcpAlive || dnsAlive

		fmt.Printf("%-30s %-10s %-10s %-10s %-10s\n",
			target,
			formatBool(icmpAlive),
			formatBool(tcpAlive),
			formatBool(dnsAlive),
			formatAliveStatus(isAlive))
	}

	fmt.Println("\n注: 不同的网络环境和防火墙配置可能导致某些探测方法失败，即使主机实际在线")
}

// 使用系统ping命令检测主机是否在线
func pingHost(ip string) bool {
	// 根据不同的操作系统选择不同的ping参数
	cmd := exec.Command("ping", "-c", "1", "-W", "3", ip)

	// 执行ping命令
	err := cmd.Run()
	return err == nil // 如果命令成功返回，则认为主机在线
}

// 解析主机获取IP
func resolveHost(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}

	// 优先返回IPv4地址
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// 如果没有IPv4地址，返回第一个IP
	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("无法解析IP地址")
}

// 格式化布尔值显示
func formatBool(value bool) string {
	if value {
		return "在线"
	}
	return "离线"
}

// 格式化在线状态
func formatAliveStatus(alive bool) string {
	if alive {
		return "在线 ✓"
	}
	return "离线 ✗"
}
