package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// HostStatus 主机状态
type HostStatus struct {
	IP      string        // IP地址
	Up      bool          // 是否存活
	Method  string        // 发现方法
	Latency time.Duration // 延迟时间
}

// DiscoveryOptions 主机发现选项
type DiscoveryOptions struct {
	ICMPPing    bool          // 是否使用ICMP Ping
	TCPPing     bool          // 是否使用TCP SYN Ping
	ARPScan     bool          // 是否使用ARP扫描(仅适用于本地网络)
	TCPPorts    []int         // TCP Ping使用的端口
	Timeout     time.Duration // 超时时间
	Concurrency int           // 并发数
	SkipPing    bool          // 是否跳过Ping扫描（类似nmap -Pn）
	ExcludeIPs  []string      // 要排除的IP地址
}

// DefaultDiscoveryOptions 默认主机发现选项
func DefaultDiscoveryOptions() *DiscoveryOptions {
	return &DiscoveryOptions{
		ICMPPing:    true,
		TCPPing:     true,
		ARPScan:     false,
		TCPPorts:    []int{80, 443, 22, 445},
		Timeout:     time.Second * 2,
		Concurrency: 100,
		SkipPing:    false,
		ExcludeIPs:  []string{},
	}
}

// DiscoverHosts 发现主机
func DiscoverHosts(networks []string, opts *DiscoveryOptions) ([]HostStatus, error) {
	var results []HostStatus
	var wg sync.WaitGroup
	resultsChan := make(chan HostStatus, 1000)
	limiter := make(chan struct{}, opts.Concurrency)

	// 收集所有IP地址
	var allIPs []string
	for _, network := range networks {
		ips, err := expandNetwork(network)
		if err != nil {
			return nil, fmt.Errorf("解析网段失败 %s: %v", network, err)
		}
		allIPs = append(allIPs, ips...)
	}

	// 过滤掉要排除的IP
	allIPs = filterExcludedIPs(allIPs, opts.ExcludeIPs)

	// 创建工作任务
	for _, ip := range allIPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			limiter <- struct{}{} // 获取令牌
			defer func() {
				<-limiter // 释放令牌
			}()

			// 如果设置了SkipPing，直接进行端口扫描
			if opts.SkipPing {
				if isUp := tcpPing(ip, opts.TCPPorts[0], opts.Timeout); isUp {
					resultsChan <- HostStatus{
						IP:      ip,
						Up:      true,
						Method:  fmt.Sprintf("TCP/%d", opts.TCPPorts[0]),
						Latency: 0,
					}
					return
				}
				resultsChan <- HostStatus{
					IP:      ip,
					Up:      false,
					Method:  "None",
					Latency: 0,
				}
				return
			}

			// 尝试不同的发现方法
			if opts.ICMPPing {
				isUp, latency, _ := pingICMP(ip, opts.Timeout)
				if isUp {
					resultsChan <- HostStatus{
						IP:      ip,
						Up:      true,
						Method:  "ICMP",
						Latency: latency,
					}
					return
				}
			}

			if opts.TCPPing {
				for _, port := range opts.TCPPorts {
					isUp, latency, _ := pingTCP(ip, port, opts.Timeout)
					if isUp {
						resultsChan <- HostStatus{
							IP:      ip,
							Up:      true,
							Method:  fmt.Sprintf("TCP/%d", port),
							Latency: latency,
						}
						return
					}
				}
			}

			if opts.ARPScan {
				isUp, _ := scanARP(ip)
				if isUp {
					resultsChan <- HostStatus{
						IP:      ip,
						Up:      true,
						Method:  "ARP",
						Latency: 0,
					}
					return
				}
			}

			resultsChan <- HostStatus{
				IP:      ip,
				Up:      false,
				Method:  "None",
				Latency: 0,
			}
		}(ip)
	}

	// 等待所有任务完成
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 收集结果
	for result := range resultsChan {
		if result.Up {
			results = append(results, result)
		}
	}

	return results, nil
}

// filterExcludedIPs 过滤掉要排除的IP地址
func filterExcludedIPs(ips []string, excludeIPs []string) []string {
	if len(excludeIPs) == 0 {
		return ips
	}

	// 创建排除IP的map以提高查找效率
	excludeMap := make(map[string]bool)
	for _, ip := range excludeIPs {
		excludeMap[ip] = true
	}

	// 过滤IP列表
	var filtered []string
	for _, ip := range ips {
		if !excludeMap[ip] {
			filtered = append(filtered, ip)
		}
	}

	return filtered
}

// PrintHosts 打印主机发现结果
func PrintHosts(hosts []HostStatus) {
	fmt.Printf("\n主机发现结果：\n")
	fmt.Printf("发现主机数：%d\n", len(hosts))

	if len(hosts) > 0 {
		fmt.Println("\n活跃主机：")
		for _, host := range hosts {
			fmt.Printf("IP: %-15s 方法: %-10s 延迟: %v\n",
				host.IP,
				host.Method,
				host.Latency)
		}
	} else {
		fmt.Println("\n未发现活跃主机")
	}
}

// expandNetwork 展开网段为IP地址列表
func expandNetwork(network string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// inc 增加IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// pingHost 使用ICMP Ping检测主机是否存活
func pingHost(ip string, timeout time.Duration) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%.0f", timeout.Seconds()), ip)
	return cmd.Run() == nil
}

// tcpPing 使用TCP连接检测主机是否存活
func tcpPing(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// arpScan 使用ARP扫描检测主机是否存活
func arpScan(ip string) bool {
	cmd := exec.Command("arping", "-c", "1", ip)
	return cmd.Run() == nil
}

// pingICMP 使用ICMP Ping检测主机
func pingICMP(target string, timeout time.Duration) (bool, time.Duration, error) {
	startTime := time.Now()

	// 使用sendICMP函数，这是我们在syn_scanner.go中实现的函数
	up, err := sendICMP(target, timeout)

	// 如果无法使用原始套接字，尝试系统ping命令
	if err != nil {
		// 使用系统ping命令作为备选方案
		cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%.0f", timeout.Seconds()), target)
		err = cmd.Run()
		if err == nil {
			return true, time.Since(startTime), nil
		}
		return false, 0, err
	}

	return up, time.Since(startTime), nil
}

// pingTCP 使用TCP SYN Ping检测主机
func pingTCP(target string, port int, timeout time.Duration) (bool, time.Duration, error) {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target, port)

	// 尝试TCP连接
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	// 连接成功，主机在线
	latency := time.Since(startTime)
	return true, latency, nil
}

// scanARP 使用ARP扫描检测本地网络主机
// 这只能在具有root权限和对目标网络有直接访问权的情况下工作
func scanARP(target string) (bool, error) {
	// 这是一个简化版实现，实际上应该使用类似gopacket等库来构建和发送ARP请求
	// 由于需要系统权限，这里使用arp系统命令作为示例
	cmd := exec.Command("arp", "-n", target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}

	// 分析输出查找MAC地址
	outputStr := string(output)
	if !strings.Contains(outputStr, "no entry") && strings.Contains(outputStr, ":") {
		return true, nil
	}

	return false, nil
}

// GenerateIPRange 生成IP地址范围
func GenerateIPRange(startIP, endIP string) ([]string, error) {
	// 解析起始IP
	start := net.ParseIP(startIP).To4()
	if start == nil {
		return nil, fmt.Errorf("无效的起始IP: %s", startIP)
	}

	// 解析结束IP
	end := net.ParseIP(endIP).To4()
	if end == nil {
		return nil, fmt.Errorf("无效的结束IP: %s", endIP)
	}

	// 校验IP地址顺序
	for i := 0; i < 4; i++ {
		if end[i] < start[i] {
			return nil, fmt.Errorf("结束IP必须大于起始IP")
		}
		if end[i] > start[i] {
			break
		}
	}

	// 计算IP地址数量
	var total uint32
	total = (uint32(end[0])-uint32(start[0]))*256*256*256 +
		(uint32(end[1])-uint32(start[1]))*256*256 +
		(uint32(end[2])-uint32(start[2]))*256 +
		(uint32(end[3]) - uint32(start[3]) + 1)

	// 为了安全，限制最大IP数量
	if total > 65536 {
		return nil, fmt.Errorf("IP地址范围太大 (最大65536): %d", total)
	}

	// 生成IP列表
	ips := make([]string, 0, total)
	for i := uint32(0); i < total; i++ {
		// 计算当前IP
		current := make(net.IP, 4)
		copy(current, start)

		// 将i添加到起始IP
		for j := 3; j >= 0; j-- {
			current[j] += byte(i % 256)
			i /= 256
		}

		ips = append(ips, current.String())
	}

	return ips, nil
}

// 使用CIDR格式生成IP地址范围
func GenerateIPRangeFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无效的CIDR格式: %s, %v", cidr, err)
	}

	// 获取网络的起始IP和广播IP
	firstIP := ipNet.IP.To4()
	if firstIP == nil {
		return nil, fmt.Errorf("仅支持IPv4地址")
	}

	// 计算广播IP
	mask := ipNet.Mask
	lastIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		lastIP[i] = firstIP[i] | ^mask[i]
	}

	// 生成IP范围
	return GenerateIPRange(firstIP.String(), lastIP.String())
}
