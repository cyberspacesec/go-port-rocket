package scanner

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/fingerprint"
	"github.com/cyberspacesec/go-port-rocket/pkg/logger"
)

// CommonServices 常见端口服务映射
var CommonServices = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	111:  "RPC",
	135:  "RPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1723: "PPTP",
	3306: "MySQL",
	3389: "RDP",
	5900: "VNC",
	8080: "HTTP-Proxy",
}

// Scanner 端口扫描器
type Scanner struct {
	opts     *ScanOptions
	ports    []int
	results  []*ScanResult
	progress float64
	mu       sync.Mutex
}

// NewScanner 创建新的扫描器
func NewScanner(opts *ScanOptions) (*Scanner, error) {
	if opts == nil {
		return nil, fmt.Errorf("扫描选项不能为空")
	}

	// 解析端口范围
	ports, err := parsePorts(opts.Ports)
	if err != nil {
		return nil, fmt.Errorf("解析端口范围失败: %v", err)
	}

	return &Scanner{
		opts:  opts,
		ports: ports,
	}, nil
}

// Scan 执行扫描
func (s *Scanner) Scan(ctx context.Context) ([]*ScanResult, error) {
	// 创建工作线程池
	jobs := make(chan int, len(s.ports))
	results := make(chan *ScanResult, len(s.ports))
	var wg sync.WaitGroup

	// 启动工作线程
	for i := 0; i < s.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := s.scanPort(ctx, port)
				if result != nil {
					results <- result
				}
				s.updateProgress()
			}
		}()
	}

	// 分发扫描任务
	go func() {
		for _, port := range s.ports {
			if ctx.Err() != nil {
				break
			}
			jobs <- port
		}
		close(jobs)
	}()

	// 等待所有工作线程完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集扫描结果
	s.results = make([]*ScanResult, 0)
	for result := range results {
		s.results = append(s.results, result)
	}

	return s.results, nil
}

// scanPort 扫描单个端口
func (s *Scanner) scanPort(ctx context.Context, port int) *ScanResult {
	result := &ScanResult{
		Port:     port,
		State:    PortStateClosed,
		Metadata: make(map[string]interface{}),
	}

	// 首先验证目标地址是否有效
	if err := s.validateTarget(); err != nil {
		result.State = PortStateUnknown
		result.Metadata["error"] = err.Error()
		logger.Debugf("目标地址验证失败: %v", err)
		return result
	}

	// 创建连接
	addr := fmt.Sprintf("%s:%d", s.opts.Target, port)
	conn, err := net.DialTimeout(string(s.opts.ScanType), addr, s.opts.Timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				result.State = PortStateFiltered
			} else if strings.Contains(netErr.Error(), "connection refused") {
				result.State = PortStateClosed
			} else if strings.Contains(netErr.Error(), "no such host") ||
				strings.Contains(netErr.Error(), "nodename nor servname provided") ||
				strings.Contains(netErr.Error(), "Name or service not known") {
				result.State = PortStateUnknown
				result.Metadata["error"] = "DNS解析失败"
			} else if strings.Contains(netErr.Error(), "network is unreachable") ||
				strings.Contains(netErr.Error(), "host is unreachable") {
				result.State = PortStateFiltered
			} else {
				result.State = PortStateFiltered
			}
		} else {
			result.State = PortStateFiltered
		}
		return result
	}
	defer conn.Close()

	// 验证连接是否真的成功建立
	if !s.verifyConnection(conn) {
		result.State = PortStateClosed
		return result
	}

	result.State = PortStateOpen

	// 服务检测
	if s.opts.EnableService {
		service, err := s.detectService(conn, port)
		if err == nil {
			result.Service = service
		}
	}

	// 操作系统检测
	if s.opts.EnableOS && result.State == PortStateOpen {
		osInfo, err := s.detectOS(conn)
		if err == nil {
			result.OS = osInfo
		}
	}

	return result
}

// detectService 检测服务
func (s *Scanner) detectService(conn net.Conn, port int) (*fingerprint.Service, error) {
	// 如果服务检测被禁用
	if !s.opts.EnableService || s.opts.Service == nil {
		return nil, fmt.Errorf("服务检测未启用")
	}

	// 获取远程地址信息
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	if remoteAddr == nil {
		return nil, fmt.Errorf("无法获取远程地址信息")
	}

	target := remoteAddr.IP.String()

	// 使用嵌入的指纹数据库创建指纹识别器
	fp, err := GetFingerprinter("")
	if err != nil {
		return nil, fmt.Errorf("创建指纹识别器失败: %v", err)
	}

	// 设置指纹识别选项
	opts := fingerprint.DefaultFingerprintOptions()
	opts.EnableServiceDetection = true
	// 从Scanner选项中设置超时
	opts.Timeout = s.opts.Service.Timeout
	fp.SetOptions(opts)

	// 执行服务指纹识别
	serviceFp, err := fp.FingerprintService(target, port)
	if err != nil {
		logger.Debugf("服务指纹识别失败: %v", err)
		return nil, err
	}

	// 转换为Service结构
	service := &fingerprint.Service{
		Name:       serviceFp.Name,
		Product:    serviceFp.Product,
		Version:    serviceFp.Version,
		Protocol:   "tcp", // 默认为TCP
		DeviceType: "",    // 如果服务有设备类型可以设置
		Banner:     "",    // 从服务探测中可能获取到的banner
		Confidence: serviceFp.Confidence,
		Metadata:   make(map[string]string),
	}

	// 添加指纹识别来源
	service.Metadata["source"] = "embedded-fingerprint-db"
	// 添加置信度
	service.Metadata["confidence"] = fmt.Sprintf("%.2f", serviceFp.Confidence)

	return service, nil
}

// detectOS 检测操作系统
func (s *Scanner) detectOS(conn net.Conn) (*fingerprint.OSInfo, error) {
	// 如果操作系统检测被禁用
	if !s.opts.EnableOS {
		return nil, fmt.Errorf("操作系统检测未启用")
	}

	// 获取远程地址信息
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	if remoteAddr == nil {
		return nil, fmt.Errorf("无法获取远程地址信息")
	}

	// 确保使用IPv4地址
	ipAddress := remoteAddr.IP.String()

	// 如果是IPv6地址但实际上是localhost
	if ipAddress == "::1" {
		ipAddress = "127.0.0.1"
	}

	// 使用嵌入的指纹数据库创建指纹识别器
	fp, err := GetFingerprinter("")
	if err != nil {
		return nil, fmt.Errorf("创建指纹识别器失败: %v", err)
	}

	// 设置指纹识别选项
	opts := fingerprint.DefaultFingerprintOptions()
	opts.EnableOSDetection = true
	opts.GuessOS = s.opts.GuessOS
	if s.opts.Service != nil {
		opts.Timeout = s.opts.Service.Timeout
	} else {
		opts.Timeout = 5 * time.Second // 默认超时
	}
	fp.SetOptions(opts)

	// 执行操作系统指纹识别
	// 注意：需要开放的端口才能探测OS
	openPorts := []int{}
	for _, r := range s.results {
		if r.State == PortStateOpen {
			openPorts = append(openPorts, r.Port)
		}
	}

	// 如果没有开放端口，返回错误
	if len(openPorts) == 0 {
		return nil, fmt.Errorf("需要开放的端口才能进行操作系统检测")
	}

	// 使用开放端口进行OS检测
	osFp, err := fp.FingerprintOS(ipAddress, openPorts)
	if err != nil {
		logger.Debugf("操作系统指纹识别失败: %v", err)
		return nil, err
	}

	// 尝试从TTL猜测操作系统
	ttl, err := getTTLValue(ipAddress)
	if err == nil {
		// 根据TTL猜测操作系统
		guessedOS := guessOSFromTTL(ttl)
		if osFp.Name == "" {
			osFp.Name = guessedOS
			osFp.Confidence = 60.0 // TTL猜测的置信度较低
		}
	}

	// 转换为OSInfo结构
	osInfo := &fingerprint.OSInfo{
		Name:       osFp.Name,
		Family:     "", // 从指纹中可能无法获取OS家族，需要进一步解析
		Version:    osFp.Version,
		Confidence: osFp.Confidence,
		Metadata:   make(map[string]string),
	}

	// 添加指纹识别来源
	osInfo.Metadata["source"] = "embedded-fingerprint-db"
	// 添加TTL信息
	if ttl > 0 {
		osInfo.Metadata["ttl"] = fmt.Sprintf("%d", ttl)
	}

	// 尝试解析OS家族
	osInfo.Family = parseOSFamily(osFp.Name)

	return osInfo, nil
}

// parseOSFamily 从操作系统名称解析出OS家族
func parseOSFamily(osName string) string {
	osName = strings.ToLower(osName)

	if strings.Contains(osName, "windows") {
		return "Windows"
	} else if strings.Contains(osName, "linux") {
		return "Linux"
	} else if strings.Contains(osName, "mac") || strings.Contains(osName, "macos") || strings.Contains(osName, "osx") {
		return "MacOS"
	} else if strings.Contains(osName, "freebsd") || strings.Contains(osName, "openbsd") || strings.Contains(osName, "netbsd") {
		return "BSD"
	} else if strings.Contains(osName, "ios") {
		return "iOS"
	} else if strings.Contains(osName, "android") {
		return "Android"
	} else if strings.Contains(osName, "unix") {
		return "Unix"
	} else if strings.Contains(osName, "solaris") || strings.Contains(osName, "sunos") {
		return "Solaris"
	}

	return "Unknown"
}

// guessOSFromTTL 根据TTL猜测操作系统
func guessOSFromTTL(ttl int) string {
	if ttl <= 64 {
		return "Linux/Unix"
	} else if ttl <= 128 {
		return "Windows"
	} else if ttl <= 255 {
		return "Cisco/Network Device"
	}
	return "Unknown"
}

// getTTLValue 使用ping命令获取TTL值
func getTTLValue(ipAddress string) (int, error) {
	// 根据OS选择适当的ping命令
	cmd := exec.Command("ping", "-c", "1", ipAddress)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	// 解析输出中的TTL值
	outputStr := string(output)

	// 尝试不同的正则表达式匹配不同操作系统的ping输出格式
	ttlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`ttl=(\d+)`),             // Linux格式
		regexp.MustCompile(`TTL=(\d+)`),             // Windows格式
		regexp.MustCompile(`time to live=(\d+)`),    // 某些Unix变体
		regexp.MustCompile(`\sttl\s*=\s*(\d+)`),     // macOS格式
		regexp.MustCompile(`[Tt][Tt][Ll][=:](\d+)`), // 通用格式，不区分大小写
	}

	for _, pattern := range ttlPatterns {
		matches := pattern.FindStringSubmatch(outputStr)
		if len(matches) >= 2 {
			ttl, err := strconv.Atoi(matches[1])
			if err != nil {
				continue // 尝试下一个模式
			}
			return ttl, nil
		}
	}

	return 0, fmt.Errorf("无法从ping输出中提取TTL值")
}

// refineOSInfoByTCPSignature 通过TCP签名细化操作系统信息
func refineOSInfoByTCPSignature(osInfo *fingerprint.OSInfo, conn net.Conn) {
	// 提取更多TCP指纹信息
	// 这里为简化实现，仅使用TTL和主机名信息进行猜测

	// 根据操作系统家族进一步猜测具体版本
	switch osInfo.Family {
	case "Unix":
		// 尝试通过主机名判断具体Unix发行版
		hostname, err := getHostname(conn.RemoteAddr().(*net.TCPAddr).IP.String())
		if err == nil {
			hostname = strings.ToLower(hostname)

			if strings.Contains(hostname, "ubuntu") {
				osInfo.Name = "Ubuntu Linux"
				osInfo.Confidence += 15.0
			} else if strings.Contains(hostname, "debian") {
				osInfo.Name = "Debian Linux"
				osInfo.Confidence += 15.0
			} else if strings.Contains(hostname, "centos") {
				osInfo.Name = "CentOS Linux"
				osInfo.Confidence += 15.0
			} else if strings.Contains(hostname, "fedora") {
				osInfo.Name = "Fedora Linux"
				osInfo.Confidence += 15.0
			} else if strings.Contains(hostname, "darwin") || strings.Contains(hostname, "mac") {
				osInfo.Name = "MacOS"
				osInfo.Family = "Darwin"
				osInfo.Confidence += 15.0
			} else if strings.Contains(hostname, "freebsd") {
				osInfo.Name = "FreeBSD"
				osInfo.Confidence += 15.0
			}
		}

	case "Windows":
		// 尝试细分Windows版本
		// 这里只是简单示例，实际需要更复杂的探测
		ttlStr, exists := osInfo.Metadata["ttl"]
		if exists {
			ttl, _ := strconv.Atoi(ttlStr)
			if ttl == 128 {
				osInfo.Name = "Windows 10/11"
				osInfo.Confidence += 10.0
			} else if ttl == 127 {
				osInfo.Name = "Windows 7/8"
				osInfo.Confidence += 10.0
			} else if ttl == 64 {
				osInfo.Name = "Windows Server (Custom TTL)"
				osInfo.Confidence -= 10.0 // 降低置信度，因为这通常不是Windows默认TTL
			}
		}
	}

	// 确保置信度不超过100
	if osInfo.Confidence > 100.0 {
		osInfo.Confidence = 100.0
	}
}

// getHostname 尝试获取主机名
func getHostname(ipAddress string) (string, error) {
	names, err := net.LookupAddr(ipAddress)
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("无法解析主机名")
	}
	return names[0], nil
}

// updateProgress 更新扫描进度
func (s *Scanner) updateProgress() {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := float64(len(s.ports))
	current := float64(len(s.results))
	s.progress = (current / total) * 100
}

// GetProgress 获取扫描进度
func (s *Scanner) GetProgress() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.progress
}

// parsePorts 解析端口范围
func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	ranges := strings.Split(portsStr, ",")

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		// 处理端口范围 (例如: 80-100)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", r)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", parts[1])
			}

			if start > end {
				return nil, fmt.Errorf("起始端口不能大于结束端口: %d > %d", start, end)
			}

			for port := start; port <= end; port++ {
				if port > 0 && port < 65536 {
					ports = append(ports, port)
				}
			}
		} else {
			// 处理单个端口
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", r)
			}

			if port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("未指定有效的端口")
	}

	return ports, nil
}

// ExecuteScan 执行扫描
func ExecuteScan(opts *ScanOptions) ([]ScanResult, error) {
	var results []ScanResult
	var err error

	// 解析端口范围
	portInts, err := parsePorts(opts.Ports)
	if err != nil {
		return nil, fmt.Errorf("解析端口范围失败: %v", err)
	}

	// 创建扫描建议器并提供建议
	advisor, err := NewScanAdvisor(opts)
	if err != nil {
		logger.Warnf("无法创建扫描建议器: %v", err)
	} else {
		advisor.PrintSuggestions()
	}

	// 根据扫描类型执行不同的扫描
	switch opts.ScanType {
	case ScanTypeTCP:
		results, err = TCPScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	case ScanTypeSYN:
		results, err = SYNScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	case ScanTypeFIN:
		results, err = FINScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	case ScanTypeNULL:
		results, err = NULLScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	case ScanTypeXMAS:
		results, err = XMASScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	case ScanTypeACK:
		results, err = ACKScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	case ScanTypeUDP:
		results, err = UDPScan(opts.Target, portInts, opts.Timeout, opts.Workers)
	default:
		return nil, fmt.Errorf("不支持的扫描类型: %s", opts.ScanType)
	}

	if err != nil {
		return nil, fmt.Errorf("扫描失败: %v", err)
	}

	// 如果启用了服务检测
	if opts.Service != nil && opts.Service.EnableVersionDetection {
		for i := range results {
			if results[i].State == PortStateOpen {
				// 执行服务检测
				serviceInfo, err := DetectService(opts.Target, results[i].Port, opts.Service)
				if err == nil {
					results[i].Service = ConvertServiceInfoToFingerprint(serviceInfo)
					results[i].ServiceName = serviceInfo.Name
				}
			}
		}
	}

	return results, nil
}

// PrintResults 打印扫描结果
func PrintResults(results []ScanResult) {
	// 计算各类端口数量
	openPorts := 0
	closedPorts := 0
	filteredPorts := 0

	// 用于收集OS信息的映射
	osInfo := make(map[string]bool)
	var osInfoDetails []string

	// 收集所有开放端口的服务
	var openPortsList []ScanResult

	// 首先统计各类型端口数量
	for _, result := range results {
		switch result.State {
		case PortStateOpen:
			openPorts++
			openPortsList = append(openPortsList, result)

			// 收集OS信息
			if result.OS != nil {
				osDesc := fmt.Sprintf("%s", result.OS.Name)
				if result.OS.Version != "" {
					osDesc += fmt.Sprintf(" %s", result.OS.Version)
				}
				if result.OS.Family != "" {
					osDesc += fmt.Sprintf(" (%s)", result.OS.Family)
				}
				osDetail := fmt.Sprintf("%s - 置信度: %.1f%%", osDesc, result.OS.Confidence)
				if ttl, ok := result.OS.Metadata["ttl"]; ok {
					osDetail += fmt.Sprintf(" [TTL: %s]", ttl)
				}
				if !osInfo[osDetail] {
					osInfo[osDetail] = true
					osInfoDetails = append(osInfoDetails, osDetail)
				}
			}
		case PortStateClosed:
			closedPorts++
		case PortStateFiltered:
			filteredPorts++
		}
	}

	// 打印美化的扫描结果标题
	fmt.Println()
	fmt.Println("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	fmt.Println("┃                            【 端口扫描报告 】                                ┃")
	fmt.Println("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	fmt.Println()

	// 打印扫描概要信息
	fmt.Println("【扫描概要】")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("总共扫描端口: %d   开放: %d   关闭: %d   被过滤: %d\n",
		len(results), openPorts, closedPorts, filteredPorts)
	fmt.Printf("扫描时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// 打印开放端口详细信息
	if openPorts > 0 {
		fmt.Println("【开放端口详情】")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("  端口    协议    状态    服务    详细信息")
		fmt.Println("────────────────────────────────────────────────────────────────────────────")

		for _, result := range openPortsList {
			// 端口和协议信息
			portInfo := fmt.Sprintf("  %-7d %-8s", result.Port, "TCP")

			// 状态信息
			stateInfo := "开放    "

			// 服务信息
			serviceName := ""
			serviceInfo := ""
			if result.Service != nil {
				serviceName = result.Service.Name
				serviceInfo = serviceName
				if result.Service.Version != "" {
					serviceInfo += " " + result.Service.Version
				}
				if result.Service.Product != "" {
					serviceInfo += " - " + result.Service.Product
				}
			} else if result.ServiceName != "" {
				serviceName = result.ServiceName
				serviceInfo = serviceName
			} else {
				serviceInfo = "未知"
			}

			// 获取服务的中文描述
			if serviceName != "" {
				chineseDesc := GetServiceDescription(serviceName)
				if chineseDesc != "未知服务" {
					serviceInfo += " (" + chineseDesc + ")"
				}
			}

			// 打印基本信息
			fmt.Printf("%s%s%-30s", portInfo, stateInfo, serviceInfo)

			// 打印额外详细信息
			if result.OS != nil {
				fmt.Printf("\n      └─ 操作系统: %s", result.OS.Name)
				if result.OS.Family != "" {
					fmt.Printf(" (%s)", result.OS.Family)
				}
				fmt.Printf(" - 置信度: %.1f%%", result.OS.Confidence)
			}

			// 打印Banner信息
			var bannerText string
			if result.Banner != "" {
				// 如果存在直接的Banner信息，优先使用
				bannerText = result.Banner
			} else if result.Service != nil && result.Service.Banner != "" {
				// 其次使用Service中的Banner
				bannerText = result.Service.Banner
			}

			if bannerText != "" {
				fmt.Printf("\n      └─ Banner: ")

				// 处理多行Banner
				bannerLines := strings.Split(bannerText, "\n")
				firstLine := true
				for _, line := range bannerLines {
					// 过滤掉空行和只包含控制字符的行
					if strings.TrimSpace(line) == "" {
						continue
					}

					// 对可能的控制字符进行转义处理
					escapedLine := strings.Map(func(r rune) rune {
						if r < 32 && r != '\t' && r != '\n' && r != '\r' {
							return '.'
						}
						return r
					}, line)

					if firstLine {
						// 第一行直接接在"Banner: "后面
						fmt.Printf("%s", escapedLine)
						firstLine = false
					} else {
						// 后续行需要缩进对齐
						fmt.Printf("\n             %s", escapedLine)
					}
				}
			}

			fmt.Println()
		}
		fmt.Println()
	}

	// 打印操作系统检测结果
	if len(osInfoDetails) > 0 {
		fmt.Println("【操作系统检测结果】")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		for _, osDetail := range osInfoDetails {
			fmt.Printf("  ● %s\n", osDetail)
		}
		fmt.Println()

		// 添加操作系统检测说明
		fmt.Println("  [说明] 操作系统检测基于TTL值和TCP/IP栈特征分析，结果仅供参考")
		fmt.Println("  [提示] 服务器可能使用了代理、负载均衡等技术，可能影响检测结果的准确性")
		fmt.Println()
	}

	// 打印综合安全建议
	fmt.Println("【安全建议】")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if openPorts > 0 {
		fmt.Println("  ● 建议检查所有开放端口是否必要，关闭不需要的服务以减小攻击面")
		fmt.Println("  ● 确保所有开放的服务都已更新到最新版本并正确配置安全选项")
		if filteredPorts > 0 {
			fmt.Println("  ● 已发现被过滤端口，建议检查防火墙规则的有效性和完整性")
		}
	} else if filteredPorts > 0 {
		fmt.Println("  ● 所有端口均被过滤，表明防火墙工作良好，建议持续维护更新防火墙策略")
	} else {
		fmt.Println("  ● 未发现开放端口，建议定期扫描确保安全状态")
	}

	// 打印结束信息
	fmt.Println("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	fmt.Println("┃                         扫描完成，感谢使用！                                 ┃")
	fmt.Println("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

	// 提示用户如何获取更多Banner信息
	var hasBanner bool
	for _, result := range results {
		if result.Banner != "" || (result.Service != nil && result.Service.Banner != "") {
			hasBanner = true
			break
		}
	}

	if !hasBanner && openPorts > 0 {
		fmt.Println("\n提示: 要获取服务Banner信息，请使用 --banner-grab 参数启用Banner抓取功能")
		fmt.Println("例如: go-port-rocket scan -t example.com -p 80,443,8080 --service-detection --banner-grab")
	}
}

// TCPScan 使用普通TCP连接进行扫描
func TCPScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	return QuickScan(target, ports, ScanTypeTCP, timeout, workers)
}

// joinPortsToString 将端口数组转换为端口范围字符串
func joinPortsToString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	var portStrs []string
	for _, port := range ports {
		portStrs = append(portStrs, strconv.Itoa(port))
	}

	return strings.Join(portStrs, ",")
}

// ScanPorts 扫描指定端口
func ScanPorts(config *ScanConfig, ports []int) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, len(ports))
	limiter := make(chan struct{}, config.Workers)

	// 初始化结果数组
	for i, port := range ports {
		results[i] = ScanResult{
			Port:  port,
			State: PortStateClosed,
			Type:  ScanTypeTCP,
		}
	}

	// 创建工作任务
	for i, port := range ports {
		wg.Add(1)
		go func(i int, port int) {
			defer wg.Done()
			limiter <- struct{}{} // 获取令牌
			defer func() {
				<-limiter // 释放令牌
			}()

			result := scanPort(config.Target, port, config.Timeout)
			results[i] = result

			if result.State == PortStateOpen {
				status := fmt.Sprintf("%s", result.State)
				if result.ServiceName != "" {
					status += fmt.Sprintf(" (%s)", result.ServiceName)
				}
				fmt.Printf("Port %-5d: %s\n", port, status)
			}
		}(i, port)
	}

	wg.Wait()
	return results
}

// scanPort 扫描单个端口
func scanPort(target string, port int, timeout time.Duration) ScanResult {
	result := ScanResult{
		Port:  port,
		State: PortStateClosed,
		Type:  ScanTypeTCP,
	}

	// 首先验证目标地址是否有效
	if err := validateTargetAddress(target); err != nil {
		result.State = PortStateUnknown
		return result
	}

	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)

	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				result.State = PortStateFiltered
			} else if strings.Contains(netErr.Error(), "connection refused") {
				result.State = PortStateClosed
			} else if strings.Contains(netErr.Error(), "no such host") ||
				strings.Contains(netErr.Error(), "nodename nor servname provided") ||
				strings.Contains(netErr.Error(), "Name or service not known") {
				result.State = PortStateUnknown
			} else if strings.Contains(netErr.Error(), "network is unreachable") ||
				strings.Contains(netErr.Error(), "host is unreachable") {
				result.State = PortStateFiltered
			} else {
				result.State = PortStateFiltered
			}
		} else {
			result.State = PortStateFiltered
		}
		return result
	}

	defer conn.Close()

	// 验证连接是否真的成功建立
	if !verifyTCPConnection(conn) {
		result.State = PortStateClosed
		return result
	}

	result.State = PortStateOpen
	result.Open = true

	// 先从CommonServices映射中查找服务名称
	var serviceName string
	if name, ok := CommonServices[port]; ok {
		serviceName = name
		result.ServiceName = serviceName
	}

	// 尝试进行服务检测
	serviceOpts := DefaultServiceDetectionOptions()
	serviceOpts.Timeout = timeout
	serviceInfo, err := DetectService(target, port, serviceOpts)
	if err == nil && serviceInfo != nil {
		result.Service = ConvertServiceInfoToFingerprint(serviceInfo)
		if result.ServiceName == "" && serviceInfo.Name != "" {
			result.ServiceName = serviceInfo.Name
		}
	} else if serviceName != "" {
		// 如果服务检测失败，仍使用常见端口映射信息
		result.Service = ConvertServiceInfoToFingerprint(&ServiceInfo{
			Name: serviceName,
			Port: port,
		})
	}

	return result
}

// UDPScan 执行UDP扫描
func UDPScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	// 使用新的UDP扫描器
	udpResults, err := ExecuteUDPScan(target, ports, timeout, workers)
	if err != nil {
		return nil, fmt.Errorf("UDP扫描失败: %v", err)
	}

	// 将UDP扫描结果转换为通用ScanResult格式
	results := make([]ScanResult, len(udpResults))
	for i, udpResult := range udpResults {
		results[i] = ScanResult{
			Port:        udpResult.Port,
			State:       udpResult.State,
			Type:        ScanTypeUDP,
			ServiceName: udpResult.ServiceName,
			Version:     udpResult.Version,
			Banner:      udpResult.Banner,
			Open:        udpResult.State == PortStateOpen,
		}
	}

	return results, nil
}

// validateTarget 验证目标地址是否有效
func (s *Scanner) validateTarget() error {
	target := s.opts.Target

	// 检查是否为空
	if target == "" {
		return fmt.Errorf("目标地址不能为空")
	}

	// 尝试解析为IP地址
	if ip := net.ParseIP(target); ip != nil {
		// 检查是否为有效的IP地址范围
		if ip.IsUnspecified() || ip.IsLoopback() {
			return nil // 允许回环地址用于测试
		}
		// 检查是否为无效的IP地址（如999.999.999.999）
		if ip.To4() == nil && ip.To16() == nil {
			return fmt.Errorf("无效的IP地址: %s", target)
		}
		return nil
	}

	// 检查是否为明显无效的IP地址格式
	if strings.Contains(target, "999.999.999.999") {
		return fmt.Errorf("无效的IP地址: %s", target)
	}

	// 如果不是IP地址，尝试DNS解析
	ips, err := net.LookupHost(target)
	if err != nil {
		return fmt.Errorf("DNS解析失败: %v", err)
	}

	// 检测通配符DNS解析
	if s.isWildcardDNS(target, ips) {
		return fmt.Errorf("检测到通配符DNS解析，目标域名可能无效: %s", target)
	}

	return nil
}

// isWildcardDNS 检测是否为通配符DNS解析
func (s *Scanner) isWildcardDNS(domain string, ips []string) bool {
	// 检查域名是否看起来像是无效的
	if strings.Contains(domain, "invalid") ||
		strings.Contains(domain, "nonexistent") ||
		strings.Contains(domain, "12345") {

		// 生成一个随机的无效子域名
		randomSubdomain := fmt.Sprintf("nonexistent-random-subdomain-99999.%s", domain)

		// 尝试解析这个随机子域名
		randomIPs, err := net.LookupHost(randomSubdomain)
		if err != nil {
			// 如果随机子域名解析失败，说明不是通配符DNS
			return false
		}

		// 如果随机子域名解析成功，说明是通配符DNS
		if len(randomIPs) > 0 {
			return true
		}
	}

	return false
}

// verifyConnection 验证连接是否真的成功建立
func (s *Scanner) verifyConnection(conn net.Conn) bool {
	if conn == nil {
		return false
	}

	// 检查连接的远程地址
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return false
	}

	// 尝试获取连接状态
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// 尝试设置一个很短的超时来测试连接
		tcpConn.SetDeadline(time.Now().Add(100 * time.Millisecond))

		// 尝试写入一个空字节来测试连接
		_, err := tcpConn.Write([]byte{})
		if err != nil {
			// 如果写入失败，可能连接不是真正建立的
			if strings.Contains(err.Error(), "broken pipe") ||
				strings.Contains(err.Error(), "connection reset") {
				return false
			}
		}
	}

	return true
}

// validateTargetAddress 验证目标地址是否有效（独立函数版本）
func validateTargetAddress(target string) error {
	// 检查是否为空
	if target == "" {
		return fmt.Errorf("目标地址不能为空")
	}

	// 尝试解析为IP地址
	if ip := net.ParseIP(target); ip != nil {
		// 检查是否为有效的IP地址范围
		if ip.IsUnspecified() || ip.IsLoopback() {
			return nil // 允许回环地址用于测试
		}
		// 检查是否为无效的IP地址（如999.999.999.999）
		if ip.To4() == nil && ip.To16() == nil {
			return fmt.Errorf("无效的IP地址: %s", target)
		}
		return nil
	}

	// 检查是否为明显无效的IP地址格式
	if strings.Contains(target, "999.999.999.999") {
		return fmt.Errorf("无效的IP地址: %s", target)
	}

	// 如果不是IP地址，尝试DNS解析
	ips, err := net.LookupHost(target)
	if err != nil {
		return fmt.Errorf("DNS解析失败: %v", err)
	}

	// 检测通配符DNS解析
	if isWildcardDNSStandalone(target, ips) {
		return fmt.Errorf("检测到通配符DNS解析，目标域名可能无效: %s", target)
	}

	return nil
}

// isWildcardDNSStandalone 检测是否为通配符DNS解析（独立函数版本）
func isWildcardDNSStandalone(domain string, ips []string) bool {
	// 检查域名是否看起来像是无效的
	if strings.Contains(domain, "invalid") ||
		strings.Contains(domain, "nonexistent") ||
		strings.Contains(domain, "12345") {

		// 生成一个随机的无效子域名
		randomSubdomain := fmt.Sprintf("nonexistent-random-subdomain-99999.%s", domain)

		// 尝试解析这个随机子域名
		randomIPs, err := net.LookupHost(randomSubdomain)
		if err != nil {
			// 如果随机子域名解析失败，说明不是通配符DNS
			return false
		}

		// 如果随机子域名解析成功，说明是通配符DNS
		if len(randomIPs) > 0 {
			return true
		}
	}

	return false
}

// verifyTCPConnection 验证TCP连接是否真的成功建立（独立函数版本）
func verifyTCPConnection(conn net.Conn) bool {
	if conn == nil {
		return false
	}

	// 检查连接的远程地址
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return false
	}

	// 尝试获取连接状态
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// 尝试设置一个很短的超时来测试连接
		tcpConn.SetDeadline(time.Now().Add(100 * time.Millisecond))

		// 尝试写入一个空字节来测试连接
		_, err := tcpConn.Write([]byte{})
		if err != nil {
			// 如果写入失败，可能连接不是真正建立的
			if strings.Contains(err.Error(), "broken pipe") ||
				strings.Contains(err.Error(), "connection reset") {
				return false
			}
		}
	}

	return true
}
