package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/logger"
)

// UDPScanResult UDP扫描的结果
type UDPScanResult struct {
	Port        int       // 端口号
	Protocol    string    // 协议
	State       PortState // 状态
	ServiceName string    // 服务名称
	Version     string    // 版本
	Banner      string    // Banner
	Reason      string    // 原因
	TTL         int       // TTL值
}

// UDPScanner UDP扫描器
type UDPScanner struct {
	target  string
	ports   []int
	timeout time.Duration
	workers int
	mu      sync.Mutex
	results []UDPScanResult
}

// NewUDPScanner 创建UDP扫描器
func NewUDPScanner(target string, ports []int, timeout time.Duration, workers int) *UDPScanner {
	return &UDPScanner{
		target:  target,
		ports:   ports,
		timeout: timeout,
		workers: workers,
		results: make([]UDPScanResult, 0),
	}
}

// Scan 执行UDP扫描
func (s *UDPScanner) Scan(ctx context.Context) ([]UDPScanResult, error) {
	// 创建工作通道
	portChan := make(chan int, len(s.ports))
	resultChan := make(chan UDPScanResult, len(s.ports))
	doneChan := make(chan struct{})

	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				select {
				case <-ctx.Done():
					return
				default:
					result := s.scanPort(port)
					resultChan <- result
				}
			}
		}()
	}

	// 收集结果
	go func() {
		wg.Wait()
		close(resultChan)
		close(doneChan)
	}()

	// 分发端口
	go func() {
		for _, port := range s.ports {
			select {
			case <-ctx.Done():
				close(portChan)
				return
			default:
				portChan <- port
			}
		}
		close(portChan)
	}()

	// 处理结果
	for {
		select {
		case <-ctx.Done():
			return s.results, ctx.Err()
		case result, ok := <-resultChan:
			if !ok {
				continue
			}
			s.mu.Lock()
			s.results = append(s.results, result)
			s.mu.Unlock()
		case <-doneChan:
			return s.results, nil
		}
	}
}

// scanPort 扫描单个UDP端口
func (s *UDPScanner) scanPort(port int) UDPScanResult {
	result := UDPScanResult{
		Port:     port,
		Protocol: "udp",
		State:    PortStateClosed,
		Reason:   "no-response",
	}

	// 根据端口选择合适的UDP探测包
	payload := getUDPProbeForPort(port)

	// 发送UDP数据包
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.target, port))
	if err != nil {
		logger.Debugf("UDP地址解析失败 %s:%d: %v", s.target, port, err)
		result.State = PortStateFiltered
		result.Reason = "resolve-failed"
		return result
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		logger.Debugf("UDP连接失败 %s:%d: %v", s.target, port, err)
		result.State = PortStateFiltered
		result.Reason = "connect-failed"
		return result
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetWriteDeadline(time.Now().Add(s.timeout))
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	// 发送数据包
	_, err = conn.Write(payload)
	if err != nil {
		logger.Debugf("UDP发送失败 %s:%d: %v", s.target, port, err)
		result.State = PortStateFiltered
		result.Reason = "send-failed"
		return result
	}

	// 读取响应
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(buf)

	if err != nil {
		// 超时通常意味着端口被过滤或者没有服务
		// 在UDP中，没有响应可能意味着过滤或开放但不响应
		result.State = PortStateFiltered
		result.Reason = "timeout"
		return result
	}

	// 收到响应，端口可能是开放的
	result.State = PortStateOpen
	result.Reason = "got-response"

	// 尝试分析响应，识别服务
	serviceInfo := analyzeUDPResponse(port, buf[:n])
	result.ServiceName = serviceInfo.Name
	result.Version = serviceInfo.Version
	result.Banner = serviceInfo.FullBanner

	return result
}

// getUDPProbeForPort 根据端口号获取合适的UDP探测包
func getUDPProbeForPort(port int) []byte {
	switch port {
	case 53: // DNS
		return createDNSQuery("example.com")
	case 123: // NTP
		return createNTPQuery()
	case 161: // SNMP
		return createSNMPQuery()
	case 137: // NetBIOS Name Service
		return createNetBIOSQuery()
	case 5353: // mDNS
		return createMDNSQuery()
	case 1900: // SSDP (UPnP)
		return createSSDPQuery()
	case 67, 68: // DHCP
		return createDHCPQuery()
	case 520: // RIP
		return createRIPQuery()
	case 69: // TFTP
		return createTFTPQuery()
	case 514: // Syslog
		return createSyslogMessage()
	default:
		// 尝试发送一些无害的数据
		return []byte("\r\n\r\n")
	}
}

// ServiceInfo UDP服务信息
type UDPServiceInfo struct {
	Name       string
	Version    string
	Product    string
	FullBanner string
	ExtraInfo  string
}

// analyzeUDPResponse 分析UDP响应，识别服务
func analyzeUDPResponse(port int, data []byte) UDPServiceInfo {
	info := UDPServiceInfo{
		Name:       "unknown",
		FullBanner: fmt.Sprintf("%x", data), // 十六进制格式的完整响应
	}

	// 根据端口和响应内容进行特定服务识别
	switch port {
	case 53: // DNS
		if len(data) > 12 {
			info.Name = "dns"
			// 分析DNS响应
			if data[2]&0x80 != 0 { // 检查QR标志位
				info.Product = "DNS Server"
				// 提取事务ID
				txID := binary.BigEndian.Uint16(data[0:2])
				info.ExtraInfo = fmt.Sprintf("Transaction ID: %d", txID)

				// 尝试提取版本信息
				if len(data) > 40 && bytes.Contains(data, []byte("VERSION")) {
					version := extractDNSVersion(data)
					if version != "" {
						info.Version = version
					}
				}
			}
		}

	case 123: // NTP
		if len(data) >= 48 {
			info.Name = "ntp"
			info.Product = "NTP Server"
			// 提取NTP版本
			if data[0]&0x38 == 0x08 { // 检查版本号范围
				version := (data[0] >> 3) & 0x07
				info.Version = fmt.Sprintf("%d", version)

				// 提取引用时间戳
				var refTimestamp uint32
				if len(data) >= 16 {
					refTimestamp = binary.BigEndian.Uint32(data[16:20])
				}

				info.ExtraInfo = fmt.Sprintf("Ref Timestamp: %d", refTimestamp)
			}
		}

	case 161: // SNMP
		if len(data) > 10 && data[0] == 0x30 { // ASN.1序列标识
			info.Name = "snmp"
			// 尝试提取SNMP版本
			if len(data) > 15 && data[4] == 0x02 { // INTEGER类型
				if data[6] == 0x00 {
					info.Version = "1"
				} else if data[6] == 0x01 {
					info.Version = "2c"
				} else if data[6] == 0x03 {
					info.Version = "3"
				}
				info.Product = "SNMP Agent"
			}
		}

	case 5353: // mDNS
		if len(data) > 12 {
			info.Name = "mdns"
			info.Product = "Multicast DNS"
			// 提取事务ID和标志
			if len(data) >= 4 {
				txID := binary.BigEndian.Uint16(data[0:2])
				flags := binary.BigEndian.Uint16(data[2:4])
				info.ExtraInfo = fmt.Sprintf("Transaction ID: %d, Flags: %04x", txID, flags)
			}
		}

	case 1900: // SSDP (UPnP)
		if bytes.HasPrefix(data, []byte("HTTP/1.1")) || bytes.Contains(data, []byte("NOTIFY")) {
			info.Name = "ssdp"
			info.Product = "UPnP Device"

			// 尝试提取服务器信息
			serverIndex := bytes.Index(data, []byte("SERVER:"))
			if serverIndex > 0 {
				end := bytes.Index(data[serverIndex:], []byte("\r\n"))
				if end > 0 {
					server := string(data[serverIndex+7 : serverIndex+end])
					info.ExtraInfo = server

					// 尝试从服务器字符串中提取版本
					parts := bytes.Split(data[serverIndex+7:serverIndex+end], []byte(" "))
					if len(parts) > 1 {
						for _, part := range parts {
							if bytes.Contains(part, []byte("/")) {
								verParts := bytes.Split(part, []byte("/"))
								if len(verParts) == 2 {
									info.Version = string(verParts[1])
									break
								}
							}
						}
					}
				}
			}
		}

	case 500: // ISAKMP/IKE (VPN)
		if len(data) > 20 && bytes.HasPrefix(data[16:20], []byte{0x00, 0x00, 0x00, 0x00}) {
			info.Name = "isakmp"
			info.Product = "IKE/ISAKMP (VPN)"
		}

	default:
		// 尝试识别通用特征
		info = detectGenericUDPService(data)
	}

	return info
}

// detectGenericUDPService 通用UDP服务识别
func detectGenericUDPService(data []byte) UDPServiceInfo {
	info := UDPServiceInfo{
		Name:       "unknown",
		FullBanner: fmt.Sprintf("%x", data),
	}

	// 检查常见的协议特征

	// 检查是否为可能的RTP数据 (实时传输协议)
	if len(data) > 12 && (data[0]&0xC0) == 0x80 {
		info.Name = "rtp"
		info.Product = "Real-time Transport Protocol"
		info.ExtraInfo = fmt.Sprintf("SSRC: %d", binary.BigEndian.Uint32(data[8:12]))
		return info
	}

	// 检查是否为可能的STUN响应
	if len(data) > 4 && data[0] == 0x01 && data[1] == 0x01 {
		info.Name = "stun"
		info.Product = "STUN Protocol"
		if len(data) > 8 {
			magicCookie := binary.BigEndian.Uint32(data[4:8])
			info.ExtraInfo = fmt.Sprintf("Magic Cookie: %08x", magicCookie)
		}
		return info
	}

	// 如果响应包含可打印的ASCII文本，提取其中的有用信息
	if isPrintableASCII(data) {
		info.FullBanner = string(data)

		// 提取可能的版本信息
		if bytes.Contains(data, []byte("version")) || bytes.Contains(data, []byte("VERSION")) {
			// 尝试从文本中提取版本号
			verInfo := extractVersionFromText(data)
			if verInfo != "" {
				info.Version = verInfo
			}
		}
	}

	return info
}

// isPrintableASCII 检查数据是否为可打印的ASCII文本
func isPrintableASCII(data []byte) bool {
	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t' {
			printableCount++
		}
	}
	// 如果80%以上的字符是可打印的，认为它是文本
	return printableCount > len(data)*8/10
}

// extractVersionFromText 从文本中提取版本信息
func extractVersionFromText(data []byte) string {
	// 简单实现，真实场景应该使用更复杂的正则表达式
	versionIndex := bytes.Index(bytes.ToLower(data), []byte("version"))
	if versionIndex > 0 {
		end := bytes.IndexAny(data[versionIndex+7:], "\r\n\t ")
		if end > 0 && end < 20 { // 防止提取太长
			return string(bytes.TrimSpace(data[versionIndex+7 : versionIndex+7+end]))
		}
	}
	return ""
}

// createDNSQuery 创建DNS查询包
func createDNSQuery(domain string) []byte {
	// 简单的DNS查询包，查询A记录
	buffer := new(bytes.Buffer)

	// 事务ID (随机)
	binary.Write(buffer, binary.BigEndian, uint16(0x1234))

	// 标志 (标准查询)
	binary.Write(buffer, binary.BigEndian, uint16(0x0100))

	// 问题数量 (1个)
	binary.Write(buffer, binary.BigEndian, uint16(1))

	// 回答、授权、附加记录数量 (0个)
	binary.Write(buffer, binary.BigEndian, uint16(0))
	binary.Write(buffer, binary.BigEndian, uint16(0))
	binary.Write(buffer, binary.BigEndian, uint16(0))

	// 查询域名
	labels := bytes.Split([]byte(domain), []byte("."))
	for _, label := range labels {
		binary.Write(buffer, binary.BigEndian, uint8(len(label)))
		buffer.Write(label)
	}

	// 域名结束符
	buffer.WriteByte(0)

	// 查询类型 (A记录)
	binary.Write(buffer, binary.BigEndian, uint16(1))

	// 查询类 (IN)
	binary.Write(buffer, binary.BigEndian, uint16(1))

	return buffer.Bytes()
}

// createNTPQuery 创建NTP查询包
func createNTPQuery() []byte {
	// NTP v4查询包
	packet := make([]byte, 48)

	// 设置LI, VN, Mode
	// LI = 0 (无闰秒警告), VN = 4 (NTP版本4), Mode = 3 (客户端)
	packet[0] = 0x23 // 00100011

	return packet
}

// createSNMPQuery 创建SNMP查询包 (GetRequest)
func createSNMPQuery() []byte {
	// 简化的SNMP v1 GetRequest
	// 这个包请求系统描述(sysDescr.0)
	return []byte{
		0x30, 0x2c, // SEQUENCE, length 44
		0x02, 0x01, 0x00, // INTEGER, length 1, value 0 (version: v1)
		0x04, 0x07, // OCTET STRING, length 7
		'p', 'u', 'b', 'l', 'i', 'c', // community: public
		0xa0, 0x1e, // GetRequest PDU, length 30
		0x02, 0x01, 0x01, // request-id: 1
		0x02, 0x01, 0x00, // error-status: 0
		0x02, 0x01, 0x00, // error-index: 0
		0x30, 0x13, // varbind-list, length 19
		0x30, 0x11, // varbind, length 17
		0x06, 0x0d, // OID, length 13
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, // 1.3.6.1.2.1.1 (iso.org.dod.internet.mgmt.mib-2.system)
		0x02, 0x00, // sysDescr.0
		0x05, 0x00, // NULL
	}
}

// createNetBIOSQuery 创建NetBIOS名称查询
func createNetBIOSQuery() []byte {
	// NetBIOS名称服务查询
	buffer := new(bytes.Buffer)

	// 事务ID
	binary.Write(buffer, binary.BigEndian, uint16(0x1234))

	// 标志 (名称查询请求)
	binary.Write(buffer, binary.BigEndian, uint16(0x0100))

	// 问题、回答、授权、附加资源记录数
	binary.Write(buffer, binary.BigEndian, uint16(1))
	binary.Write(buffer, binary.BigEndian, uint16(0))
	binary.Write(buffer, binary.BigEndian, uint16(0))
	binary.Write(buffer, binary.BigEndian, uint16(0))

	// 查询名称 (编码为NetBIOS格式)
	buffer.Write([]byte{
		32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
		32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
	})

	// 查询类型 (NB)
	binary.Write(buffer, binary.BigEndian, uint16(0x0020))

	// 查询类 (IN)
	binary.Write(buffer, binary.BigEndian, uint16(0x0001))

	return buffer.Bytes()
}

// createMDNSQuery 创建mDNS查询包
func createMDNSQuery() []byte {
	// 简单的mDNS查询，查询_services._dns-sd._udp.local.
	buffer := new(bytes.Buffer)

	// 事务ID
	binary.Write(buffer, binary.BigEndian, uint16(0x0000))

	// 标志 (标准查询)
	binary.Write(buffer, binary.BigEndian, uint16(0x0000))

	// 问题数量 (1个)
	binary.Write(buffer, binary.BigEndian, uint16(1))

	// 回答、授权、附加记录数量 (0个)
	binary.Write(buffer, binary.BigEndian, uint16(0))
	binary.Write(buffer, binary.BigEndian, uint16(0))
	binary.Write(buffer, binary.BigEndian, uint16(0))

	// 查询域名: _services._dns-sd._udp.local.
	labels := [][]byte{
		[]byte("_services"),
		[]byte("_dns-sd"),
		[]byte("_udp"),
		[]byte("local"),
	}

	for _, label := range labels {
		binary.Write(buffer, binary.BigEndian, uint8(len(label)))
		buffer.Write(label)
	}

	// 域名结束符
	buffer.WriteByte(0)

	// 查询类型 (PTR)
	binary.Write(buffer, binary.BigEndian, uint16(12))

	// 查询类 (IN)
	binary.Write(buffer, binary.BigEndian, uint16(1))

	return buffer.Bytes()
}

// createSSDPQuery 创建SSDP查询包
func createSSDPQuery() []byte {
	query := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"

	return []byte(query)
}

// createDHCPQuery 创建DHCP发现包
func createDHCPQuery() []byte {
	// 简化的DHCP发现包
	packet := make([]byte, 244)

	// 消息类型 (Boot Request)
	packet[0] = 0x01

	// 硬件类型 (Ethernet)
	packet[1] = 0x01

	// 硬件地址长度
	packet[2] = 0x06

	// 跳数
	packet[3] = 0x00

	// 事务ID
	binary.BigEndian.PutUint32(packet[4:8], 0x12345678)

	// 秒数
	binary.BigEndian.PutUint16(packet[8:10], 0x0000)

	// 标志 (Broadcast)
	binary.BigEndian.PutUint16(packet[10:12], 0x8000)

	// DHCP Options
	packet[236] = 53 // Option: DHCP Message Type
	packet[237] = 1  // Length
	packet[238] = 1  // DHCP Discover

	// End Option
	packet[239] = 255

	return packet
}

// createRIPQuery 创建RIP查询包
func createRIPQuery() []byte {
	// RIP v2查询
	packet := make([]byte, 24)

	// 命令 (请求)
	packet[0] = 0x01

	// 版本
	packet[1] = 0x02

	// 未使用
	packet[2] = 0x00
	packet[3] = 0x00

	// 地址族 (IP)
	binary.BigEndian.PutUint16(packet[4:6], 0x0000)

	// 路由标记
	binary.BigEndian.PutUint16(packet[6:8], 0x0000)

	// IP地址 (0.0.0.0)
	packet[8] = 0x00
	packet[9] = 0x00
	packet[10] = 0x00
	packet[11] = 0x00

	// 子网掩码 (0.0.0.0)
	packet[12] = 0x00
	packet[13] = 0x00
	packet[14] = 0x00
	packet[15] = 0x00

	// 下一跳 (0.0.0.0)
	packet[16] = 0x00
	packet[17] = 0x00
	packet[18] = 0x00
	packet[19] = 0x00

	// 度量 (16)
	binary.BigEndian.PutUint32(packet[20:24], 16)

	return packet
}

// createTFTPQuery 创建TFTP请求包
func createTFTPQuery() []byte {
	// TFTP读请求
	buffer := new(bytes.Buffer)

	// 操作码 (读请求)
	binary.Write(buffer, binary.BigEndian, uint16(1))

	// 文件名
	buffer.WriteString("test.txt")
	buffer.WriteByte(0)

	// 模式
	buffer.WriteString("octet")
	buffer.WriteByte(0)

	return buffer.Bytes()
}

// createSyslogMessage 创建Syslog消息
func createSyslogMessage() []byte {
	// Syslog消息 (RFC 3164格式)
	message := "<34>Oct 11 22:14:15 test: probe message from Go-Port-Rocket"
	return []byte(message)
}

// extractDNSVersion 从DNS响应中提取版本信息
func extractDNSVersion(data []byte) string {
	// 通常版本信息会在TXT记录的版本查询响应中
	if len(data) < 40 {
		return ""
	}

	// 简单查找版本字符串
	verIndex := bytes.Index(data, []byte("version"))
	if verIndex > 0 {
		// 提取版本信息，但长度限制为20个字符
		end := verIndex + 20
		if end > len(data) {
			end = len(data)
		}

		// 找到可能是版本号的字符串
		for i := verIndex + 7; i < end; i++ {
			if data[i] >= '0' && data[i] <= '9' {
				// 找到数字，提取直到非版本号字符
				start := i
				for i < end && ((data[i] >= '0' && data[i] <= '9') || data[i] == '.' || data[i] == '-') {
					i++
				}
				if i > start {
					return string(data[start:i])
				}
			}
		}
	}

	return ""
}

// ExecuteUDPScan 执行UDP扫描
func ExecuteUDPScan(target string, ports []int, timeout time.Duration, workers int) ([]UDPScanResult, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanner := NewUDPScanner(target, ports, timeout, workers)
	return scanner.Scan(ctx)
}
