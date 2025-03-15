package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// SynScanResult SYN扫描的结果
type SynScanResult struct {
	Port   int
	State  string // "open", "closed", "filtered"
	Reason string
}

// SynScanState SYN扫描的状态
type SynScanState struct {
	Target  string
	Timeout time.Duration
	Results []SynScanResult
}

// SYNScanner SYN扫描器
type SYNScanner struct {
	*baseScanner
}

// NewSYNScanner 创建新的SYN扫描器
func NewSYNScanner() *SYNScanner {
	return &SYNScanner{
		baseScanner: newBaseScanner(ScanTypeSYN),
	}
}

// scanPort 实现SYN端口扫描
func (s *SYNScanner) scanPort(ctx context.Context, port int) (ScanResult, error) {
	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return ScanResult{Port: port, State: PortStateUnknown}, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, int(s.opts.Timeout.Milliseconds()))
	if err != nil {
		return ScanResult{Port: port, State: PortStateUnknown}, fmt.Errorf("设置套接字选项失败: %v", err)
	}

	// 构造TCP SYN包
	addr := net.ParseIP(s.opts.Target)
	if addr == nil {
		return ScanResult{Port: port, State: PortStateUnknown}, fmt.Errorf("无效的目标IP地址: %s", s.opts.Target)
	}

	// 构造TCP头
	tcpHeader := make([]byte, 20)
	tcpHeader[0] = 0x50 // 数据偏移
	tcpHeader[1] = 0x00 // 保留
	tcpHeader[2] = 0x00 // 窗口大小
	tcpHeader[3] = 0x00
	tcpHeader[4] = 0x00 // 校验和
	tcpHeader[5] = 0x00
	tcpHeader[6] = 0x02 // SYN标志
	tcpHeader[7] = 0x00
	tcpHeader[8] = 0x00 // 序列号
	tcpHeader[9] = 0x00
	tcpHeader[10] = 0x00
	tcpHeader[11] = 0x00
	tcpHeader[12] = 0x00 // 确认号
	tcpHeader[13] = 0x00
	tcpHeader[14] = 0x00
	tcpHeader[15] = 0x00
	tcpHeader[16] = 0x00 // 紧急指针
	tcpHeader[17] = 0x00
	tcpHeader[18] = 0x00
	tcpHeader[19] = 0x00

	// 构造IP头
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // 版本和头部长度
	ipHeader[1] = 0x00 // 服务类型
	ipHeader[2] = 0x00 // 总长度
	ipHeader[3] = 0x28
	ipHeader[4] = 0x00 // 标识
	ipHeader[5] = 0x00
	ipHeader[6] = 0x40 // 标志和片偏移
	ipHeader[7] = 0x00
	ipHeader[8] = 0x40  // 生存时间
	ipHeader[9] = 0x06  // 协议(TCP)
	ipHeader[10] = 0x00 // 校验和
	ipHeader[11] = 0x00
	ipHeader[12] = 0x00 // 源IP
	ipHeader[13] = 0x00
	ipHeader[14] = 0x00
	ipHeader[15] = 0x00
	ipHeader[16] = byte(addr[0]) // 目标IP
	ipHeader[17] = byte(addr[1])
	ipHeader[18] = byte(addr[2])
	ipHeader[19] = byte(addr[3])

	// 发送SYN包
	packet := append(ipHeader, tcpHeader...)
	sa := &syscall.SockaddrInet4{
		Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
	}
	err = syscall.Sendto(fd, packet, 0, sa)
	if err != nil {
		return ScanResult{Port: port, State: PortStateUnknown}, fmt.Errorf("发送SYN包失败: %v", err)
	}

	// 接收响应
	buf := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		if err == syscall.EAGAIN {
			return ScanResult{Port: port, State: PortStateFiltered}, nil
		}
		return ScanResult{Port: port, State: PortStateUnknown}, fmt.Errorf("接收响应失败: %v", err)
	}

	// 解析响应
	if n > 0 {
		// 检查是否是RST包
		if buf[33]&0x04 != 0 {
			return ScanResult{Port: port, State: PortStateClosed}, nil
		}
		// 检查是否是SYN-ACK包
		if buf[33]&0x12 != 0 {
			return ScanResult{Port: port, State: PortStateOpen}, nil
		}
	}

	return ScanResult{Port: port, State: PortStateUnknown}, nil
}

// ValidateOptions 验证SYN扫描选项
func (s *SYNScanner) ValidateOptions(opts *ScanOptions) error {
	if err := s.baseScanner.ValidateOptions(opts); err != nil {
		return err
	}

	// 检查是否有root权限
	if os.Geteuid() != 0 {
		return ErrRootRequired
	}

	return nil
}

// RequiresRoot SYN扫描需要root权限
func (s *SYNScanner) RequiresRoot() bool {
	return true
}

// 以下是真实SYN扫描所需的函数的框架
// 注意：这些函数在大多数情况下需要root/管理员权限才能运行

// sendSYNPacket 发送SYN数据包
func sendSYNPacket(dst string, dstPort int) error {
	// 实际实现需要使用原始套接字发送TCP SYN数据包
	// 这需要更复杂的网络编程和特权访问
	return fmt.Errorf("not implemented")
}

// listenForSYNACK 监听SYN-ACK响应
func listenForSYNACK(timeout time.Duration) error {
	// 实际实现需要捕获和解析原始TCP数据包
	return fmt.Errorf("not implemented")
}

// sendICMP 发送ICMP包以检测主机是否可达
func sendICMP(target string, timeout time.Duration) (bool, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("Go-Port-Rocket ICMP probe"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return false, err
	}

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return false, err
	}

	if _, err := c.WriteTo(wb, dst); err != nil {
		return false, err
	}

	rb := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return false, err
	}

	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return false, err
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return true, nil
	default:
		return false, nil
	}
}
