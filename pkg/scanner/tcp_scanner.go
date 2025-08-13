package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/logger"
)

// TCPScanner TCP扫描器
type TCPScanner struct {
	*baseScanner
}

// NewTCPScanner 创建新的TCP扫描器
func NewTCPScanner() *TCPScanner {
	return &TCPScanner{
		baseScanner: newBaseScanner(ScanTypeTCP),
	}
}

// scanPort 实现TCP端口扫描
func (s *TCPScanner) scanPort(ctx context.Context, port int) (ScanResult, error) {
	// 首先验证目标地址是否有效
	if err := s.validateTarget(); err != nil {
		return ScanResult{Port: port, State: PortStateUnknown}, err
	}

	addr := fmt.Sprintf("%s:%d", s.opts.Target, port)
	conn, err := net.DialTimeout("tcp", addr, s.opts.Timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				return ScanResult{Port: port, State: PortStateFiltered}, nil
			}
			// 检查是否是连接被拒绝错误
			if strings.Contains(netErr.Error(), "connection refused") {
				return ScanResult{Port: port, State: PortStateClosed}, nil
			}
			// 检查DNS解析失败
			if strings.Contains(netErr.Error(), "no such host") ||
				strings.Contains(netErr.Error(), "nodename nor servname provided") ||
				strings.Contains(netErr.Error(), "Name or service not known") {
				return ScanResult{Port: port, State: PortStateUnknown}, fmt.Errorf("DNS解析失败: %v", err)
			}
			// 检查网络不可达
			if strings.Contains(netErr.Error(), "network is unreachable") ||
				strings.Contains(netErr.Error(), "host is unreachable") {
				return ScanResult{Port: port, State: PortStateFiltered}, nil
			}
		}
		return ScanResult{Port: port, State: PortStateUnknown}, err
	}
	defer conn.Close()

	// 验证连接是否真的成功建立
	if !s.verifyConnection(conn) {
		return ScanResult{Port: port, State: PortStateClosed}, nil
	}

	// 如果连接成功，端口是开放的
	result := ScanResult{
		Port:  port,
		State: PortStateOpen,
	}

	// 如果启用了服务探测
	if s.opts.ServiceProbe {
		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(s.opts.Timeout))

		// 发送探测数据
		probe := []byte("\r\n")
		if _, err := conn.Write(probe); err != nil {
			logger.Debug("发送探测数据失败: %v", err)
			return result, nil
		}

		// 读取响应
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return result, nil
			}
			logger.Debug("读取响应失败: %v", err)
			return result, nil
		}

		// 解析服务信息
		if n > 0 {
			result.Banner = string(buf[:n])
			// TODO: 实现服务识别逻辑
		}
	}

	return result, nil
}

// ValidateOptions 验证TCP扫描选项
func (s *TCPScanner) ValidateOptions(opts *ScanOptions) error {
	if err := s.baseScanner.ValidateOptions(opts); err != nil {
		return err
	}

	// TCP扫描不需要root权限
	return nil
}

// RequiresRoot TCP扫描不需要root权限
func (s *TCPScanner) RequiresRoot() bool {
	return false
}

// validateTarget 验证目标地址是否有效
func (s *TCPScanner) validateTarget() error {
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

	// 如果不是IP地址，尝试DNS解析
	_, err := net.LookupHost(target)
	if err != nil {
		return fmt.Errorf("DNS解析失败: %v", err)
	}

	return nil
}

// verifyConnection 验证连接是否真的成功建立
func (s *TCPScanner) verifyConnection(conn net.Conn) bool {
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
