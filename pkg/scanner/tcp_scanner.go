package scanner

import (
	"context"
	"fmt"
	"net"
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
	addr := fmt.Sprintf("%s:%d", s.opts.Target, port)
	conn, err := net.DialTimeout("tcp", addr, s.opts.Timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				return ScanResult{Port: port, State: PortStateFiltered}, nil
			}
			// 检查是否是连接被拒绝错误
			if netErr.Error() == "connection refused" {
				return ScanResult{Port: port, State: PortStateClosed}, nil
			}
		}
		return ScanResult{Port: port, State: PortStateUnknown}, err
	}
	defer conn.Close()

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
