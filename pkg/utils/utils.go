package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ParsePortRange 解析端口范围字符串，如 "1-1000" 或 "22,80,443"
func ParsePortRange(portsStr string) ([]int, error) {
	var ports []int

	// 按逗号分隔单独指定的端口
	parts := strings.Split(portsStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// 检查是否是范围 (例如 "1-1000")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %s: %v", part, err)
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %s: %v", part, err)
			}

			if start > end {
				return nil, fmt.Errorf("start port cannot be greater than end port in range %s", part)
			}

			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("ports must be between 1 and 65535 in range %s", part)
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port %d is out of range (1-65535)", port)
			}

			ports = append(ports, port)
		}
	}

	return ports, nil
}

// ResolveHost 解析主机名到IP地址
func ResolveHost(host string) (string, error) {
	// 检查是否已经是IP地址
	if net.ParseIP(host) != nil {
		return host, nil
	}

	// 尝试解析主机名
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve host %s: %v", host, err)
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("no IP addresses found for host %s", host)
	}

	return addrs[0], nil
}

// Logger 通用日志接口
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
}

// SimpleLogger 简单日志实现
type SimpleLogger struct {
	verbose bool
}

// NewSimpleLogger 创建简单日志器
func NewSimpleLogger(verbose bool) *SimpleLogger {
	return &SimpleLogger{verbose: verbose}
}

func (l *SimpleLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}

func (l *SimpleLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}

func (l *SimpleLogger) Debug(msg string, args ...interface{}) {
	if l.verbose {
		fmt.Printf("[DEBUG] "+msg+"\n", args...)
	}
}

func (l *SimpleLogger) Warn(msg string, args ...interface{}) {
	fmt.Printf("[WARN] "+msg+"\n", args...)
}

// RemoveDuplicatePorts 去除重复的端口
func RemoveDuplicatePorts(ports []int) []int {
	seen := make(map[int]bool)
	var result []int

	for _, port := range ports {
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}

	return result
}

// ValidateTarget 验证目标地址是否有效
func ValidateTarget(target string) error {
	// 尝试解析为IP地址
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}

	// 尝试解析为域名
	_, err := net.LookupHost(target)
	if err != nil {
		return fmt.Errorf("无法解析目标地址: %s", target)
	}

	return nil
}

// NetworkError 网络错误类型
type NetworkError struct {
	Type    string // 错误类型: timeout, refused, unreachable, dns_failed
	Message string // 错误消息
	Err     error  // 原始错误
}

func (e *NetworkError) Error() string {
	return e.Message
}

// AnalyzeNetworkError 分析网络错误类型
func AnalyzeNetworkError(err error) *NetworkError {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// 检查超时错误
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return &NetworkError{
			Type:    "timeout",
			Message: "连接超时",
			Err:     err,
		}
	}

	// 检查连接被拒绝
	if strings.Contains(errStr, "connection refused") {
		return &NetworkError{
			Type:    "refused",
			Message: "连接被拒绝",
			Err:     err,
		}
	}

	// 检查DNS解析失败
	if strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "nodename nor servname provided") ||
		strings.Contains(errStr, "Name or service not known") {
		return &NetworkError{
			Type:    "dns_failed",
			Message: "DNS解析失败",
			Err:     err,
		}
	}

	// 检查网络不可达
	if strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "host is unreachable") {
		return &NetworkError{
			Type:    "unreachable",
			Message: "网络不可达",
			Err:     err,
		}
	}

	// 其他网络错误
	return &NetworkError{
		Type:    "unknown",
		Message: errStr,
		Err:     err,
	}
}

// ConnectWithTimeout 带超时的TCP连接
func ConnectWithTimeout(target string, port int, timeout time.Duration) (net.Conn, *NetworkError) {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, AnalyzeNetworkError(err)
	}
	return conn, nil
}

// ValidateRequiredParams 验证必需的命令行参数
func ValidateRequiredParams(params map[string]string) error {
	for name, value := range params {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("必须指定%s参数", name)
		}
	}
	return nil
}

// ValidatePortRange 验证端口范围参数
func ValidatePortRange(portsStr string) error {
	if strings.TrimSpace(portsStr) == "" {
		return fmt.Errorf("端口范围不能为空")
	}

	_, err := ParsePortRange(portsStr)
	return err
}

// ValidateTimeout 验证超时参数
func ValidateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("超时时间必须大于0")
	}
	if timeout > 300*time.Second {
		return fmt.Errorf("超时时间不能超过300秒")
	}
	return nil
}

// ValidateWorkers 验证工作线程数参数
func ValidateWorkers(workers int) error {
	if workers <= 0 {
		return fmt.Errorf("工作线程数必须大于0")
	}
	if workers > 10000 {
		return fmt.Errorf("工作线程数不能超过10000")
	}
	return nil
}

// ValidateOutputFormat 验证输出格式参数
func ValidateOutputFormat(format string) error {
	validFormats := []string{"text", "json", "xml", "html", "csv"}
	format = strings.ToLower(strings.TrimSpace(format))

	for _, valid := range validFormats {
		if format == valid {
			return nil
		}
	}

	return fmt.Errorf("不支持的输出格式: %s，支持的格式: %s", format, strings.Join(validFormats, ", "))
}
