package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/fingerprint"
	"github.com/cyberspacesec/go-port-rocket/pkg/logger"
)

// 正则表达式预编译
var (
	// HTTP服务版本正则
	httpServerRegex = regexp.MustCompile(`(?i)Server: ([^\r\n]+)`)
	// SSH版本正则
	sshVersionRegex = regexp.MustCompile(`^SSH-(\d+\.\d+)-([^\s]+)`)
	// FTP版本正则
	ftpVersionRegex = regexp.MustCompile(`^220[ -]([^\r\n]+)`)
	// SMTP版本正则
	smtpVersionRegex = regexp.MustCompile(`^220[ -]([^\r\n]+)`)
	// MySQL版本正则
	mysqlVersionRegex = regexp.MustCompile(`([.\d]+)`)
)

// DetectServiceVersion 检测服务版本
func DetectServiceVersion(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	// 根据常见服务端口执行相应的版本检测
	switch port {
	case 22:
		return detectSSH(target, port, timeout)
	case 21:
		return detectFTP(target, port, timeout)
	case 25, 587:
		return detectSMTP(target, port, timeout)
	case 80, 443, 8080, 8443:
		return detectHTTP(target, port, timeout)
	case 3306:
		return detectMySQL(target, port, timeout)
	default:
		// 对于未知服务，尝试通用banner抓取
		return grabBanner(target, port, timeout)
	}
}

// grabBanner 通用Banner抓取
func grabBanner(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	// 尝试直接读取banner (一些服务会在连接后立即发送banner)
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)

	info := &ServiceInfo{
		Name: "unknown",
	}

	if err == nil && n > 0 {
		banner := string(buffer[:n])
		info.FullBanner = banner
		// 从banner中提取可能的版本信息
		info.Fingerprint = fmt.Sprintf("%x", buffer[:n])

		// 尝试简单解析
		lines := strings.Split(banner, "\n")
		if len(lines) > 0 {
			firstLine := strings.TrimSpace(lines[0])
			if len(firstLine) > 0 {
				info.ExtraInfo = firstLine
				// 尝试从第一行猜测服务
				if strings.Contains(firstLine, "SSH") {
					info.Name = "ssh"
				} else if strings.Contains(firstLine, "FTP") {
					info.Name = "ftp"
				} else if strings.Contains(firstLine, "SMTP") {
					info.Name = "smtp"
				} else if strings.Contains(firstLine, "HTTP") {
					info.Name = "http"
				}
			}
		}
	}

	return info, nil
}

// detectHTTP 检测HTTP服务
func detectHTTP(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("HTTP连接失败: %v", err)
	}
	defer conn.Close()

	// 发送HTTP请求
	httpReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-Port-Rocket/1.0\r\nConnection: close\r\n\r\n", target)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(httpReq))
	if err != nil {
		return nil, fmt.Errorf("发送HTTP请求失败: %v", err)
	}

	// 读取响应
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取HTTP响应失败: %v", err)
	}

	response := string(buffer[:n])
	info := &ServiceInfo{
		Name:       "http",
		FullBanner: response,
	}

	// 解析服务器版本
	matches := httpServerRegex.FindStringSubmatch(response)
	if len(matches) > 1 {
		serverHeader := matches[1]
		info.Version = serverHeader

		// 进一步解析Server头
		parts := strings.Split(serverHeader, " ")
		if len(parts) > 0 {
			info.Product = parts[0]
			if len(parts) > 1 {
				info.ExtraInfo = strings.Join(parts[1:], " ")
			}
		}
	}

	return info, nil
}

// detectSSH 检测SSH服务
func detectSSH(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("SSH连接失败: %v", err)
	}
	defer conn.Close()

	// 读取SSH banner
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取SSH banner失败: %v", err)
	}

	banner := string(buffer[:n])
	info := &ServiceInfo{
		Name:       "ssh",
		FullBanner: banner,
	}

	// 解析版本信息
	matches := sshVersionRegex.FindStringSubmatch(banner)
	if len(matches) > 2 {
		info.Version = matches[1]
		info.Product = matches[2]
	}

	return info, nil
}

// detectFTP 检测FTP服务
func detectFTP(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("FTP连接失败: %v", err)
	}
	defer conn.Close()

	// 读取FTP banner
	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("读取FTP banner失败: %v", err)
	}

	info := &ServiceInfo{
		Name:       "ftp",
		FullBanner: banner,
	}

	// 解析版本信息
	matches := ftpVersionRegex.FindStringSubmatch(banner)
	if len(matches) > 1 {
		serverInfo := matches[1]
		info.ExtraInfo = serverInfo

		// 尝试从banner中提取产品名和版本
		// 通常格式为: ProductName Version
		parts := strings.Fields(serverInfo)
		if len(parts) > 0 {
			info.Product = parts[0]
			if len(parts) > 1 {
				info.Version = parts[1]
			}
		}
	}

	return info, nil
}

// detectSMTP 检测SMTP服务
func detectSMTP(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("SMTP连接失败: %v", err)
	}
	defer conn.Close()

	// 读取SMTP banner
	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("读取SMTP banner失败: %v", err)
	}

	info := &ServiceInfo{
		Name:       "smtp",
		FullBanner: banner,
	}

	// 解析版本信息
	matches := smtpVersionRegex.FindStringSubmatch(banner)
	if len(matches) > 1 {
		serverInfo := matches[1]
		info.ExtraInfo = serverInfo

		// 尝试从banner中提取产品名和版本
		parts := strings.Fields(serverInfo)
		if len(parts) > 0 {
			info.Product = parts[0]
			if len(parts) > 1 {
				info.Version = parts[1]
			}
		}
	}

	return info, nil
}

// detectMySQL 检测MySQL服务
func detectMySQL(target string, port int, timeout time.Duration) (*ServiceInfo, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("MySQL连接失败: %v", err)
	}
	defer conn.Close()

	// 读取MySQL握手包
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取MySQL握手包失败: %v", err)
	}

	info := &ServiceInfo{
		Name:       "mysql",
		FullBanner: fmt.Sprintf("%x", buffer[:n]),
	}

	// MySQL协议版本
	if n > 5 {
		// 数据包格式: [3字节长度][1字节序列号][1字节协议版本][服务器版本(Null终止的字符串)]...
		protocolVersion := buffer[4]

		// 从第6个字节开始是服务器版本字符串，以Null字节结束
		versionBytes := buffer[5:]
		nullIndex := bytes.IndexByte(versionBytes, 0)
		if nullIndex > 0 {
			versionStr := string(versionBytes[:nullIndex])
			info.Version = versionStr

			// 提取版本号
			matches := mysqlVersionRegex.FindStringSubmatch(versionStr)
			if len(matches) > 1 {
				info.Version = matches[1]
			}

			info.ExtraInfo = fmt.Sprintf("Protocol: %d", protocolVersion)
		}
	}

	return info, nil
}

// GetFingerprinter 获取指纹识别器实例，优先使用嵌入的指纹数据库
func GetFingerprinter(nmapSharePath string) (*fingerprint.Fingerprinter, error) {
	// 创建指纹识别器实例
	fp, err := fingerprint.NewFingerprinter(nmapSharePath)
	if err != nil {
		logger.Errorf("创建指纹识别器失败: %v", err)
		return nil, err
	}

	// 初始化默认选项
	opts := fingerprint.DefaultFingerprintOptions()
	fp.SetOptions(opts)

	return fp, nil
}
