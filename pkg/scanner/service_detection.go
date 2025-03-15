package scanner

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ServiceDetectionOptions 服务检测选项
type ServiceDetectionOptions struct {
	EnableVersionDetection bool // 启用版本检测
	VersionIntensity       int  // 版本检测强度(0-9)
	EnableOSDetection      bool // 启用操作系统检测
	BannerGrab             bool // 获取服务banner
	Timeout                time.Duration
}

// DefaultServiceDetectionOptions 默认服务检测选项
func DefaultServiceDetectionOptions() *ServiceDetectionOptions {
	return &ServiceDetectionOptions{
		EnableVersionDetection: true,
		VersionIntensity:       5,
		EnableOSDetection:      false,
		BannerGrab:             true,
		Timeout:                time.Second * 5,
	}
}

// 服务描述映射，添加中文说明
var ServiceDescriptions = map[string]string{
	"http":       "HTTP 网页服务器",
	"https":      "HTTPS 加密网页服务器",
	"ssh":        "SSH 安全远程登录",
	"ftp":        "FTP 文件传输服务",
	"smtp":       "SMTP 电子邮件发送服务",
	"pop3":       "POP3 电子邮件接收服务",
	"imap":       "IMAP 电子邮件接收服务",
	"dns":        "DNS 域名服务",
	"mysql":      "MySQL 数据库服务",
	"postgresql": "PostgreSQL 数据库服务",
	"mongodb":    "MongoDB 数据库服务",
	"redis":      "Redis 缓存服务",
	"memcached":  "Memcached 缓存服务",
	"rdp":        "RDP 远程桌面服务",
	"vnc":        "VNC 远程桌面服务",
	"telnet":     "Telnet 远程登录服务",
	"smb":        "SMB 文件共享服务",
	"nfs":        "NFS 网络文件系统",
	"ldap":       "LDAP 目录访问服务",
	"snmp":       "SNMP 网络管理服务",
}

// GetServiceDescription 获取服务中文描述
func GetServiceDescription(serviceName string) string {
	description, exists := ServiceDescriptions[strings.ToLower(serviceName)]
	if exists {
		return description
	}
	return "未知服务"
}

// DetectService 检测服务版本信息
func DetectService(target string, port int, opts *ServiceDetectionOptions) (*ServiceInfo, error) {
	serviceName := ""

	// 根据常见端口映射查找服务名称
	if name, ok := CommonServices[port]; ok {
		serviceName = name
	}

	info := &ServiceInfo{
		Name:    serviceName,
		Port:    port,
		Version: "",
	}

	// 1. 尝试TCP连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), opts.Timeout)
	if err != nil {
		return info, err
	}
	defer conn.Close()

	// 2. 获取初始banner
	if opts.BannerGrab {
		conn.SetDeadline(time.Now().Add(opts.Timeout))
		reader := bufio.NewReader(conn)
		banner, err := reader.ReadString('\n')
		if err == nil {
			info.FullBanner = strings.TrimSpace(banner)
			// 解析banner中的版本信息
			parseVersionFromBanner(info)
		}
	}

	// 3. 发送特定服务的探测包
	if opts.EnableVersionDetection {
		probes := getServiceProbes(info.Name, opts.VersionIntensity)
		for _, probe := range probes {
			conn.SetDeadline(time.Now().Add(opts.Timeout))
			_, err := conn.Write([]byte(probe.Request))
			if err != nil {
				continue
			}

			// 读取响应
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				continue
			}

			response := string(buf[:n])
			if matches := probe.MatchPattern.FindStringSubmatch(response); len(matches) > 1 {
				info.Product = matches[1]
				if len(matches) > 2 {
					info.Version = matches[2]
				}
				break
			}
		}
	}

	return info, nil
}

// ServiceProbe 服务探测规则
type ServiceProbe struct {
	ServiceName  string
	Request      string
	MatchPattern *regexp.Regexp
}

// getServiceProbes 获取服务探测规则
func getServiceProbes(serviceName string, intensity int) []ServiceProbe {
	probes := []ServiceProbe{
		// HTTP
		{
			ServiceName:  "http",
			Request:      "HEAD / HTTP/1.0\r\n\r\n",
			MatchPattern: regexp.MustCompile(`Server: ([^\r\n]+)`),
		},
		// SSH
		{
			ServiceName:  "ssh",
			Request:      "",
			MatchPattern: regexp.MustCompile(`SSH-([0-9.]+)-([^\r\n]+)`),
		},
		// FTP
		{
			ServiceName:  "ftp",
			Request:      "",
			MatchPattern: regexp.MustCompile(`([^\r\n]+) FTP`),
		},
		// SMTP
		{
			ServiceName:  "smtp",
			Request:      "EHLO localhost\r\n",
			MatchPattern: regexp.MustCompile(`([^\r\n]+) ESMTP`),
		},
		// MySQL
		{
			ServiceName:  "mysql",
			Request:      "",
			MatchPattern: regexp.MustCompile(`([0-9.]+)-MariaDB`),
		},
		// Redis
		{
			ServiceName:  "redis",
			Request:      "INFO\r\n",
			MatchPattern: regexp.MustCompile(`redis_version:([0-9.]+)`),
		},
		// MongoDB
		{
			ServiceName:  "mongodb",
			Request:      "\x3F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			MatchPattern: regexp.MustCompile(`mongodb([0-9.]+)`),
		},
		// PostgreSQL
		{
			ServiceName:  "postgresql",
			Request:      "\x00\x00\x00\x08\x04\xD2\x16\x2F",
			MatchPattern: regexp.MustCompile(`PostgreSQL ([0-9.]+)`),
		},
		// Telnet
		{
			ServiceName:  "telnet",
			Request:      "",
			MatchPattern: regexp.MustCompile(`([^\r\n]+) telnet`),
		},
		// HTTPS/TLS
		{
			ServiceName:  "https",
			Request:      "",
			MatchPattern: regexp.MustCompile(`TLS ([0-9.]+)`),
		},
	}

	// 根据强度过滤探测规则
	if intensity < len(probes) {
		return probes[:intensity]
	}
	return probes
}

// parseVersionFromBanner 从banner中解析版本信息
func parseVersionFromBanner(info *ServiceInfo) {
	if info.FullBanner == "" {
		return
	}

	// 常见的版本号模式
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`([a-zA-Z]+)[/ ]([0-9.]+)`),
		regexp.MustCompile(`version[: ]([0-9.]+)`),
		regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`),
	}

	for _, pattern := range versionPatterns {
		if matches := pattern.FindStringSubmatch(info.FullBanner); len(matches) > 1 {
			if info.Product == "" && len(matches) > 2 {
				info.Product = matches[1]
				info.Version = matches[2]
			} else {
				info.Version = matches[1]
			}
			break
		}
	}
}
