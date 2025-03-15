package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
