package scanner

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberspacesec/go-port-rocket/pkg/fingerprint"
)

// ParsePorts 解析端口范围字符串
func ParsePorts(portsStr string) ([]int, error) {
	var ports []int
	ranges := strings.Split(portsStr, ",")

	for _, r := range ranges {
		if strings.Contains(r, "-") {
			// 处理端口范围
			bounds := strings.Split(r, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", r)
			}

			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", bounds[0])
			}

			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", bounds[1])
			}

			if start > end {
				return nil, fmt.Errorf("起始端口大于结束端口: %d > %d", start, end)
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
				return nil, fmt.Errorf("无效的端口: %s", r)
			}

			if port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("没有有效的端口")
	}

	return ports, nil
}

// ConvertServiceInfoToFingerprint 将ServiceInfo转换为fingerprint.Service
func ConvertServiceInfoToFingerprint(info *ServiceInfo) *fingerprint.Service {
	if info == nil {
		return nil
	}

	service := &fingerprint.Service{
		Name:       info.Name,
		Version:    info.Version,
		Product:    info.Product,
		Protocol:   "tcp", // 默认为TCP协议
		Banner:     info.FullBanner,
		Confidence: 100.0, // 默认置信度为100%
	}

	// 如果有CPE信息，则添加
	if len(info.CPE) > 0 {
		service.CPE = info.CPE
	}

	// 创建元数据
	service.Metadata = make(map[string]string)
	if info.ExtraInfo != "" {
		service.Metadata["extra_info"] = info.ExtraInfo
	}
	if info.Fingerprint != "" {
		service.Metadata["fingerprint"] = info.Fingerprint
	}
	if info.FullBanner != "" {
		service.Metadata["full_banner"] = info.FullBanner
	}

	return service
}

// ConvertFingerprintToServiceInfo 将fingerprint.Service转换为ServiceInfo
func ConvertFingerprintToServiceInfo(service *fingerprint.Service) *ServiceInfo {
	if service == nil {
		return nil
	}

	info := &ServiceInfo{
		Name:    service.Name,
		Version: service.Version,
		Product: service.Product,
	}

	// 获取Banner信息
	if service.Banner != "" {
		info.FullBanner = service.Banner
	}

	// 获取CPE信息
	if len(service.CPE) > 0 {
		info.CPE = service.CPE
	}

	// 获取额外信息
	if service.Metadata != nil {
		if extraInfo, ok := service.Metadata["extra_info"]; ok {
			info.ExtraInfo = extraInfo
		}
		if fingerprint, ok := service.Metadata["fingerprint"]; ok {
			info.Fingerprint = fingerprint
		}
	}

	return info
}
