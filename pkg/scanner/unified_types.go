package scanner

import (
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/fingerprint"
)

// ScanType 扫描类型
type ScanType string

const (
	ScanTypeTCP    ScanType = "tcp"
	ScanTypeSYN    ScanType = "syn"
	ScanTypeFIN    ScanType = "fin"
	ScanTypeNULL   ScanType = "null"
	ScanTypeXMAS   ScanType = "xmas"
	ScanTypeACK    ScanType = "ack"
	ScanTypeUDP    ScanType = "udp"
	ScanTypeMAIMON ScanType = "maimon"
)

// PortState 端口状态
type PortState string

const (
	PortStateOpen     PortState = "open"
	PortStateClosed   PortState = "closed"
	PortStateFiltered PortState = "filtered"
	PortStateUnknown  PortState = "unknown"
)

// ScanOptions 扫描选项
type ScanOptions struct {
	Target           string                   // 目标地址
	Ports            string                   // 端口范围
	ScanType         ScanType                 // 扫描类型
	Timeout          time.Duration            // 超时时间
	Workers          int                      // 工作线程数
	EnableOS         bool                     // 启用操作系统检测
	EnableService    bool                     // 启用服务检测
	ServiceProbe     bool                     // 启用服务探测
	BannerProbe      bool                     // 获取服务banner
	RateLimit        int                      // 速率限制
	Retries          int                      // 重试次数
	Verbose          bool                     // 详细输出
	VersionIntensity int                      // 版本检测强度
	GuessOS          bool                     // 推测操作系统
	LimitOSScan      bool                     // 限制操作系统扫描
	Service          *ServiceDetectionOptions // 服务检测选项
	OutputFile       string                   // 输出文件
}

// NewScanOptions 创建新的扫描选项，使用合理的默认值
func NewScanOptions(target string, ports []int, scanType ScanType) *ScanOptions {
	// 将端口数组转换为字符串
	portsStr := joinPortsToString(ports)

	return &ScanOptions{
		Target:           target,
		Ports:            portsStr,
		ScanType:         scanType,
		Timeout:          time.Second * 5, // 默认5秒超时
		Workers:          100,             // 默认100个工作线程
		RateLimit:        1000,            // 默认速率限制
		Retries:          3,               // 默认重试3次
		Verbose:          false,           // 默认不详细输出
		ServiceProbe:     true,            // 默认启用服务探测
		BannerProbe:      true,            // 默认启用Banner探测
		EnableOS:         false,           // 默认禁用OS检测（避免超时）
		EnableService:    false,           // 默认禁用服务检测（避免超时）
		VersionIntensity: 0,               // 默认禁用版本检测
		GuessOS:          false,           // 默认禁用OS猜测
		LimitOSScan:      false,           // 默认不限制OS扫描
	}
}

// ScanResult 扫描结果
type ScanResult struct {
	Port        int                    `json:"port"`                   // 端口号
	State       PortState              `json:"state"`                  // 端口状态
	Service     *fingerprint.Service   `json:"service"`                // 服务信息
	OS          *fingerprint.OSInfo    `json:"os"`                     // 操作系统信息
	Banner      string                 `json:"banner,omitempty"`       // 服务banner
	Version     string                 `json:"version,omitempty"`      // 版本信息
	ServiceName string                 `json:"service_name,omitempty"` // 服务名称
	Open        bool                   `json:"open,omitempty"`         // 是否开放
	Type        ScanType               `json:"type,omitempty"`         // 扫描类型
	TTL         int                    `json:"ttl,omitempty"`          // TTL
	Metadata    map[string]interface{} `json:"metadata,omitempty"`     // 元数据
}

// ScanConfig 兼容旧结构体
type ScanConfig struct {
	Target  string
	Ports   []int
	Workers int
	Timeout time.Duration
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name        string   // 服务名称
	Port        int      // 端口号
	Version     string   // 版本号
	Product     string   // 产品名称
	ExtraInfo   string   // 额外信息
	FullBanner  string   // 完整的Banner信息
	Fingerprint string   // 指纹
	CPE         []string // Common Platform Enumeration
	TTL         int      // Time To Live (用于OS检测)
}

// ScanStats 扫描统计信息
type ScanStats struct {
	StartTime     time.Time
	EndTime       time.Time
	TotalPorts    int
	OpenPorts     int
	ClosedPorts   int
	FilteredPorts int
	Errors        int
	ScanRate      float64
}

// ScanError 扫描错误
type ScanError struct {
	Port  int
	Error error
}

// RawScanResult 原始扫描结果
type RawScanResult struct {
	Port    int
	State   PortState
	TTL     int
	OS      string
	Banner  string
	Service string
	Version string
	TCPSeq  uint32
	TCPAck  uint32
	Flags   uint8
	Type    ScanType
}

// NewScanStats 创建新的扫描统计信息
func NewScanStats() *ScanStats {
	return &ScanStats{
		StartTime: time.Now(),
	}
}
