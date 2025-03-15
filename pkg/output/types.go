package output

import (
	"time"
)

// ScanResult 扫描结果
type ScanResult struct {
	Target     string    // 目标主机
	StartTime  time.Time // 开始时间
	EndTime    time.Time // 结束时间
	Ports      []PortResult
	OS         *OSResult
	Statistics Statistics
}

// PortResult 端口扫描结果
type PortResult struct {
	Port      int       // 端口号
	State     string    // 状态 (open/closed/filtered)
	Service   *Service  // 服务信息
	Timestamp time.Time // 扫描时间
}

// Service 服务信息
type Service struct {
	Name    string // 服务名称
	Version string // 版本号
	Product string // 产品名称
}

// OSResult 操作系统识别结果
type OSResult struct {
	Name       string  // 操作系统名称
	Version    string  // 版本号
	Confidence float64 // 置信度
}

// Statistics 统计信息
type Statistics struct {
	TotalPorts    int           // 总端口数
	OpenPorts     int           // 开放端口数
	ClosedPorts   int           // 关闭端口数
	FilteredPorts int           // 被过滤端口数
	ScanDuration  time.Duration // 扫描持续时间
}

// OutputFormat 输出格式
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatXML  OutputFormat = "xml"
	FormatHTML OutputFormat = "html"
)

// OutputOptions 输出选项
type OutputOptions struct {
	Format     OutputFormat // 输出格式
	OutputFile string       // 输出文件路径
	Pretty     bool         // 是否美化输出
}
