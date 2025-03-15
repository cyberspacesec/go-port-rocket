package fingerprint

import (
	"time"
)

// OSFingerprint 操作系统指纹
type OSFingerprint struct {
	Name        string            // 操作系统名称
	Version     string            // 版本号
	Confidence  float64           // 置信度 (0-100)
	Features    map[string]string // 特征值
	Probes      []ProbeResult     // 探测结果
	LastUpdated time.Time         // 最后更新时间
}

// ServiceFingerprint 服务指纹
type ServiceFingerprint struct {
	Name        string            // 服务名称
	Version     string            // 版本号
	Product     string            // 产品名称
	Confidence  float64           // 置信度 (0-100)
	Features    map[string]string // 特征值
	Probes      []ProbeResult     // 探测结果
	LastUpdated time.Time         // 最后更新时间
}

// ProbeResult 探测结果
type ProbeResult struct {
	Type      string            // 探测类型
	Target    string            // 目标
	Port      int               // 端口
	Protocol  string            // 协议
	Data      []byte            // 原始数据
	Response  []byte            // 响应数据
	Timestamp time.Time         // 时间戳
	Features  map[string]string // 特征值
}

// FingerprintOptions 指纹识别选项
type FingerprintOptions struct {
	EnableOSDetection      bool          // 启用操作系统检测
	EnableServiceDetection bool          // 启用服务检测
	VersionIntensity       int           // 版本检测强度 (0-9)
	MaxProbes              int           // 最大探测次数
	Timeout                time.Duration // 超时时间
	GuessOS                bool          // 是否推测操作系统
	LimitOSScan            bool          // 是否限制操作系统扫描
}

// DefaultFingerprintOptions 默认指纹识别选项
func DefaultFingerprintOptions() *FingerprintOptions {
	return &FingerprintOptions{
		EnableOSDetection:      true,
		EnableServiceDetection: true,
		VersionIntensity:       7,
		MaxProbes:              5,
		Timeout:                time.Second * 5,
		GuessOS:                true,
		LimitOSScan:            false,
	}
}

// FingerprintDB 指纹数据库接口
type FingerprintDB interface {
	// OS指纹相关
	LoadOSFingerprints() error
	SaveOSFingerprints() error
	AddOSFingerprint(fp *OSFingerprint) error
	MatchOSFingerprint(fp *OSFingerprint) ([]OSFingerprint, error)

	// 服务指纹相关
	LoadServiceFingerprints() error
	SaveServiceFingerprints() error
	AddServiceFingerprint(fp *ServiceFingerprint) error
	MatchServiceFingerprint(fp *ServiceFingerprint) ([]ServiceFingerprint, error)
}

// Service 服务信息
type Service struct {
	Name       string            `json:"name"`        // 服务名称
	Version    string            `json:"version"`     // 服务版本
	Product    string            `json:"product"`     // 产品名称
	Protocol   string            `json:"protocol"`    // 协议
	DeviceType string            `json:"device_type"` // 设备类型
	CPE        []string          `json:"cpe"`         // CPE标识
	Banner     string            `json:"banner"`      // 服务横幅
	Confidence float64           `json:"confidence"`  // 置信度
	Metadata   map[string]string `json:"metadata"`    // 元数据
}

// OSInfo 操作系统信息
type OSInfo struct {
	Name         string            `json:"name"`         // 操作系统名称
	Family       string            `json:"family"`       // 操作系统家族
	Generation   string            `json:"generation"`   // 操作系统代
	Version      string            `json:"version"`      // 操作系统版本
	Kernel       string            `json:"kernel"`       // 内核版本
	Architecture string            `json:"architecture"` // 系统架构
	CPE          []string          `json:"cpe"`          // CPE标识
	Confidence   float64           `json:"confidence"`   // 置信度
	Metadata     map[string]string `json:"metadata"`     // 元数据
}

// MatchResult 匹配结果
type MatchResult struct {
	Service *Service `json:"service,omitempty"`  // 服务匹配结果
	OS      *OSInfo  `json:"os,omitempty"`       // 操作系统匹配结果
	RawData []byte   `json:"raw_data,omitempty"` // 原始数据
	Error   string   `json:"error,omitempty"`    // 错误信息
}

// Feature 特征
type Feature struct {
	Name   string   `json:"name"`   // 特征名称
	Value  string   `json:"value"`  // 特征值
	Weight float64  `json:"weight"` // 权重
	Tags   []string `json:"tags"`   // 标签
}

// Probe 探测规则
type Probe struct {
	Name        string   `json:"name"`         // 规则名称
	Protocol    string   `json:"protocol"`     // 协议
	Ports       []int    `json:"ports"`        // 目标端口
	Data        []byte   `json:"data"`         // 探测数据
	Timeout     int      `json:"timeout"`      // 超时时间
	Matches     []string `json:"matches"`      // 匹配规则
	SoftMatches []string `json:"soft_matches"` // 软匹配规则
	Rarity      int      `json:"rarity"`       // 稀有度
	Fallback    string   `json:"fallback"`     // 回退规则
}

// Database 指纹数据库
type Database struct {
	Services   map[string]*Service `json:"services"`    // 服务指纹
	OSes       map[string]*OSInfo  `json:"oses"`        // 操作系统指纹
	Probes     map[string]*Probe   `json:"probes"`      // 探测规则
	Features   map[string]*Feature `json:"features"`    // 特征库
	LastUpdate string              `json:"last_update"` // 最后更新时间
	Version    string              `json:"version"`     // 数据库版本
}
