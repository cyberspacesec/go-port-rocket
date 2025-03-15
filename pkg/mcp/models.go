package mcp

import (
	"time"
)

// 这个文件包含MCP模块中使用的模型结构定义

// 扫描相关结构体

// ScanResult 扫描结果
type ScanResult struct {
	Target    string          `json:"target"`          // 目标
	StartTime time.Time       `json:"start_time"`      // 开始时间
	EndTime   time.Time       `json:"end_time"`        // 结束时间
	Ports     []PortInfo      `json:"ports"`           // 端口信息
	OS        OSInfo          `json:"os"`              // 操作系统信息
	Services  []Service       `json:"services"`        // 服务信息
	Vulns     []Vulnerability `json:"vulnerabilities"` // 漏洞信息
}

// PortInfo 端口信息
type PortInfo struct {
	Port     int    `json:"port"`     // 端口号
	Protocol string `json:"protocol"` // 协议
	State    string `json:"state"`    // 状态
	Service  string `json:"service"`  // 服务
	Version  string `json:"version"`  // 版本
	Banner   string `json:"banner"`   // 横幅
}

// OSInfo 操作系统信息
type OSInfo struct {
	Name     string   `json:"name"`     // 名称
	Version  string   `json:"version"`  // 版本
	Family   string   `json:"family"`   // 系列
	Accuracy int      `json:"accuracy"` // 准确度
	CPE      []string `json:"cpe"`      // CPE标识
}

// Service 服务信息
type Service struct {
	Name      string   `json:"name"`       // 名称
	Port      int      `json:"port"`       // 端口
	Protocol  string   `json:"protocol"`   // 协议
	Version   string   `json:"version"`    // 版本
	Product   string   `json:"product"`    // 产品
	ExtraInfo string   `json:"extra_info"` // 额外信息
	CPE       []string `json:"cpe"`        // CPE标识
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string   `json:"id"`          // 漏洞ID
	Service     string   `json:"service"`     // 关联服务
	Port        int      `json:"port"`        // 关联端口
	Severity    string   `json:"severity"`    // 严重程度
	Description string   `json:"description"` // 描述
	References  []string `json:"references"`  // 参考链接
	Solution    string   `json:"solution"`    // 解决方案
}
