package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Protocol 模型上下文协议实现
type Protocol struct {
	sessions map[string]*Session
}

// NewProtocol 创建一个新的协议实例
func NewProtocol() *Protocol {
	return &Protocol{
		sessions: make(map[string]*Session),
	}
}

// CreateSession 创建一个新的会话
func (p *Protocol) CreateSession() (string, error) {
	sessionID := uuid.New().String()
	p.sessions[sessionID] = NewSession(sessionID)
	return sessionID, nil
}

// GetSession 获取指定的会话
func (p *Protocol) GetSession(sessionID string) (*Session, error) {
	session, ok := p.sessions[sessionID]
	if ok {
		// 更新最后活动时间
		session.LastActive = time.Now()
		return session, nil
	}

	return nil, fmt.Errorf("会话不存在: %s", sessionID)
}

// ProcessQuery 处理自然语言查询
func (p *Protocol) ProcessQuery(query string, sessionID string) (*Response, error) {
	var session *Session
	var err error

	// 如果没有会话ID，则创建一个新会话
	if sessionID == "" {
		sessionID, err = p.CreateSession()
		if err != nil {
			return nil, err
		}
	}

	// 获取会话
	session, err = p.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	// 分析查询，确定指令类型和意图
	instType, intent, params := p.analyzeQuery(query)

	// 创建指令
	instruction := Instruction{
		Type:       instType,
		Intent:     intent,
		Query:      query,
		Parameters: params,
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)
	if err != nil {
		return nil, err
	}

	// 添加会话ID到响应
	response.SessionID = sessionID

	return response, nil
}

// ExportSession 导出会话
func (p *Protocol) ExportSession(sessionID string) ([]byte, error) {
	// 获取会话
	session, err := p.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	// 获取上下文
	context := session.GetContext()

	// 将会话数据封装成可导出的格式
	exportData := struct {
		SessionID   string                 `json:"session_id"`
		CreatedAt   time.Time              `json:"created_at"`
		LastActive  time.Time              `json:"last_active"`
		History     []Instruction          `json:"history"`
		Environment map[string]interface{} `json:"environment"`
		State       map[string]interface{} `json:"state"`
	}{
		SessionID:   session.ID,
		CreatedAt:   session.CreatedAt,
		LastActive:  session.LastActive,
		History:     context.History,
		Environment: context.Environment,
		State:       context.State,
	}

	// 序列化为JSON
	return json.Marshal(exportData)
}

// ImportSession 导入会话
func (p *Protocol) ImportSession(data []byte) (string, error) {
	// 解析导入的数据
	var importData struct {
		SessionID   string                 `json:"session_id"`
		CreatedAt   time.Time              `json:"created_at"`
		LastActive  time.Time              `json:"last_active"`
		History     []Instruction          `json:"history"`
		Environment map[string]interface{} `json:"environment"`
		State       map[string]interface{} `json:"state"`
	}

	if err := json.Unmarshal(data, &importData); err != nil {
		return "", fmt.Errorf("解析会话数据失败: %v", err)
	}

	// 创建新会话
	sessionID := importData.SessionID
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	session := NewSession(sessionID)
	session.CreatedAt = importData.CreatedAt
	session.LastActive = importData.LastActive

	// 恢复上下文数据
	context := session.GetContext()
	context.History = importData.History
	context.Environment = importData.Environment
	context.State = importData.State

	// 保存会话
	p.sessions[sessionID] = session

	return sessionID, nil
}

// DeleteSession 删除会话
func (p *Protocol) DeleteSession(sessionID string) error {
	if _, ok := p.sessions[sessionID]; !ok {
		return errors.New("会话不存在")
	}

	delete(p.sessions, sessionID)
	return nil
}

// analyzeQuery 分析查询，确定指令类型和意图
func (p *Protocol) analyzeQuery(query string) (InstructionType, IntentType, map[string]interface{}) {
	// 预处理查询
	query = strings.TrimSpace(strings.ToLower(query))

	// 初始化参数
	params := make(map[string]interface{})

	// 默认指令类型为查询
	instType := TypeQuery

	// 检查是否是扫描指令
	scanKeywords := []string{"scan", "扫描", "discover", "发现", "检测", "探测"}
	for _, kw := range scanKeywords {
		if strings.Contains(query, kw) {
			instType = TypeScan
			break
		}
	}

	// 检查是否是分析指令
	analyzeKeywords := []string{"analyze", "分析", "assessment", "评估", "risk", "风险"}
	for _, kw := range analyzeKeywords {
		if strings.Contains(query, kw) {
			instType = TypeAnalyze
			break
		}
	}

	// 检查是否是配置指令
	configKeywords := []string{"config", "配置", "setting", "设置", "setup", "参数"}
	for _, kw := range configKeywords {
		if strings.Contains(query, kw) {
			instType = TypeConfig
			break
		}
	}

	// 根据指令类型确定意图
	var intent IntentType

	// 提取参数
	switch instType {
	case TypeScan:
		// 提取目标
		target := p.extractParameter(query, "target", "目标", "host", "主机", "ip")
		if target != "" {
			params["target"] = target
		}

		// 提取端口
		ports := p.extractParameter(query, "port", "端口", "ports", "端口范围")
		if ports != "" {
			params["ports"] = ports
		}

		// 提取扫描类型
		scanType := p.extractParameter(query, "type", "类型", "protocol", "协议")
		if scanType != "" {
			params["scan_type"] = scanType
		}

		// 确定扫描意图
		if strings.Contains(query, "port") || strings.Contains(query, "端口") {
			intent = IntentPortScan
		} else if strings.Contains(query, "service") || strings.Contains(query, "服务") {
			intent = IntentService
		} else if strings.Contains(query, "os") || strings.Contains(query, "操作系统") {
			intent = IntentOSScan
		} else if strings.Contains(query, "vuln") || strings.Contains(query, "漏洞") {
			intent = IntentVulnScan
		} else {
			intent = IntentPortScan // 默认为端口扫描
		}

	case TypeAnalyze:
		if strings.Contains(query, "risk") || strings.Contains(query, "风险") {
			intent = IntentRiskAnalysis
		} else if strings.Contains(query, "recommend") || strings.Contains(query, "建议") {
			intent = IntentRecommend
		} else if strings.Contains(query, "compare") || strings.Contains(query, "比较") {
			intent = IntentCompare
		} else {
			intent = IntentRiskAnalysis // 默认为风险分析
		}

	case TypeConfig:
		if strings.Contains(query, "model") || strings.Contains(query, "模型") {
			intent = IntentSetModel

			// 提取模型类型
			modelType := p.extractParameter(query, "model", "模型", "type", "类型")
			if modelType != "" {
				params["model_type"] = modelType
			}

			// 提取API密钥
			apiKey := p.extractParameter(query, "api", "api-key", "apikey", "key", "密钥")
			if apiKey != "" {
				params["api_key"] = apiKey
			}
		} else if strings.Contains(query, "scan") || strings.Contains(query, "扫描") {
			intent = IntentSetScan
		} else if strings.Contains(query, "output") || strings.Contains(query, "输出") {
			intent = IntentSetOutput
		} else {
			intent = IntentSetModel // 默认为设置模型
		}

	case TypeQuery:
		if strings.Contains(query, "help") || strings.Contains(query, "帮助") {
			intent = IntentHelp
		} else if strings.Contains(query, "status") || strings.Contains(query, "状态") {
			intent = IntentStatus
		} else if strings.Contains(query, "explain") || strings.Contains(query, "解释") {
			intent = IntentExplain
		} else if strings.Contains(query, "summary") || strings.Contains(query, "摘要") {
			intent = IntentSummary
		} else {
			intent = IntentHelp // 默认为帮助
		}
	}

	return instType, intent, params
}

// extractParameter 从查询中提取参数
func (p *Protocol) extractParameter(query string, keywords ...string) string {
	for _, keyword := range keywords {
		// 寻找格式如 "keyword: value" 或 "keyword=value" 的模式
		patterns := []string{
			keyword + ":",
			keyword + "=",
			keyword + " ",
		}

		for _, p := range patterns {
			// 简单的正则匹配
			// 这里用字符串操作简化实现
			startIdx := strings.Index(query, p)
			if startIdx >= 0 {
				// 提取值
				startIdx += len(p)
				endIdx := strings.Index(query[startIdx:], " ")

				if endIdx < 0 {
					// 如果没有空格，则取到字符串结尾
					return strings.TrimSpace(query[startIdx:])
				}

				// 提取参数值
				return strings.TrimSpace(query[startIdx : startIdx+endIdx])
			}
		}
	}

	return ""
}

// Status 响应状态类型
type Status string

// InstructionType 指令类型
type InstructionType string

// IntentType 意图类型
type IntentType string

// Instruction 指令结构
type Instruction struct {
	Type       InstructionType        `json:"type"`                 // 指令类型
	Intent     IntentType             `json:"intent"`               // 指令意图
	Query      string                 `json:"query,omitempty"`      // 原始查询
	Parameters map[string]interface{} `json:"parameters,omitempty"` // 参数
	Timestamp  time.Time              `json:"timestamp,omitempty"`  // 时间戳
}

// Response 响应结构
type Response struct {
	Status    Status                 `json:"status"`               // 响应状态
	Message   string                 `json:"message,omitempty"`    // 响应消息
	Data      map[string]interface{} `json:"data,omitempty"`       // 响应数据
	Analysis  map[string]interface{} `json:"analysis,omitempty"`   // 分析结果
	NextSteps []string               `json:"next_steps,omitempty"` // 推荐的下一步
	SessionID string                 `json:"session_id,omitempty"` // 会话ID
}

const (
	// 指令类型常量
	TypeQuery   InstructionType = "query"   // 查询类型
	TypeScan    InstructionType = "scan"    // 扫描类型
	TypeAnalyze InstructionType = "analyze" // 分析类型
	TypeConfig  InstructionType = "config"  // 配置类型

	// 状态常量
	StatusSuccess Status = "success" // 成功
	StatusPending Status = "pending" // 等待中
	StatusError   Status = "error"   // 错误

	// 意图类型常量
	// 查询意图
	IntentHelp    IntentType = "help"    // 帮助
	IntentStatus  IntentType = "status"  // 状态
	IntentExplain IntentType = "explain" // 解释
	IntentSummary IntentType = "summary" // 摘要

	// 扫描意图
	IntentPortScan IntentType = "port_scan" // 端口扫描
	IntentService  IntentType = "service"   // 服务检测
	IntentVulnScan IntentType = "vuln_scan" // 漏洞扫描
	IntentOSScan   IntentType = "os_scan"   // 操作系统检测

	// 分析意图
	IntentRiskAnalysis IntentType = "risk"      // 风险分析
	IntentCompare      IntentType = "compare"   // 比较
	IntentRecommend    IntentType = "recommend" // 建议

	// 配置意图
	IntentSetModel  IntentType = "set_model"  // 设置模型
	IntentSetScan   IntentType = "set_scan"   // 设置扫描参数
	IntentSetOutput IntentType = "set_output" // 设置输出参数
)

// 下面的函数从全局函数改为包级别的辅助函数

// AnalyzeIntent 分析查询意图
func AnalyzeIntent(query string, context *Context) (IntentType, error) {
	// TODO: 实现基于AI的意图分析
	// 这里使用简单的关键词匹配作为示例

	// 检查是否为发现意图
	discoverKeywords := []string{"扫描", "发现", "查找", "检测", "端口", "服务", "scan", "discover", "find", "detect"}
	for _, keyword := range discoverKeywords {
		if contains(query, keyword) {
			return IntentPortScan, nil
		}
	}

	// 检查是否为分析意图
	analyzeKeywords := []string{"分析", "评估", "安全", "风险", "analyze", "assess", "security", "risk"}
	for _, keyword := range analyzeKeywords {
		if contains(query, keyword) {
			return IntentRiskAnalysis, nil
		}
	}

	// 检查是否为检查意图
	checkKeywords := []string{"检查", "验证", "漏洞", "check", "verify", "vulnerability"}
	for _, keyword := range checkKeywords {
		if contains(query, keyword) {
			return IntentVulnScan, nil
		}
	}

	// 检查是否为配置意图
	configKeywords := []string{"配置", "设置", "configure", "setup", "config"}
	for _, keyword := range configKeywords {
		if contains(query, keyword) {
			return IntentSetModel, nil
		}
	}

	// 如果无法确定意图，则基于上下文推断
	if context != nil && len(context.History) > 0 {
		lastInstruction := context.History[len(context.History)-1]
		return lastInstruction.Intent, nil
	}

	return IntentHelp, nil
}

// ExtractParameters 从查询中提取参数
func ExtractParameters(query string, intent IntentType, context *Context) (map[string]interface{}, error) {
	// TODO: 实现基于AI的参数提取
	// 这里使用简单的示例实现

	params := make(map[string]interface{})

	// 提取目标
	targets := extractTargets(query)
	if len(targets) > 0 {
		params["target"] = targets[0]
	} else if context != nil && len(context.History) > 0 {
		// 尝试从上下文中提取目标
		for i := len(context.History) - 1; i >= 0; i-- {
			if p, ok := context.History[i].Parameters["target"]; ok {
				params["target"] = p
				break
			}
		}
	}

	// 提取端口
	ports := extractPorts(query)
	if len(ports) > 0 {
		params["ports"] = ports
	}

	// 根据不同意图设置不同的默认参数
	switch intent {
	case IntentPortScan:
		params["scan_type"] = "tcp"
		params["service_detection"] = true
	case IntentRiskAnalysis:
		params["os_detection"] = true
		params["service_detection"] = true
		params["version_intensity"] = 9
	case IntentVulnScan:
		params["version_intensity"] = 7
		params["service_detection"] = true
	}

	return params, nil
}

// 辅助函数：检查字符串是否包含关键词
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// 辅助函数：从查询中提取目标
func extractTargets(query string) []string {
	// TODO: 实现更智能的目标提取算法
	// 这里使用简单的示例实现
	return []string{}
}

// 辅助函数：从查询中提取端口
func extractPorts(query string) string {
	// TODO: 实现更智能的端口提取算法
	// 这里使用简单的示例实现
	return ""
}
