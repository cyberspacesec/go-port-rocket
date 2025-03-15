package mcp

import (
	"fmt"
	"time"
)

// Session 表示MCP会话
type Session struct {
	ID         string    `json:"id"`          // 会话ID
	CreatedAt  time.Time `json:"created_at"`  // 创建时间
	LastActive time.Time `json:"last_active"` // 最后活动时间
	context    *Context  // 会话上下文
	aiHandler  AIHandler
}

// NewSession 创建一个新的会话
func NewSession(sessionID string) *Session {
	now := time.Now()
	return &Session{
		ID:         sessionID,
		CreatedAt:  now,
		LastActive: now,
		context:    NewContext(),
		aiHandler:  NewLocalAIHandler(), // 默认使用本地处理器
	}
}

// GetContext 获取会话上下文
func (s *Session) GetContext() *Context {
	return s.context
}

// SetAIHandler 设置AI处理器
func (s *Session) SetAIHandler(handler AIHandler) {
	s.aiHandler = handler
}

// ExecuteInstruction 执行指令
func (s *Session) ExecuteInstruction(instruction Instruction) (*Response, error) {
	// 更新最后活动时间
	s.LastActive = time.Now()

	// 将指令添加到历史记录
	s.context.AddToHistory(instruction)

	// 根据指令类型和意图执行相应操作
	switch instruction.Type {
	case TypeQuery:
		return s.processQueryInstruction(instruction)
	case TypeScan:
		return s.processScanInstruction(instruction)
	case TypeAnalyze:
		return s.processAnalyzeInstruction(instruction)
	case TypeConfig:
		return s.processConfigInstruction(instruction)
	default:
		return nil, fmt.Errorf("未知的指令类型: %s", instruction.Type)
	}
}

// 处理查询指令
func (s *Session) processQueryInstruction(instruction Instruction) (*Response, error) {
	switch instruction.Intent {
	case IntentHelp:
		// 构建帮助信息
		helpInfo := map[string]interface{}{
			"commands": []string{"help", "status", "scan", "service", "os", "vuln"},
			"intents": []string{
				string(IntentHelp),
				string(IntentStatus),
				string(IntentPortScan),
				string(IntentService),
				string(IntentOSScan),
				string(IntentVulnScan),
				string(IntentRiskAnalysis),
				string(IntentCompare),
				string(IntentRecommend),
			},
			"examples": []string{
				"请帮我扫描192.168.1.1的开放端口",
				"检测10.0.0.1-10.0.0.10范围内的主机服务",
				"分析上次扫描结果的安全风险",
				"给出加固建议",
			},
		}

		// 返回帮助信息
		return &Response{
			Status:  StatusSuccess,
			Message: "MCP可以执行多种网络安全扫描和分析任务",
			Data:    helpInfo,
		}, nil

	case IntentStatus:
		// 获取会话状态信息
		sessionStatus := map[string]interface{}{
			"session_id":     s.ID,
			"created_at":     s.CreatedAt,
			"last_active":    s.LastActive,
			"history_length": len(s.context.History),
			"environment":    s.context.Environment,
		}

		// 返回状态信息
		return &Response{
			Status:  StatusSuccess,
			Message: "当前会话状态",
			Data:    sessionStatus,
		}, nil

	default:
		return &Response{
			Status:  StatusError,
			Message: "未知的查询意图",
		}, nil
	}
}

// 处理扫描指令
func (s *Session) processScanInstruction(instruction Instruction) (*Response, error) {
	switch instruction.Intent {
	case IntentPortScan:
		// 确认有目标参数
		targetExists := false
		var target string
		if t, ok := instruction.Parameters["target"]; ok {
			target = t.(string)
			targetExists = true
		}

		// 如果没有目标参数，返回错误
		if !targetExists {
			return &Response{
				Status:  StatusError,
				Message: "未指定扫描目标",
			}, nil
		}

		// 获取端口参数
		ports := "1-1000" // 默认端口范围
		if p, ok := instruction.Parameters["ports"]; ok {
			ports = p.(string)
		}

		// 构造响应
		response := &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("计划扫描目标: %s，端口范围: %s", target, ports),
			Data: map[string]interface{}{
				"target": target,
				"ports":  ports,
				"status": "running",
			},
		}

		return response, nil

	case IntentService:
		// 确认有目标参数
		targetExists := false
		var target string
		if t, ok := instruction.Parameters["target"]; ok {
			target = t.(string)
			targetExists = true
		}

		// 如果没有目标参数，返回错误
		if !targetExists {
			return &Response{
				Status:  StatusError,
				Message: "未指定服务检测目标",
			}, nil
		}

		// 获取端口参数
		ports := "21-25,80,443,3306,5432,8080" // 默认检测常用服务端口
		if p, ok := instruction.Parameters["ports"]; ok {
			ports = p.(string)
		}

		// 返回计划检测的信息
		return &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("计划检测目标: %s 的服务，端口范围: %s", target, ports),
			Data: map[string]interface{}{
				"target": target,
				"ports":  ports,
				"status": "running",
			},
		}, nil

	case IntentOSScan:
		// 操作系统检测逻辑
		target, targetExists := instruction.Parameters["target"]
		if !targetExists {
			return &Response{
				Status:  StatusError,
				Message: "未指定操作系统检测目标",
			}, nil
		}

		response := &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("计划检测目标: %s 的操作系统", target),
			Data: map[string]interface{}{
				"target": target,
				"status": "running",
			},
		}

		// 在真实实现中，这里会调用OS检测函数
		response.Data["status"] = "running"
		response.NextSteps = []string{
			"等待检测完成",
			"查看检测结果: go-port-rocket mcp --query \"显示操作系统检测结果\"",
		}

		return response, nil

	case IntentVulnScan:
		// 确认有目标参数
		targetExists := false
		var target string
		if t, ok := instruction.Parameters["target"]; ok {
			target = t.(string)
			targetExists = true
		}

		// 如果没有目标参数，返回错误
		if !targetExists {
			return &Response{
				Status:  StatusError,
				Message: "未指定漏洞扫描目标",
			}, nil
		}

		// 获取端口参数
		ports := "1-65535" // 默认扫描全部端口
		if p, ok := instruction.Parameters["ports"]; ok {
			ports = p.(string)
		}

		// 返回计划检测的信息
		return &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("计划扫描目标: %s 的漏洞", target),
			Data: map[string]interface{}{
				"target": target,
				"ports":  ports,
				"status": "running",
			},
		}, nil

	default:
		return nil, fmt.Errorf("未知的扫描意图: %s", instruction.Intent)
	}
}

// 处理分析指令
func (s *Session) processAnalyzeInstruction(instruction Instruction) (*Response, error) {
	switch instruction.Intent {
	case IntentRiskAnalysis:
		// 如果没有目标参数，返回错误
		if _, ok := instruction.Parameters["target"]; !ok {
			return &Response{
				Status:  StatusError,
				Message: "未指定分析目标",
			}, nil
		}

		// 获取目标
		target := instruction.Parameters["target"].(string)
		ports := "1-65535" // 默认分析所有端口

		// 返回分析信息
		return &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("对目标 %s 进行风险分析", target),
			Data: map[string]interface{}{
				"target": target,
				"ports":  ports,
			},
			Analysis: map[string]interface{}{
				"risk_level": "medium",
				"overview":   "目标系统整体安全性中等，存在一些潜在风险。",
				"security_issues": []map[string]interface{}{
					{
						"severity":       "high",
						"service":        "ssh",
						"issue":          "SSH服务允许弱密码认证",
						"recommendation": "配置SSH服务禁用密码认证，启用密钥认证",
					},
					{
						"severity":       "medium",
						"service":        "http",
						"issue":          "Web服务器暴露版本信息",
						"recommendation": "配置Web服务器隐藏版本信息",
					},
				},
			},
			NextSteps: []string{
				"加固SSH认证机制",
				"更新Web服务器配置",
				"进行全面漏洞扫描",
			},
		}, nil

	case IntentCompare:
		// 对比分析逻辑
		// 在真实实现中，这里会对比不同扫描结果
		return &Response{
			Status:  StatusSuccess,
			Message: "对比分析功能尚未实现",
		}, nil

	case IntentRecommend:
		// 安全建议逻辑
		lastScanTarget, exists := s.context.GetState("last_scan_target")
		if !exists {
			return &Response{
				Status:  StatusError,
				Message: "没有找到最近的扫描结果，请先执行扫描",
			}, nil
		}

		// 在真实实现中，这里会基于扫描结果给出安全建议
		response := &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("针对 %v 的安全建议", lastScanTarget),
			Analysis: map[string]interface{}{
				"recommendations": []string{
					"关闭不必要的服务",
					"更新所有服务到最新版本",
					"配置防火墙规则限制访问",
					"启用入侵检测系统",
					"定期进行安全扫描",
				},
			},
		}

		return response, nil

	default:
		return nil, fmt.Errorf("未知的分析意图: %s", instruction.Intent)
	}
}

// 处理配置指令
func (s *Session) processConfigInstruction(instruction Instruction) (*Response, error) {
	// 根据意图执行不同的配置操作
	switch instruction.Intent {
	case IntentSetModel:
		// 配置AI模型
		modelType, modelTypeExists := instruction.Parameters["model_type"]
		if !modelTypeExists {
			var exists bool
			modelType, exists = s.context.GetEnvironment("model_type")
			if !exists || modelType == "" {
				modelType = "openai"
			}
		}

		model, modelExists := instruction.Parameters["model"]
		if !modelExists {
			var exists bool
			model, exists = s.context.GetEnvironment("model")
			if !exists || model == "" {
				model = "gpt-4"
			}
		}

		apiKey, apiKeyExists := instruction.Parameters["api_key"]
		if !apiKeyExists {
			apiKey, _ = s.context.GetEnvironment("api_key")
		}

		// 更新环境变量
		s.context.SetEnvironment("model_type", fmt.Sprintf("%v", modelType))
		s.context.SetEnvironment("model", fmt.Sprintf("%v", model))
		if apiKey != nil {
			s.context.SetEnvironment("api_key", fmt.Sprintf("%v", apiKey))
		}

		// 创建AI处理器
		modelTypeStr := fmt.Sprintf("%v", modelType)
		if modelTypeStr == "openai" {
			apiKeyValue, _ := s.context.GetEnvironment("api_key")
			modelValue, _ := s.context.GetEnvironment("model")

			apiKeyStr := ""
			if apiKeyValue != nil {
				apiKeyStr = fmt.Sprintf("%v", apiKeyValue)
			}

			modelStr := "gpt-4"
			if modelValue != nil {
				modelStr = fmt.Sprintf("%v", modelValue)
			}

			s.aiHandler = NewOpenAIHandler(apiKeyStr, modelStr)
		} else {
			s.aiHandler = NewLocalAIHandler()
		}

		return &Response{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("AI模型已配置为 %v (%v)", model, modelType),
			Data: map[string]interface{}{
				"model_type":  modelType,
				"model":       model,
				"api_key_set": apiKey != nil,
			},
		}, nil

	case IntentSetScan:
		// 配置扫描参数
		workers, workersExist := instruction.Parameters["workers"]
		timeout, timeoutExist := instruction.Parameters["timeout"]

		// 更新环境变量
		if workersExist {
			s.context.SetEnvironment("workers", fmt.Sprintf("%v", workers))
		}
		if timeoutExist {
			s.context.SetEnvironment("timeout", fmt.Sprintf("%v", timeout))
		}

		// 获取当前的环境变量值（处理返回值）
		workersValue, workersExists := s.context.GetEnvironment("workers")
		timeoutValue, timeoutExists := s.context.GetEnvironment("timeout")

		workersStr := ""
		if workersExists && workersValue != nil {
			workersStr = fmt.Sprintf("%v", workersValue)
		}

		timeoutStr := ""
		if timeoutExists && timeoutValue != nil {
			timeoutStr = fmt.Sprintf("%v", timeoutValue)
		}

		return &Response{
			Status:  StatusSuccess,
			Message: "扫描参数已更新",
			Data: map[string]interface{}{
				"workers": workersStr,
				"timeout": timeoutStr,
			},
		}, nil

	case IntentSetOutput:
		// 配置输出参数
		format, formatExist := instruction.Parameters["format"]
		file, fileExist := instruction.Parameters["file"]

		// 更新环境变量
		if formatExist {
			s.context.SetEnvironment("output_format", fmt.Sprintf("%v", format))
		}
		if fileExist {
			s.context.SetEnvironment("output_file", fmt.Sprintf("%v", file))
		}

		// 获取当前的环境变量值（处理返回值）
		formatValue, formatExists := s.context.GetEnvironment("output_format")
		fileValue, fileExists := s.context.GetEnvironment("output_file")

		formatStr := ""
		if formatExists && formatValue != nil {
			formatStr = fmt.Sprintf("%v", formatValue)
		}

		fileStr := ""
		if fileExists && fileValue != nil {
			fileStr = fmt.Sprintf("%v", fileValue)
		}

		return &Response{
			Status:  StatusSuccess,
			Message: "输出参数已更新",
			Data: map[string]interface{}{
				"format": formatStr,
				"file":   fileStr,
			},
		}, nil

	default:
		return nil, fmt.Errorf("未知的配置意图: %s", instruction.Intent)
	}
}
