package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// AIHandler 接口定义了AI模型处理器
type AIHandler interface {
	ProcessQuery(query string, context *Context) (*Response, error)
}

// OpenAIHandler 实现OpenAI API处理
type OpenAIHandler struct {
	ApiKey string
	Model  string
}

// NewOpenAIHandler 创建OpenAI处理器
func NewOpenAIHandler(apiKey, model string) *OpenAIHandler {
	if model == "" {
		model = "gpt-4" // 默认使用GPT-4模型
	}
	return &OpenAIHandler{
		ApiKey: apiKey,
		Model:  model,
	}
}

// ProcessQuery 处理查询
func (h *OpenAIHandler) ProcessQuery(query string, context *Context) (*Response, error) {
	// 如果没有API密钥，尝试从环境变量获取
	apiKey := h.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("未设置OpenAI API密钥，请设置OPENAI_API_KEY环境变量或使用--api-key参数")
		}
	}

	// 准备消息
	messages := []map[string]string{
		{
			"role":    "system",
			"content": "你是一个安全扫描助手，基于Model Context Protocol，可以帮助用户进行端口扫描和安全分析。你需要理解用户的自然语言请求，并将其转换为结构化的指令。",
		},
	}

	// 添加历史消息
	if len(context.History) > 0 {
		for _, instruction := range context.History {
			messages = append(messages, map[string]string{
				"role":    "user",
				"content": instruction.Query,
			})
			// 如果有响应，也添加
			if instruction.Parameters != nil {
				if response, ok := instruction.Parameters["response"]; ok {
					messages = append(messages, map[string]string{
						"role":    "assistant",
						"content": fmt.Sprintf("%v", response),
					})
				}
			}
		}
	}

	// 添加当前查询
	messages = append(messages, map[string]string{
		"role":    "user",
		"content": query,
	})

	// 构造请求
	requestBody := map[string]interface{}{
		"model":       h.Model,
		"messages":    messages,
		"temperature": 0.7,
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	// 发送API请求
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	// 解析响应
	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	// 处理错误
	if errMsg, ok := responseData["error"].(map[string]interface{}); ok {
		return nil, fmt.Errorf("API错误: %v", errMsg["message"])
	}

	// 提取生成的文本
	var generatedText string
	if choices, ok := responseData["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if message, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := message["content"].(string); ok {
					generatedText = content
				}
			}
		}
	}

	if generatedText == "" {
		return nil, fmt.Errorf("无法获取生成的文本")
	}

	// 处理AI响应
	return parseAIResponse(generatedText, query)
}

// parseAIResponse 解析AI响应并转换为结构化响应
func parseAIResponse(aiText, originalQuery string) (*Response, error) {
	// 初始化响应
	response := &Response{
		Status:    StatusSuccess,
		Message:   "",
		Data:      make(map[string]interface{}),
		Analysis:  make(map[string]interface{}),
		NextSteps: []string{},
	}

	// 尝试提取JSON
	jsonStart := strings.Index(aiText, "{")
	jsonEnd := strings.LastIndex(aiText, "}")
	if jsonStart >= 0 && jsonEnd >= 0 && jsonEnd > jsonStart {
		jsonData := aiText[jsonStart : jsonEnd+1]
		var structuredData map[string]interface{}
		if err := json.Unmarshal([]byte(jsonData), &structuredData); err == nil {
			// 提取数据
			if status, ok := structuredData["status"].(string); ok {
				// 将字符串转换为Status类型
				switch status {
				case "success":
					response.Status = StatusSuccess
				case "error":
					response.Status = StatusError
				case "pending":
					response.Status = StatusPending
				default:
					response.Status = StatusSuccess
				}
			}
			if message, ok := structuredData["message"].(string); ok {
				response.Message = message
			}
			if data, ok := structuredData["data"].(map[string]interface{}); ok {
				response.Data = data
			}
			if analysis, ok := structuredData["analysis"].(map[string]interface{}); ok {
				response.Analysis = analysis
			}
			if nextSteps, ok := structuredData["next_steps"].([]interface{}); ok {
				for _, step := range nextSteps {
					if stepStr, ok := step.(string); ok {
						response.NextSteps = append(response.NextSteps, stepStr)
					}
				}
			}
			return response, nil
		}
	}

	// 如果没有提取到JSON，则使用简单的文本处理
	// 提取消息
	response.Message = aiText

	// 基于查询内容进行简单分析
	lowerQuery := strings.ToLower(originalQuery)
	if strings.Contains(lowerQuery, "scan") || strings.Contains(lowerQuery, "扫描") {
		// 可能是扫描相关查询
		if strings.Contains(lowerQuery, "port") || strings.Contains(lowerQuery, "端口") {
			response.Data["query_type"] = "port_scan"
		} else if strings.Contains(lowerQuery, "vuln") || strings.Contains(lowerQuery, "漏洞") {
			response.Data["query_type"] = "vulnerability_scan"
		}
	} else if strings.Contains(lowerQuery, "analyze") || strings.Contains(lowerQuery, "分析") {
		response.Data["query_type"] = "analysis"
	}

	// 返回处理后的响应
	return response, nil
}

// LocalAIHandler 本地AI处理器实现
type LocalAIHandler struct {
	// 本地AI模型配置
}

// NewLocalAIHandler 创建本地AI处理器
func NewLocalAIHandler() *LocalAIHandler {
	return &LocalAIHandler{}
}

// ProcessQuery 处理查询
func (h *LocalAIHandler) ProcessQuery(query string, context *Context) (*Response, error) {
	// 本地AI实现，可以基于规则或简单模型
	// 这里只提供一个简单的实现

	// 初始化响应
	response := &Response{
		Status:    StatusSuccess,
		Message:   "本地AI处理结果",
		Data:      make(map[string]interface{}),
		Analysis:  make(map[string]interface{}),
		NextSteps: []string{},
	}

	// 简单的关键词匹配
	lowerQuery := strings.ToLower(query)

	// 扫描相关
	if strings.Contains(lowerQuery, "scan") || strings.Contains(lowerQuery, "扫描") {
		if strings.Contains(lowerQuery, "port") || strings.Contains(lowerQuery, "端口") {
			response.Message = "理解为端口扫描请求"
			response.Data["query_type"] = "port_scan"

			// 提取目标
			targetIndex := -1
			keywords := []string{"target", "目标", "ip", "host", "主机"}
			for _, keyword := range keywords {
				if idx := strings.Index(lowerQuery, keyword); idx >= 0 {
					targetIndex = idx
					break
				}
			}

			if targetIndex >= 0 {
				parts := strings.Split(lowerQuery[targetIndex:], " ")
				if len(parts) >= 2 {
					target := parts[1]
					target = strings.Trim(target, " :=")
					if target != "" {
						response.Data["target"] = target
					}
				}
			}

			response.NextSteps = append(response.NextSteps, "执行端口扫描")
			response.NextSteps = append(response.NextSteps, "分析开放端口")
		}
	} else if strings.Contains(lowerQuery, "help") || strings.Contains(lowerQuery, "帮助") {
		response.Message = "这是MCP命令的帮助信息。您可以使用自然语言进行以下操作：\n" +
			"1. 扫描端口：「扫描目标 example.com 的端口」\n" +
			"2. 服务检测：「检测 192.168.1.1 上运行的服务」\n" +
			"3. 分析结果：「分析上次扫描的风险」\n" +
			"4. 获取建议：「针对开放端口给出安全建议」"
	}

	return response, nil
}
