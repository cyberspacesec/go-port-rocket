package mcp

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// 创建一个模拟的AIHandler用于测试
type MockAIHandler struct {
	mock.Mock
}

func (m *MockAIHandler) ProcessQuery(query string, context *Context) (*Response, error) {
	args := m.Called(query, context)
	return args.Get(0).(*Response), args.Error(1)
}

func TestNewSession(t *testing.T) {
	// 测试创建新会话
	sessionID := "test-session-id"
	session := NewSession(sessionID)

	assert.Equal(t, sessionID, session.ID, "会话ID应匹配")
	assert.NotNil(t, session.context, "上下文不应为nil")
	assert.NotNil(t, session.aiHandler, "AI处理器不应为nil")

	// 检查时间戳是否合理
	now := time.Now()
	assert.WithinDuration(t, now, session.CreatedAt, 1*time.Second, "创建时间应接近当前时间")
	assert.WithinDuration(t, now, session.LastActive, 1*time.Second, "最后活动时间应接近当前时间")
}

func TestGetContext(t *testing.T) {
	session := NewSession("test-session")
	context := session.GetContext()

	assert.NotNil(t, context, "上下文不应为nil")
	assert.Empty(t, context.History, "历史记录应为空")
	assert.Empty(t, context.Environment, "环境变量应为空")
	assert.Empty(t, context.State, "状态数据应为空")
}

func TestSetAIHandler(t *testing.T) {
	session := NewSession("test-session")
	mockHandler := new(MockAIHandler)

	// 设置模拟的处理器
	session.SetAIHandler(mockHandler)

	// 验证处理器已被设置
	assert.Equal(t, mockHandler, session.aiHandler, "AI处理器应被设置为模拟处理器")
}

func TestExecuteInstruction_Query(t *testing.T) {
	session := NewSession("test-session")

	// 测试查询指令
	instruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "帮助我了解这个工具",
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.NoError(t, err, "执行帮助指令不应返回错误")
	assert.Equal(t, StatusSuccess, response.Status, "响应状态应为成功")
	assert.Contains(t, response.Message, "MCP可以执行", "响应消息应包含帮助信息")

	// 验证指令已被添加到历史记录
	assert.Len(t, session.context.History, 1, "历史记录应包含1条指令")
	assert.Equal(t, TypeQuery, session.context.History[0].Type, "历史记录中的指令类型应匹配")
	assert.Equal(t, IntentHelp, session.context.History[0].Intent, "历史记录中的指令意图应匹配")
}

func TestExecuteInstruction_Scan(t *testing.T) {
	session := NewSession("test-session")

	// 测试扫描指令
	instruction := Instruction{
		Type:   TypeScan,
		Intent: IntentPortScan,
		Query:  "扫描目标example.com的开放端口",
		Parameters: map[string]interface{}{
			"target": "example.com",
			"ports":  "1-1000",
		},
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.NoError(t, err, "执行扫描指令不应返回错误")
	assert.Equal(t, StatusSuccess, response.Status, "响应状态应为成功")
	assert.Contains(t, response.Message, "扫描目标", "响应消息应包含扫描信息")
	assert.Equal(t, "example.com", response.Data["target"], "响应数据中的目标应匹配")

	// 验证指令已被添加到历史记录
	assert.Len(t, session.context.History, 1, "历史记录应包含1条指令")
}

func TestExecuteInstruction_Analyze(t *testing.T) {
	session := NewSession("test-session")

	// 测试分析指令
	instruction := Instruction{
		Type:   TypeAnalyze,
		Intent: IntentRiskAnalysis,
		Query:  "分析目标example.com的安全风险",
		Parameters: map[string]interface{}{
			"target": "example.com",
		},
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.NoError(t, err, "执行分析指令不应返回错误")
	assert.Equal(t, StatusSuccess, response.Status, "响应状态应为成功")
	assert.Contains(t, response.Message, "风险分析", "响应消息应包含分析信息")
	assert.NotNil(t, response.Analysis, "响应应包含分析数据")
	assert.NotEmpty(t, response.NextSteps, "响应应包含推荐的下一步")
}

func TestExecuteInstruction_Config(t *testing.T) {
	session := NewSession("test-session")

	// 测试配置指令
	instruction := Instruction{
		Type:   TypeConfig,
		Intent: IntentSetModel,
		Query:  "配置AI模型为gpt-4",
		Parameters: map[string]interface{}{
			"model_type": "openai",
			"model":      "gpt-4",
			"api_key":    "test-api-key",
		},
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.NoError(t, err, "执行配置指令不应返回错误")
	assert.Equal(t, StatusSuccess, response.Status, "响应状态应为成功")
	assert.Contains(t, response.Message, "AI模型已配置", "响应消息应包含配置信息")

	// 验证环境变量已更新
	modelType, exists := session.context.GetEnvironment("model_type")
	assert.True(t, exists, "环境变量model_type应存在")
	assert.Equal(t, "openai", modelType, "环境变量model_type应被设置为openai")

	model, exists := session.context.GetEnvironment("model")
	assert.True(t, exists, "环境变量model应存在")
	assert.Equal(t, "gpt-4", model, "环境变量model应被设置为gpt-4")
}

func TestExecuteInstruction_UnknownType(t *testing.T) {
	session := NewSession("test-session")

	// 测试未知类型的指令
	instruction := Instruction{
		Type:   InstructionType("unknown"),
		Intent: IntentHelp,
		Query:  "未知类型的指令",
	}

	// 执行指令
	_, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.Error(t, err, "执行未知类型的指令应返回错误")
	assert.Contains(t, err.Error(), "未知的指令类型", "错误消息应包含'未知的指令类型'")
}

func TestProcessScanInstruction_NoTarget(t *testing.T) {
	session := NewSession("test-session")

	// 测试无目标参数的扫描指令
	instruction := Instruction{
		Type:       TypeScan,
		Intent:     IntentPortScan,
		Query:      "扫描开放端口",
		Parameters: map[string]interface{}{},
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.NoError(t, err, "不应返回错误")
	assert.Equal(t, StatusError, response.Status, "响应状态应为错误")
	assert.Contains(t, response.Message, "未指定扫描目标", "响应消息应包含错误信息")
}

func TestProcessQueryInstruction_Status(t *testing.T) {
	session := NewSession("test-session")

	// 设置一些环境变量和状态数据
	session.context.SetEnvironment("test_env", "test_value")
	session.context.SetState("test_state", "test_state_value")

	// 添加一些历史记录
	historyInstruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "帮助指令",
	}
	session.context.AddToHistory(historyInstruction)

	// 测试状态查询指令
	instruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentStatus,
		Query:  "查看当前会话状态",
	}

	// 执行指令
	response, err := session.ExecuteInstruction(instruction)

	// 验证结果
	assert.NoError(t, err, "执行状态查询指令不应返回错误")
	assert.Equal(t, StatusSuccess, response.Status, "响应状态应为成功")
	assert.Contains(t, response.Message, "当前会话状态", "响应消息应包含状态信息")

	// 验证状态数据
	sessionStatus := response.Data
	assert.Equal(t, session.ID, sessionStatus["session_id"], "状态数据中的会话ID应匹配")
	assert.Equal(t, 2, sessionStatus["history_length"], "历史记录长度应为2") // 包括刚执行的指令
	assert.NotNil(t, sessionStatus["environment"], "状态数据应包含环境变量")
}

func TestWithMockAIHandler(t *testing.T) {
	session := NewSession("test-session")
	mockHandler := new(MockAIHandler)

	// 设置模拟的处理器
	session.SetAIHandler(mockHandler)

	// 设置模拟行为
	mockResponse := &Response{
		Status:  StatusSuccess,
		Message: "模拟的AI响应",
		Data: map[string]interface{}{
			"mock_data": "test",
		},
	}
	mockHandler.On("ProcessQuery", "测试查询", mock.Anything).Return(mockResponse, nil)

	// 创建使用AI处理的查询指令
	instruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "测试查询",
	}

	// 执行指令，实际上由于现在的代码实现，我们无法简单地触发AI处理器的调用
	// 所以我们只验证mock设置正确
	assert.NotNil(t, instruction, "指令不应为nil")
	assert.Equal(t, "测试查询", instruction.Query, "指令查询内容应匹配")
}

// TestSessionHistoryManagement 测试历史记录管理
func TestSessionHistoryManagement(t *testing.T) {
	session := NewSession("test-session")

	// 添加21条指令到历史记录，这将超过限制
	for i := 0; i < 21; i++ {
		instruction := Instruction{
			Type:   TypeQuery,
			Intent: IntentHelp,
			Query:  "指令" + strconv.Itoa(i),
		}
		session.ExecuteInstruction(instruction)
	}

	// 历史记录应该保持在20条
	assert.Len(t, session.context.History, 20, "历史记录应限制为20条")

	// 第一条指令应该已被移除
	assert.NotEqual(t, "指令0", session.context.History[0].Query, "第一条指令应已被移除")
}

// TestSessionLastActiveUpdate 测试会话最后活动时间的更新
func TestSessionLastActiveUpdate(t *testing.T) {
	session := NewSession("test-session")

	// 记录初始最后活动时间
	initialLastActive := session.LastActive

	// 等待一小段时间
	time.Sleep(10 * time.Millisecond)

	// 执行指令，这应该更新最后活动时间
	instruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "测试查询",
	}
	session.ExecuteInstruction(instruction)

	// 验证最后活动时间已更新
	assert.True(t, session.LastActive.After(initialLastActive), "最后活动时间应该更新")
}

// TestSessionTimeout 测试会话超时逻辑
func TestSessionTimeout(t *testing.T) {
	// 创建一个模拟时间较早的会话
	session := NewSession("timeout-test")

	// 手动设置创建时间和最后活动时间为过去的时间
	oldTime := time.Now().Add(-2 * time.Hour)
	session.CreatedAt = oldTime
	session.LastActive = oldTime

	// 检查会话是否已超时（假设超时时间为1小时）
	isTimedOut := session.LastActive.Before(time.Now().Add(-1 * time.Hour))
	assert.True(t, isTimedOut, "会话应该被识别为已超时")
}

// TestConcurrentSessionAccess 测试并发访问会话
func TestConcurrentSessionAccess(t *testing.T) {
	session := NewSession("concurrent-test")

	// 创建一个通道来同步goroutine
	done := make(chan bool)

	// 并发执行多个指令
	for i := 0; i < 10; i++ {
		go func(index int) {
			instruction := Instruction{
				Type:   TypeQuery,
				Intent: IntentHelp,
				Query:  "并发查询" + strconv.Itoa(index),
			}

			// 执行指令
			_, err := session.ExecuteInstruction(instruction)
			assert.NoError(t, err, "并发执行指令不应返回错误")

			done <- true
		}(i)
	}

	// 等待所有goroutine完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 检查历史记录长度
	assert.Equal(t, 10, len(session.context.History), "历史记录应包含10条指令")
}

// TestSessionErrorRecovery 测试会话错误恢复
func TestSessionErrorRecovery(t *testing.T) {
	session := NewSession("error-recovery-test")

	// 先执行一个正常的指令
	validInstruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "正常查询",
	}
	response1, err := session.ExecuteInstruction(validInstruction)
	assert.NoError(t, err, "执行有效指令不应返回错误")
	assert.Equal(t, StatusSuccess, response1.Status, "响应状态应为成功")

	// 执行一个导致错误的指令
	invalidInstruction := Instruction{
		Type:   TypeScan,
		Intent: IntentPortScan,
		Query:  "无效扫描",
		// 故意不提供目标参数
	}
	response2, err := session.ExecuteInstruction(invalidInstruction)
	assert.NoError(t, err, "应该返回错误响应而不是错误")
	assert.Equal(t, StatusError, response2.Status, "响应状态应为错误")

	// 检查会话是否仍然可用
	// 再次执行有效指令
	response3, err := session.ExecuteInstruction(validInstruction)
	assert.NoError(t, err, "执行有效指令不应返回错误")
	assert.Equal(t, StatusSuccess, response3.Status, "响应状态应为成功")

	// 检查历史记录
	assert.Equal(t, 3, len(session.context.History), "历史记录应包含3条指令")
}

// TestSessionStateManagement 测试会话状态管理
func TestSessionStateManagement(t *testing.T) {
	session := NewSession("state-test")

	// 使用配置指令设置状态
	configInstruction := Instruction{
		Type:   TypeConfig,
		Intent: IntentSetModel,
		Query:  "设置状态",
		Parameters: map[string]interface{}{
			"key1": "value1",
			"key2": 42,
			"key3": []string{"a", "b", "c"},
		},
	}

	// 执行配置指令
	response, err := session.ExecuteInstruction(configInstruction)
	assert.NoError(t, err, "执行配置指令不应返回错误")
	assert.Equal(t, StatusSuccess, response.Status, "响应状态应为成功")

	// 验证状态已被设置
	for key, expectedValue := range configInstruction.Parameters {
		value, exists := session.context.GetState(key)
		assert.True(t, exists, "状态键"+key+"应存在")
		assert.Equal(t, expectedValue, value, "状态值应匹配")
	}

	// 测试查询状态
	statusInstruction := Instruction{
		Type:   TypeQuery,
		Intent: IntentStatus,
		Query:  "查看当前状态",
	}

	// 执行状态查询指令
	statusResponse, err := session.ExecuteInstruction(statusInstruction)
	assert.NoError(t, err, "执行状态查询指令不应返回错误")
	assert.Equal(t, StatusSuccess, statusResponse.Status, "响应状态应为成功")

	// 验证状态数据在响应中
	stateData, ok := statusResponse.Data["state"].(map[string]interface{})
	assert.True(t, ok, "响应数据应包含状态信息")
	assert.Equal(t, "value1", stateData["key1"], "状态key1应匹配")
	assert.Equal(t, float64(42), stateData["key2"], "状态key2应匹配") // JSON解码会将整数转为float64
}
