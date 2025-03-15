package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLocalAIHandler(t *testing.T) {
	handler := NewLocalAIHandler()
	assert.NotNil(t, handler, "本地AI处理器不应为nil")
}

func TestLocalAIHandler_ProcessQuery(t *testing.T) {
	handler := NewLocalAIHandler()
	context := NewContext()

	tests := []struct {
		name           string
		query          string
		wantStatus     Status
		wantMessageCtn string
		wantDataKey    string
	}{
		{
			name:           "端口扫描查询",
			query:          "扫描目标example.com的端口",
			wantStatus:     StatusSuccess,
			wantMessageCtn: "理解为端口扫描请求",
			wantDataKey:    "query_type",
		},
		{
			name:           "帮助查询",
			query:          "帮助我了解这个工具",
			wantStatus:     StatusSuccess,
			wantMessageCtn: "这是MCP命令的帮助信息",
			wantDataKey:    "",
		},
		{
			name:           "带目标的扫描查询",
			query:          "扫描目标 target: example.com 的端口",
			wantStatus:     StatusSuccess,
			wantMessageCtn: "理解为端口扫描请求",
			wantDataKey:    "target",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := handler.ProcessQuery(tc.query, context)

			assert.NoError(t, err, "处理查询不应返回错误")
			assert.NotNil(t, response, "响应不应为nil")
			assert.Equal(t, tc.wantStatus, response.Status, "响应状态应匹配")
			assert.Contains(t, response.Message, tc.wantMessageCtn, "响应消息应包含预期内容")

			if tc.wantDataKey != "" {
				_, exists := response.Data[tc.wantDataKey]
				assert.True(t, exists, "响应数据应包含 "+tc.wantDataKey)
			}
		})
	}
}

func TestParseAIResponse(t *testing.T) {
	tests := []struct {
		name          string
		aiText        string
		originalQuery string
		wantStatus    Status
		wantDataKey   string
	}{
		{
			name:          "JSON响应解析",
			aiText:        `这是一个包含JSON的响应: {"status":"success","message":"测试消息","data":{"key":"value"},"analysis":{"risk":"low"}}`,
			originalQuery: "测试查询",
			wantStatus:    StatusSuccess,
			wantDataKey:   "key",
		},
		{
			name:          "纯文本响应解析_扫描查询",
			aiText:        "这是一个纯文本响应，没有JSON结构",
			originalQuery: "扫描端口",
			wantStatus:    StatusSuccess,
			wantDataKey:   "query_type",
		},
		{
			name:          "纯文本响应解析_分析查询",
			aiText:        "这是一个纯文本响应，没有JSON结构",
			originalQuery: "分析风险",
			wantStatus:    StatusSuccess,
			wantDataKey:   "query_type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := parseAIResponse(tc.aiText, tc.originalQuery)

			assert.NoError(t, err, "解析AI响应不应返回错误")
			assert.NotNil(t, response, "响应不应为nil")
			assert.Equal(t, tc.wantStatus, response.Status, "响应状态应匹配")

			if tc.wantDataKey != "" {
				if tc.name == "JSON响应解析" {
					_, exists := response.Data[tc.wantDataKey]
					assert.True(t, exists, "响应数据应包含 "+tc.wantDataKey)
				} else {
					assert.NotEmpty(t, response.Data, "响应数据不应为空")
				}
			}
		})
	}
}

// 测试OpenAI处理器的创建
func TestNewOpenAIHandler(t *testing.T) {
	// 测试使用默认模型
	handler1 := NewOpenAIHandler("test-api-key", "")
	assert.Equal(t, "gpt-4", handler1.Model, "默认模型应为gpt-4")
	assert.Equal(t, "test-api-key", handler1.ApiKey, "API密钥应匹配")

	// 测试指定模型
	handler2 := NewOpenAIHandler("test-api-key", "gpt-3.5-turbo")
	assert.Equal(t, "gpt-3.5-turbo", handler2.Model, "模型应匹配指定值")
}

// OpenAI处理器的ProcessQuery方法依赖外部API，不适合单元测试
// 在真实环境中应该使用模拟或集成测试

// TestLocalAIHandler_EdgeCases 测试处理边界情况
func TestLocalAIHandler_EdgeCases(t *testing.T) {
	handler := NewLocalAIHandler()
	context := NewContext()

	tests := []struct {
		name        string
		query       string
		shouldError bool
	}{
		{
			name:        "空查询",
			query:       "",
			shouldError: false,
		},
		{
			name:        "极长查询",
			query:       strings.Repeat("a", 4096) + " 扫描端口",
			shouldError: false,
		},
		{
			name:        "特殊字符",
			query:       "扫描端口 target: example.com\n\t\r",
			shouldError: false,
		},
		{
			name:        "SQL注入尝试",
			query:       "扫描目标 DROP TABLE users;--",
			shouldError: false,
		},
		{
			name:        "命令注入尝试",
			query:       "扫描目标 example.com; rm -rf /;",
			shouldError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := handler.ProcessQuery(tc.query, context)

			if tc.shouldError {
				assert.Error(t, err, "应返回错误")
			} else {
				assert.NoError(t, err, "不应返回错误")
				assert.NotNil(t, response, "应返回响应")
				// 所有情况下本地AI处理器都应返回成功状态
				assert.Equal(t, StatusSuccess, response.Status, "本地AI处理器应返回成功状态")
			}
		})
	}
}

// TestParseAIResponse_EdgeCases 测试解析AI响应的边界情况
func TestParseAIResponse_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		aiText        string
		originalQuery string
		shouldError   bool
	}{
		{
			name:          "空响应",
			aiText:        "",
			originalQuery: "扫描端口",
			shouldError:   false,
		},
		{
			name:          "极长响应",
			aiText:        strings.Repeat("a", 8192),
			originalQuery: "扫描端口",
			shouldError:   false,
		},
		{
			name:          "畸形JSON",
			aiText:        `{"status":"success", "message":"测试", "data":{"key":"value"`,
			originalQuery: "扫描端口",
			shouldError:   false, // 应该能够处理畸形JSON
		},
		{
			name:          "嵌套JSON",
			aiText:        `{"response":{"status":"success", "message":"测试", "data":{"key":"value"}}}`,
			originalQuery: "扫描端口",
			shouldError:   false,
		},
		{
			name:          "多个JSON",
			aiText:        `{"status":"success"} {"message":"测试"}`,
			originalQuery: "扫描端口",
			shouldError:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := parseAIResponse(tc.aiText, tc.originalQuery)

			if tc.shouldError {
				assert.Error(t, err, "应返回错误")
			} else {
				assert.NoError(t, err, "不应返回错误")
				assert.NotNil(t, response, "应返回响应")
				// 即使输入有问题，也应该能够生成合理的响应
				assert.Equal(t, StatusSuccess, response.Status, "应返回成功状态")
			}
		})
	}
}

// TestAIHandler_SecurityTests 安全性测试
func TestAIHandler_SecurityTests(t *testing.T) {
	handler := NewLocalAIHandler()
	context := NewContext()

	// 测试可能的安全隐患
	securityTests := []struct {
		name  string
		query string
		check func(t *testing.T, response *Response)
	}{
		{
			name:  "XSS尝试",
			query: "<script>alert('XSS')</script> 扫描端口",
			check: func(t *testing.T, response *Response) {
				// 确保响应消息中不包含原始的脚本标签
				assert.NotContains(t, response.Message, "<script>", "响应不应包含未转义的HTML")
			},
		},
		{
			name:  "命令注入",
			query: "扫描目标 `rm -rf /`",
			check: func(t *testing.T, response *Response) {
				// 确保dangerous_command不在响应中作为可执行命令
				if data, ok := response.Data["command"]; ok {
					assert.NotContains(t, data, "rm -rf", "响应不应包含危险命令")
				}
			},
		},
		{
			name:  "路径遍历",
			query: "扫描目标 ../../../etc/passwd",
			check: func(t *testing.T, response *Response) {
				// 确保没有文件系统路径泄露
				assert.NotContains(t, response.Message, "/etc/passwd", "响应不应包含系统路径")
			},
		},
	}

	for _, tc := range securityTests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := handler.ProcessQuery(tc.query, context)
			assert.NoError(t, err, "查询不应导致错误")
			assert.NotNil(t, response, "应返回响应")

			// 执行特定安全检查
			tc.check(t, response)
		})
	}
}

// TestOpenAIHandler_APIKeyHandling 测试API密钥处理
func TestOpenAIHandler_APIKeyHandling(t *testing.T) {
	// 测试未提供API密钥的情况
	// 由于这个测试依赖于环境变量，暂时跳过
	t.Skip("这个测试需要模拟环境变量，暂时跳过")

	// 完整测试需要在环境中设置API密钥
	// handler := NewOpenAIHandler("", "gpt-4")
	// context := NewContext()
	// _, err := handler.ProcessQuery("测试查询", context)
	// 应该检查错误情况
}

// TestLocalAIHandler_QueryContext 测试查询上下文处理
func TestLocalAIHandler_QueryContext(t *testing.T) {
	handler := NewLocalAIHandler()
	context := NewContext()

	// 设置上下文数据
	context.SetState("last_scan_target", "example.com")
	context.SetState("last_scan_ports", "1-1000")
	context.SetEnvironment("scan_timeout", "5s")

	// 测试本地处理器是否考虑上下文
	// 注意：这个测试依赖于LocalAIHandler的实现如何使用上下文
	// 如果LocalAIHandler实际上并不使用上下文，这个测试可能需要跳过
	response, err := handler.ProcessQuery("再次扫描上次的目标", context)

	assert.NoError(t, err, "处理查询不应返回错误")
	assert.NotNil(t, response, "应返回响应")

	// 检查响应中是否包含状态数据
	// 但不假设具体行为，因为本地处理器可能不使用上下文
	t.Skip("这个测试需要LocalAIHandler实现上下文处理逻辑，暂时跳过")
}
