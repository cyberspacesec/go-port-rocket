package mcp

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewContext(t *testing.T) {
	context := NewContext()

	assert.NotNil(t, context, "上下文不应为nil")
	assert.Empty(t, context.History, "历史记录应为空")
	assert.Empty(t, context.Environment, "环境变量应为空")
	assert.Empty(t, context.State, "状态数据应为空")
}

func TestAddToHistory(t *testing.T) {
	context := NewContext()

	// 添加一条指令
	instruction1 := Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "帮助我了解这个工具",
	}
	context.AddToHistory(instruction1)

	assert.Len(t, context.History, 1, "历史记录应包含1条指令")
	assert.Equal(t, instruction1, context.History[0], "历史记录中的指令应匹配")

	// 再添加一条指令
	instruction2 := Instruction{
		Type:   TypeScan,
		Intent: IntentPortScan,
		Query:  "扫描目标example.com的开放端口",
	}
	context.AddToHistory(instruction2)

	assert.Len(t, context.History, 2, "历史记录应包含2条指令")
	assert.Equal(t, instruction1, context.History[0], "第一条指令应匹配")
	assert.Equal(t, instruction2, context.History[1], "第二条指令应匹配")
}

func TestHistoryLimitEnforcement(t *testing.T) {
	context := NewContext()

	// 添加21条指令以超过默认的20条限制
	for i := 0; i < 21; i++ {
		instruction := Instruction{
			Type:   TypeQuery,
			Intent: IntentHelp,
			Query:  "指令" + strconv.Itoa(i),
		}
		context.AddToHistory(instruction)
	}

	// 验证历史记录限制为20条
	assert.Len(t, context.History, 20, "历史记录应限制为20条")

	// 验证第一条指令已被移除
	firstInst := context.History[0]
	assert.Equal(t, "指令1", firstInst.Query, "第一条指令应为'指令1'")
}

func TestEnvironmentVariables(t *testing.T) {
	context := NewContext()

	// 测试设置环境变量
	context.SetEnvironment("test_key", "test_value")

	// 验证环境变量已设置
	value, exists := context.GetEnvironment("test_key")
	assert.True(t, exists, "环境变量应存在")
	assert.Equal(t, "test_value", value, "环境变量值应匹配")

	// 测试获取不存在的环境变量
	_, exists = context.GetEnvironment("non_existent_key")
	assert.False(t, exists, "不存在的环境变量应返回不存在")

	// 测试更新环境变量
	context.SetEnvironment("test_key", "updated_value")
	value, _ = context.GetEnvironment("test_key")
	assert.Equal(t, "updated_value", value, "更新后的环境变量值应匹配")
}

func TestStateData(t *testing.T) {
	context := NewContext()

	// 测试设置状态数据
	context.SetState("test_state", "test_state_value")

	// 验证状态数据已设置
	value, exists := context.GetState("test_state")
	assert.True(t, exists, "状态数据应存在")
	assert.Equal(t, "test_state_value", value, "状态数据值应匹配")

	// 测试获取不存在的状态数据
	_, exists = context.GetState("non_existent_state")
	assert.False(t, exists, "不存在的状态数据应返回不存在")

	// 测试更新状态数据
	context.SetState("test_state", "updated_state_value")
	value, _ = context.GetState("test_state")
	assert.Equal(t, "updated_state_value", value, "更新后的状态数据值应匹配")

	// 测试复杂类型状态数据
	complexData := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}
	context.SetState("complex_state", complexData)

	retrievedData, exists := context.GetState("complex_state")
	assert.True(t, exists, "复杂状态数据应存在")
	assert.Equal(t, complexData, retrievedData, "复杂状态数据值应匹配")
}

func TestClearMethods(t *testing.T) {
	context := NewContext()

	// 添加历史记录
	context.AddToHistory(Instruction{
		Type:   TypeQuery,
		Intent: IntentHelp,
		Query:  "帮助指令",
	})

	// 设置环境变量
	context.SetEnvironment("test_env", "test_value")

	// 设置状态数据
	context.SetState("test_state", "test_state_value")

	// 验证数据已设置
	assert.NotEmpty(t, context.History, "历史记录不应为空")
	assert.NotEmpty(t, context.Environment, "环境变量不应为空")
	assert.NotEmpty(t, context.State, "状态数据不应为空")

	// 测试ClearHistory
	context.ClearHistory()
	assert.Empty(t, context.History, "历史记录应为空")
	assert.NotEmpty(t, context.Environment, "环境变量不应为空")
	assert.NotEmpty(t, context.State, "状态数据不应为空")

	// 再次添加历史记录
	context.AddToHistory(Instruction{
		Type:   TypeScan,
		Intent: IntentPortScan,
		Query:  "扫描指令",
	})

	// 测试ClearState
	context.ClearState()
	assert.NotEmpty(t, context.History, "历史记录不应为空")
	assert.NotEmpty(t, context.Environment, "环境变量不应为空")
	assert.Empty(t, context.State, "状态数据应为空")

	// 测试Clear（全部清除）
	context.Clear()
	assert.Empty(t, context.History, "历史记录应为空")
	assert.Empty(t, context.Environment, "环境变量应为空")
	assert.Empty(t, context.State, "状态数据应为空")
}

func TestComplexDataTypes(t *testing.T) {
	context := NewContext()

	// 测试存储各种复杂数据类型

	// 数组
	arrayData := []interface{}{"item1", "item2", "item3"}
	context.SetState("array_data", arrayData)

	// 嵌套映射
	nestedMap := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": "深层数据",
			},
		},
	}
	context.SetState("nested_map", nestedMap)

	// 混合类型
	mixedData := map[string]interface{}{
		"string_key": "字符串值",
		"int_key":    42,
		"bool_key":   true,
		"array_key":  []interface{}{1, 2, 3},
		"map_key": map[string]interface{}{
			"sub_key": "子值",
		},
	}
	context.SetState("mixed_data", mixedData)

	// 验证数据
	retrievedArray, exists := context.GetState("array_data")
	assert.True(t, exists, "数组数据应存在")
	assert.Equal(t, arrayData, retrievedArray, "数组数据应匹配")

	retrievedNestedMap, exists := context.GetState("nested_map")
	assert.True(t, exists, "嵌套映射应存在")
	assert.Equal(t, nestedMap, retrievedNestedMap, "嵌套映射应匹配")

	retrievedMixedData, exists := context.GetState("mixed_data")
	assert.True(t, exists, "混合数据应存在")
	assert.Equal(t, mixedData, retrievedMixedData, "混合数据应匹配")
}
