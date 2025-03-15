package mcp

// Context 表示会话上下文
type Context struct {
	History     []Instruction          `json:"history"`     // 指令历史
	Environment map[string]interface{} `json:"environment"` // 环境变量
	State       map[string]interface{} `json:"state"`       // 状态数据
}

// NewContext 创建一个新的上下文
func NewContext() *Context {
	return &Context{
		History:     make([]Instruction, 0),
		Environment: make(map[string]interface{}),
		State:       make(map[string]interface{}),
	}
}

// AddToHistory 添加指令到历史记录
func (c *Context) AddToHistory(instruction Instruction) {
	c.History = append(c.History, instruction)
	// 保持历史记录不超过一定长度
	if len(c.History) > 20 {
		c.History = c.History[1:]
	}
}

// SetEnvironment 设置环境变量
func (c *Context) SetEnvironment(key string, value interface{}) {
	c.Environment[key] = value
}

// GetEnvironment 获取环境变量
func (c *Context) GetEnvironment(key string) (interface{}, bool) {
	value, exists := c.Environment[key]
	return value, exists
}

// SetState 设置状态数据
func (c *Context) SetState(key string, value interface{}) {
	c.State[key] = value
}

// GetState 获取状态数据
func (c *Context) GetState(key string) (interface{}, bool) {
	value, exists := c.State[key]
	return value, exists
}

// Clear 清除所有上下文数据
func (c *Context) Clear() {
	c.History = make([]Instruction, 0)
	c.Environment = make(map[string]interface{})
	c.State = make(map[string]interface{})
}

// ClearHistory 清除历史记录
func (c *Context) ClearHistory() {
	c.History = make([]Instruction, 0)
}

// ClearState 清除状态数据
func (c *Context) ClearState() {
	c.State = make(map[string]interface{})
}
