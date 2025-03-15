package http_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberspacesec/go-port-rocket/pkg/api"
)

var serverURL string

// TestMain 设置测试环境
func setupServer(t *testing.T) func() {
	// 创建一个临时测试服务器
	config := &api.ServerConfig{
		Host:           "localhost",
		Port:           0, // 使用随机可用端口
		JWTSecret:      "test-secret",
		RedisAddr:      "", // 不使用Redis
		TaskTimeout:    10 * time.Second,
		MaxConcurrency: 5,
		QueueSize:      100,
		EnableAuth:     false, // 禁用认证以简化测试
		AllowInMemory:  true,
	}

	server := api.NewServer(config)
	require.NotNil(t, server, "服务器不应为nil")

	// 启动服务器(异步)
	done := make(chan error)
	go func() {
		done <- server.Start()
	}()

	// 等待服务器启动完成
	time.Sleep(500 * time.Millisecond)

	// 获取实际使用的端口
	// 注意: 这里简化实现，假设服务器在localhost:8080监听
	// 实际上，应该从server获取实际监听的地址和端口
	serverURL = "http://localhost:8080"

	// 清理函数
	return func() {
		server.Stop()
	}
}

// 测试创建扫描任务
func TestCreateScanTask(t *testing.T) {
	cleanup := setupServer(t)
	defer cleanup()

	// 准备请求数据
	scanRequest := api.ScanRequest{
		Target:       "example.com",
		Ports:        "1-1000",
		ScanType:     "tcp",
		Timeout:      5 * time.Second,
		Workers:      10,
		OutputFormat: "json",
	}

	reqBody, err := json.Marshal(scanRequest)
	require.NoError(t, err, "序列化请求不应返回错误")

	// 发送创建任务请求
	resp, err := http.Post(fmt.Sprintf("%s/api/tasks", serverURL),
		"application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err, "创建任务请求不应返回错误")
	defer resp.Body.Close()

	// 验证响应状态码
	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "创建任务响应状态码应为202")

	// 解析响应
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "读取响应体不应返回错误")

	var response struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err, "解析响应体不应返回错误")

	// 验证任务ID和状态
	assert.NotEmpty(t, response.TaskID, "任务ID不应为空")
	assert.Equal(t, "pending", response.Status, "初始任务状态应为pending")

	// 等待任务处理
	time.Sleep(1 * time.Second)

	// 获取任务详情
	taskResp, err := http.Get(fmt.Sprintf("%s/api/tasks/%s", serverURL, response.TaskID))
	require.NoError(t, err, "获取任务详情不应返回错误")
	defer taskResp.Body.Close()

	// 验证任务详情响应状态码
	assert.Equal(t, http.StatusOK, taskResp.StatusCode, "获取任务详情响应状态码应为200")
}

// 测试获取任务列表
func TestListTasks(t *testing.T) {
	cleanup := setupServer(t)
	defer cleanup()

	// 创建几个测试任务
	for i := 0; i < 3; i++ {
		// 准备请求数据
		scanRequest := api.ScanRequest{
			Target:       fmt.Sprintf("example%d.com", i),
			Ports:        "1-1000",
			ScanType:     "tcp",
			Timeout:      5 * time.Second,
			Workers:      10,
			OutputFormat: "json",
		}

		reqBody, err := json.Marshal(scanRequest)
		require.NoError(t, err, "序列化请求不应返回错误")

		// 发送创建任务请求
		resp, err := http.Post(fmt.Sprintf("%s/api/tasks", serverURL),
			"application/json", bytes.NewBuffer(reqBody))
		require.NoError(t, err, "创建任务请求不应返回错误")
		resp.Body.Close()
	}

	// 等待任务创建完成
	time.Sleep(500 * time.Millisecond)

	// 获取任务列表
	listResp, err := http.Get(fmt.Sprintf("%s/api/tasks", serverURL))
	require.NoError(t, err, "获取任务列表不应返回错误")
	defer listResp.Body.Close()

	// 验证响应状态码
	assert.Equal(t, http.StatusOK, listResp.StatusCode, "获取任务列表响应状态码应为200")

	// 解析响应
	body, err := io.ReadAll(listResp.Body)
	require.NoError(t, err, "读取响应体不应返回错误")

	var response struct {
		Tasks []api.Task `json:"tasks"`
		Total int        `json:"total"`
	}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err, "解析响应体不应返回错误")

	// 验证任务数量
	assert.GreaterOrEqual(t, response.Total, 3, "总任务数应大于等于3")
	assert.GreaterOrEqual(t, len(response.Tasks), 3, "响应任务数应大于等于3")
}

// 测试取消任务
func TestCancelTask(t *testing.T) {
	cleanup := setupServer(t)
	defer cleanup()

	// 创建一个任务
	scanRequest := api.ScanRequest{
		Target:       "example.com",
		Ports:        "1-1000",
		ScanType:     "tcp",
		Timeout:      5 * time.Second,
		Workers:      10,
		OutputFormat: "json",
	}

	reqBody, err := json.Marshal(scanRequest)
	require.NoError(t, err, "序列化请求不应返回错误")

	// 发送创建任务请求
	resp, err := http.Post(fmt.Sprintf("%s/api/tasks", serverURL),
		"application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err, "创建任务请求不应返回错误")

	// 解析响应获取任务ID
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "读取响应体不应返回错误")

	var createResponse struct {
		TaskID string `json:"task_id"`
	}
	err = json.Unmarshal(body, &createResponse)
	require.NoError(t, err, "解析响应体不应返回错误")
	require.NotEmpty(t, createResponse.TaskID, "任务ID不应为空")

	// 取消任务
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/api/tasks/%s", serverURL, createResponse.TaskID), nil)
	require.NoError(t, err, "创建删除请求不应返回错误")

	cancelResp, err := client.Do(req)
	require.NoError(t, err, "发送删除请求不应返回错误")
	defer cancelResp.Body.Close()

	// 验证响应状态码
	assert.Equal(t, http.StatusOK, cancelResp.StatusCode, "取消任务响应状态码应为200")

	// 等待取消操作完成
	time.Sleep(500 * time.Millisecond)

	// 获取任务详情，验证任务状态
	taskResp, err := http.Get(fmt.Sprintf("%s/api/tasks/%s", serverURL, createResponse.TaskID))
	require.NoError(t, err, "获取任务详情不应返回错误")
	defer taskResp.Body.Close()

	// 解析响应
	taskBody, err := io.ReadAll(taskResp.Body)
	require.NoError(t, err, "读取响应体不应返回错误")

	var taskResponse api.Task
	err = json.Unmarshal(taskBody, &taskResponse)
	require.NoError(t, err, "解析响应体不应返回错误")

	// 验证任务状态为已取消
	assert.Equal(t, "cancelled", taskResponse.Status, "任务状态应为cancelled")
}

// 测试系统状态API
func TestSystemStatus(t *testing.T) {
	cleanup := setupServer(t)
	defer cleanup()

	// 获取系统状态
	resp, err := http.Get(fmt.Sprintf("%s/api/system/status", serverURL))
	require.NoError(t, err, "获取系统状态不应返回错误")
	defer resp.Body.Close()

	// 验证响应状态码
	assert.Equal(t, http.StatusOK, resp.StatusCode, "获取系统状态响应状态码应为200")

	// 解析响应
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "读取响应体不应返回错误")

	var response struct {
		Status    string `json:"status"`
		Version   string `json:"version"`
		Tasks     int    `json:"tasks"`
		Uptime    int64  `json:"uptime"`
		Timestamp int64  `json:"timestamp"`
	}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err, "解析响应体不应返回错误")

	// 验证响应字段
	assert.Equal(t, "running", response.Status, "系统状态应为running")
	assert.NotEmpty(t, response.Version, "版本不应为空")
	assert.GreaterOrEqual(t, response.Tasks, 0, "任务数应大于等于0")
	assert.GreaterOrEqual(t, response.Uptime, int64(0), "运行时间应大于等于0")
	assert.Greater(t, response.Timestamp, int64(0), "时间戳应大于0")
}

// 测试错误处理 - 无效的请求参数
func TestErrorHandling_InvalidRequest(t *testing.T) {
	cleanup := setupServer(t)
	defer cleanup()

	// 发送无效的扫描请求(空的目标)
	scanRequest := api.ScanRequest{
		// Target字段为空
		Ports:    "1-1000",
		ScanType: "tcp",
	}

	reqBody, err := json.Marshal(scanRequest)
	require.NoError(t, err, "序列化请求不应返回错误")

	// 发送创建任务请求
	resp, err := http.Post(fmt.Sprintf("%s/api/tasks", serverURL),
		"application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err, "创建任务请求不应返回错误")
	defer resp.Body.Close()

	// 验证响应状态码
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "无效请求响应状态码应为400")

	// 解析错误响应
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "读取响应体不应返回错误")

	var errorResponse struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(body, &errorResponse)
	require.NoError(t, err, "解析响应体不应返回错误")

	// 验证错误消息
	assert.Contains(t, errorResponse.Error, "目标不能为空", "错误消息应包含'目标不能为空'")
}

// 测试错误处理 - 资源不存在
func TestErrorHandling_ResourceNotFound(t *testing.T) {
	cleanup := setupServer(t)
	defer cleanup()

	// 尝试获取不存在的任务
	resp, err := http.Get(fmt.Sprintf("%s/api/tasks/non-existent-id", serverURL))
	require.NoError(t, err, "获取不存在的任务不应返回错误")
	defer resp.Body.Close()

	// 验证响应状态码
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "获取不存在资源响应状态码应为404")

	// 解析错误响应
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "读取响应体不应返回错误")

	var errorResponse struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(body, &errorResponse)
	require.NoError(t, err, "解析响应体不应返回错误")

	// 验证错误消息
	assert.Contains(t, errorResponse.Error, "找不到任务", "错误消息应包含'找不到任务'")
}

// 测试认证机制 - 如果启用了认证
func TestAuthentication(t *testing.T) {
	// 创建一个启用认证的服务器
	config := &api.ServerConfig{
		Host:           "localhost",
		Port:           8081, // 使用不同的端口
		JWTSecret:      "test-secret",
		RedisAddr:      "", // 不使用Redis
		TaskTimeout:    10 * time.Second,
		MaxConcurrency: 5,
		QueueSize:      100,
		EnableAuth:     true, // 启用认证
		AllowInMemory:  true,
	}

	server := api.NewServer(config)
	require.NotNil(t, server, "服务器不应为nil")

	// 启动服务器(异步)
	go func() {
		server.Start()
	}()
	defer server.Stop()

	// 等待服务器启动完成
	time.Sleep(500 * time.Millisecond)

	authServerURL := "http://localhost:8081"

	// 发送未认证请求
	resp, err := http.Get(fmt.Sprintf("%s/api/tasks", authServerURL))
	require.NoError(t, err, "发送未认证请求不应返回错误")
	defer resp.Body.Close()

	// 验证响应状态码 (应该是401 Unauthorized)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "未认证请求响应状态码应为401")

	// 登录获取令牌
	loginRequest := api.LoginRequest{
		Username: "admin",
		Password: "admin123", // 假设这是有效的凭据
	}

	loginBody, err := json.Marshal(loginRequest)
	require.NoError(t, err, "序列化登录请求不应返回错误")

	loginResp, err := http.Post(fmt.Sprintf("%s/api/auth/login", authServerURL),
		"application/json", bytes.NewBuffer(loginBody))
	require.NoError(t, err, "登录请求不应返回错误")
	defer loginResp.Body.Close()

	// 解析登录响应获取令牌
	tokenBody, err := io.ReadAll(loginResp.Body)
	require.NoError(t, err, "读取登录响应体不应返回错误")

	var loginResponse api.LoginResponse
	err = json.Unmarshal(tokenBody, &loginResponse)

	// 如果登录成功，使用令牌发送认证请求
	if loginResp.StatusCode == http.StatusOK && err == nil {
		client := &http.Client{}
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/tasks", authServerURL), nil)
		require.NoError(t, err, "创建认证请求不应返回错误")

		// 添加认证头
		req.Header.Add("Authorization", "Bearer "+loginResponse.Token)

		authResp, err := client.Do(req)
		require.NoError(t, err, "发送认证请求不应返回错误")
		defer authResp.Body.Close()

		// 验证认证请求响应状态码
		assert.Equal(t, http.StatusOK, authResp.StatusCode, "认证请求响应状态码应为200")
	}
}
