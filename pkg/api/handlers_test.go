package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 初始化测试环境
func setupTestServer() *Server {
	gin.SetMode(gin.TestMode)

	config := &ServerConfig{
		Host:           "localhost",
		Port:           8080,
		JWTSecret:      "test-secret",
		RedisAddr:      "", // 不使用Redis
		TaskTimeout:    10 * time.Second,
		MaxConcurrency: 5,
		QueueSize:      100,
		EnableAuth:     false,
		AllowInMemory:  true,
	}

	return NewServer(config)
}

// TestHandleLogin 测试登录处理器
func TestHandleLogin(t *testing.T) {
	server := setupTestServer()

	tests := []struct {
		name       string
		req        LoginRequest
		expectCode int
		expectBody string
	}{
		{
			name: "有效登录",
			req: LoginRequest{
				Username: "admin",
				Password: "admin123",
			},
			expectCode: http.StatusOK,
			expectBody: "token",
		},
		{
			name: "用户名或密码错误",
			req: LoginRequest{
				Username: "admin",
				Password: "wrongpass",
			},
			expectCode: http.StatusUnauthorized,
			expectBody: "用户名或密码错误",
		},
		{
			name:       "空请求体",
			req:        LoginRequest{},
			expectCode: http.StatusUnauthorized,
			expectBody: "用户名或密码错误",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 创建请求
			reqBody, err := json.Marshal(tc.req)
			require.NoError(t, err)

			req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// 创建响应记录器
			w := httptest.NewRecorder()

			// 创建gin上下文
			router := gin.New()
			router.POST("/api/auth/login", server.handleLogin)

			// 执行请求
			router.ServeHTTP(w, req)

			// 验证响应
			assert.Equal(t, tc.expectCode, w.Code, "响应状态码应匹配")
			assert.Contains(t, w.Body.String(), tc.expectBody, "响应体应包含预期内容")
		})
	}
}

// TestHandleCreateScanTask 测试创建扫描任务
func TestHandleCreateScanTask(t *testing.T) {
	server := setupTestServer()

	tests := []struct {
		name       string
		req        ScanRequest
		expectCode int
		expectBody string
	}{
		{
			name: "有效扫描任务",
			req: ScanRequest{
				Target:       "example.com",
				Ports:        "1-1000",
				ScanType:     "tcp",
				Timeout:      5 * time.Second,
				Workers:      10,
				OutputFormat: "json",
				EnableOS:     true,
			},
			expectCode: http.StatusAccepted,
			expectBody: "task_id",
		},
		{
			name: "无目标",
			req: ScanRequest{
				Ports:    "1-1000",
				ScanType: "tcp",
			},
			expectCode: http.StatusBadRequest,
			expectBody: "目标不能为空",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 创建请求
			reqBody, err := json.Marshal(tc.req)
			require.NoError(t, err)

			req, _ := http.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// 创建响应记录器
			w := httptest.NewRecorder()

			// 创建gin上下文
			router := gin.New()
			router.POST("/api/tasks", server.handleCreateScanTask)

			// 执行请求
			router.ServeHTTP(w, req)

			// 验证响应
			assert.Equal(t, tc.expectCode, w.Code, "响应状态码应匹配")
			assert.Contains(t, w.Body.String(), tc.expectBody, "响应体应包含预期内容")
		})
	}
}

// TestHandleListTasks 测试任务列表
func TestHandleListTasks(t *testing.T) {
	server := setupTestServer()

	// 添加一些测试任务
	for i := 0; i < 5; i++ {
		task := &Task{
			ID:         fmt.Sprintf("task-%d", i),
			Status:     "completed",
			CreateTime: time.Now(),
			Request: &ScanRequest{
				Target: fmt.Sprintf("example%d.com", i),
				Ports:  "1-1000",
			},
		}
		server.tasks.Store(task.ID, task)
	}

	// 创建请求
	req, _ := http.NewRequest(http.MethodGet, "/api/tasks", nil)

	// 创建响应记录器
	w := httptest.NewRecorder()

	// 创建gin上下文
	router := gin.New()
	router.GET("/api/tasks", server.handleListTasks)

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code, "响应状态码应为200")

	// 解析响应体
	var response struct {
		Tasks []Task `json:"tasks"`
		Total int    `json:"total"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "解析响应体不应返回错误")

	// 验证任务数量
	assert.Equal(t, 5, response.Total, "总任务数应为5")
	assert.Len(t, response.Tasks, 5, "响应任务数应为5")
}

// TestHandleGetTask 测试获取单个任务
func TestHandleGetTask(t *testing.T) {
	server := setupTestServer()

	// 添加一个测试任务
	testTask := &Task{
		ID:         "test-task-id",
		Status:     "running",
		CreateTime: time.Now(),
		Request: &ScanRequest{
			Target: "example.com",
			Ports:  "1-1000",
		},
	}
	server.tasks.Store(testTask.ID, testTask)

	tests := []struct {
		name       string
		taskID     string
		expectCode int
	}{
		{
			name:       "有效任务ID",
			taskID:     "test-task-id",
			expectCode: http.StatusOK,
		},
		{
			name:       "无效任务ID",
			taskID:     "invalid-id",
			expectCode: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 创建请求
			req, _ := http.NewRequest(http.MethodGet, "/api/tasks/"+tc.taskID, nil)

			// 创建响应记录器
			w := httptest.NewRecorder()

			// 创建gin上下文
			router := gin.New()
			router.GET("/api/tasks/:id", server.handleGetTask)

			// 执行请求
			router.ServeHTTP(w, req)

			// 验证响应
			assert.Equal(t, tc.expectCode, w.Code, "响应状态码应匹配")

			if tc.expectCode == http.StatusOK {
				// 验证响应体中包含任务ID
				assert.Contains(t, w.Body.String(), tc.taskID, "响应体应包含任务ID")
			}
		})
	}
}

// TestHandleCancelTask 测试取消任务
func TestHandleCancelTask(t *testing.T) {
	server := setupTestServer()

	// 添加一个运行中的测试任务
	testTask := &Task{
		ID:         "running-task",
		Status:     "running",
		CreateTime: time.Now(),
		Request: &ScanRequest{
			Target: "example.com",
			Ports:  "1-1000",
		},
	}
	server.tasks.Store(testTask.ID, testTask)

	// 添加一个已完成的测试任务
	completedTask := &Task{
		ID:         "completed-task",
		Status:     "completed",
		CreateTime: time.Now(),
		Request: &ScanRequest{
			Target: "example.com",
			Ports:  "1-1000",
		},
	}
	server.tasks.Store(completedTask.ID, completedTask)

	tests := []struct {
		name       string
		taskID     string
		expectCode int
	}{
		{
			name:       "取消运行中的任务",
			taskID:     "running-task",
			expectCode: http.StatusOK,
		},
		{
			name:       "取消已完成的任务",
			taskID:     "completed-task",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "取消不存在的任务",
			taskID:     "non-existent-task",
			expectCode: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 创建请求
			req, _ := http.NewRequest(http.MethodDelete, "/api/tasks/"+tc.taskID, nil)

			// 创建响应记录器
			w := httptest.NewRecorder()

			// 创建gin上下文
			router := gin.New()
			router.DELETE("/api/tasks/:id", server.handleCancelTask)

			// 执行请求
			router.ServeHTTP(w, req)

			// 验证响应
			assert.Equal(t, tc.expectCode, w.Code, "响应状态码应匹配")
		})
	}
}

// TestHandleSystemStatus 测试系统状态
func TestHandleSystemStatus(t *testing.T) {
	server := setupTestServer()

	// 创建请求
	req, _ := http.NewRequest(http.MethodGet, "/api/system/status", nil)

	// 创建响应记录器
	w := httptest.NewRecorder()

	// 创建gin上下文
	router := gin.New()
	router.GET("/api/system/status", server.handleSystemStatus)

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code, "响应状态码应为200")

	// 解析响应体
	var response struct {
		Status    string `json:"status"`
		Version   string `json:"version"`
		Tasks     int    `json:"tasks"`
		Uptime    int64  `json:"uptime"`
		Timestamp int64  `json:"timestamp"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "解析响应体不应返回错误")

	// 验证响应字段
	assert.Equal(t, "running", response.Status, "系统状态应为running")
	assert.NotEmpty(t, response.Version, "版本不应为空")
	assert.GreaterOrEqual(t, response.Uptime, int64(0), "运行时间应大于等于0")
	assert.Greater(t, response.Timestamp, int64(0), "时间戳应大于0")
}
