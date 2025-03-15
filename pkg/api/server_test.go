package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestNewServer 测试创建服务器
func TestNewServer(t *testing.T) {
	// 设置测试模式，避免gin输出调试信息
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

	server := NewServer(config)
	assert.NotNil(t, server, "服务器不应为nil")
	assert.Equal(t, config, server.config, "服务器配置应匹配")
	assert.NotNil(t, server.engine, "gin引擎不应为nil")
	assert.NotNil(t, server.taskQueue, "任务队列不应为nil")
	assert.NotNil(t, server.workers, "工作线程通道不应为nil")
	assert.NotNil(t, server.ctx, "上下文不应为nil")
	assert.NotNil(t, server.cancel, "取消函数不应为nil")
	assert.True(t, server.inmemory, "内存存储标志应为true")
}

// TestServer_SetupRoutes 测试路由设置
func TestServer_SetupRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &ServerConfig{
		Host:           "localhost",
		Port:           8080,
		JWTSecret:      "test-secret",
		AllowInMemory:  true,
		EnableAuth:     false,
		MaxConcurrency: 5,
		QueueSize:      100,
		TaskTimeout:    10 * time.Second,
	}

	server := NewServer(config)

	// 通过反射获取路由信息较复杂，这里我们只检查一些关键路由
	// 使用httptest来测试路由是否正确设置
	paths := []struct {
		method  string
		path    string
		expCode int
	}{
		{http.MethodPost, "/api/auth/login", http.StatusNotFound}, // 未实现验证，应返回404
		{http.MethodGet, "/api/tasks", http.StatusOK},
		{http.MethodGet, "/api/system/status", http.StatusOK},
	}

	for _, route := range paths {
		t.Run(route.path, func(t *testing.T) {
			w := performRequest(server.engine, route.method, route.path)
			assert.Equal(t, route.expCode, w.Code, "请求%s %s应返回状态码%d", route.method, route.path, route.expCode)
		})
	}
}

// TestServer_StartStop 测试服务器启动和停止
func TestServer_StartStop(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &ServerConfig{
		Host:           "localhost",
		Port:           8888, // 使用不太可能被占用的端口
		JWTSecret:      "test-secret",
		AllowInMemory:  true,
		EnableAuth:     false,
		MaxConcurrency: 5,
		QueueSize:      100,
		TaskTimeout:    10 * time.Second,
	}

	server := NewServer(config)

	// 启动服务器(非阻塞方式)
	go func() {
		err := server.Start()
		if err != nil {
			// 排除正常关闭导致的错误
			if err.Error() != "http: Server closed" {
				t.Errorf("服务器启动失败: %v", err)
			}
		}
	}()

	// 等待服务器启动
	time.Sleep(100 * time.Millisecond)

	// 测试服务器是否在监听
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://localhost:8888/api/system/status", nil)
	resp, err := client.Do(req)
	if err == nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode, "系统状态API应返回200")
		resp.Body.Close()
	}

	// 停止服务器
	server.Stop()

	// 验证服务器已停止
	time.Sleep(100 * time.Millisecond)
	_, err = client.Do(req)
	assert.Error(t, err, "服务器已停止，请求应失败")
}

// 辅助函数：执行HTTP请求并返回响应记录器
func performRequest(engine http.Handler, method, path string) *httpRecorder {
	req, _ := http.NewRequest(method, path, nil)
	w := &httpRecorder{
		Code:      http.StatusOK,
		HeaderMap: make(http.Header),
	}
	engine.ServeHTTP(w, req)
	return w
}

// httpRecorder 模拟http.ResponseWriter
type httpRecorder struct {
	Code      int
	HeaderMap http.Header
	Body      string
	Flushed   bool
	headers   http.Header
}

func (r *httpRecorder) Header() http.Header {
	return r.headers
}

func (r *httpRecorder) Write(buf []byte) (int, error) {
	r.Body += string(buf)
	return len(buf), nil
}

func (r *httpRecorder) WriteHeader(code int) {
	r.Code = code
}

func (r *httpRecorder) Flush() {
	r.Flushed = true
}
