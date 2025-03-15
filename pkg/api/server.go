package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/redis/go-redis/v9"
)

// ServerConfig API服务器配置
type ServerConfig struct {
	Host           string        // 监听地址
	Port           int           // 监听端口
	JWTSecret      string        // JWT密钥
	RedisAddr      string        // Redis地址
	RedisPassword  string        // Redis密码
	RedisDB        int           // Redis数据库
	TaskTimeout    time.Duration // 任务超时时间
	MaxConcurrency int           // 最大并发任务数
	QueueSize      int           // 任务队列大小
	EnableAuth     bool          // 是否启用认证
	AllowInMemory  bool          // 是否允许在Redis连接失败时降级到内存存储
}

// Server API服务器
type Server struct {
	config    *ServerConfig
	engine    *gin.Engine
	redis     *redis.Client
	taskQueue chan *Task
	tasks     sync.Map
	workers   chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	inmemory  bool // 是否使用内存存储
}

// Task 扫描任务
type Task struct {
	ID         string       `json:"id"`          // 任务ID
	Status     string       `json:"status"`      // 任务状态
	CreateTime time.Time    `json:"create_time"` // 创建时间
	StartTime  *time.Time   `json:"start_time"`  // 开始时间
	EndTime    *time.Time   `json:"end_time"`    // 结束时间
	Request    *ScanRequest `json:"request"`     // 扫描请求
	Result     *ScanResult  `json:"result"`      // 扫描结果
	Error      string       `json:"error"`       // 错误信息
}

// ScanRequest 扫描请求
type ScanRequest struct {
	Target           string        `json:"target"`            // 目标
	Ports            string        `json:"ports"`             // 端口
	ScanType         string        `json:"scan_type"`         // 扫描类型
	Timeout          time.Duration `json:"timeout"`           // 超时时间
	Workers          int           `json:"workers"`           // 工作线程数
	OutputFormat     string        `json:"output_format"`     // 输出格式
	PrettyOutput     bool          `json:"pretty_output"`     // 美化输出
	EnableOS         bool          `json:"enable_os"`         // 启用操作系统检测
	EnableService    bool          `json:"enable_service"`    // 启用服务检测
	VersionIntensity int           `json:"version_intensity"` // 版本检测强度
	GuessOS          bool          `json:"guess_os"`          // 推测操作系统
	LimitOSScan      bool          `json:"limit_os_scan"`     // 限制操作系统扫描
}

// ScanResult 扫描结果
type ScanResult struct {
	TaskID    string    `json:"task_id"`    // 任务ID
	Status    string    `json:"status"`     // 状态
	Progress  float64   `json:"progress"`   // 进度
	StartTime time.Time `json:"start_time"` // 开始时间
	EndTime   time.Time `json:"end_time"`   // 结束时间
	Result    string    `json:"result"`     // 结果数据
}

// NewServer 创建新的API服务器
func NewServer(config *ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		config:    config,
		engine:    gin.Default(),
		taskQueue: make(chan *Task, config.QueueSize),
		workers:   make(chan struct{}, config.MaxConcurrency),
		ctx:       ctx,
		cancel:    cancel,
		inmemory:  config.RedisAddr == "", // 如果Redis地址为空，则使用内存存储
	}

	// 初始化Redis客户端
	if !server.inmemory {
		server.redis = redis.NewClient(&redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})

		// 测试Redis连接
		_, err := server.redis.Ping(ctx).Result()
		if err != nil {
			// 如果Redis地址是明确指定的（不是默认值）且不允许内存降级，则报错并退出
			if config.RedisAddr != "localhost:6379" && !config.AllowInMemory {
				fmt.Printf("错误: Redis连接失败: %v\n", err)
				fmt.Println("\n您有以下选择:")
				fmt.Println("1. 确保Redis服务器在指定地址可用，并重新启动")
				fmt.Println("2. 允许内存存储降级: --allow-inmemory")
				fmt.Println("\n示例命令:")
				fmt.Printf("  ./go-port-rocket api --redis-addr=\"%s\" --allow-inmemory\n", config.RedisAddr)
				fmt.Println("  ./go-port-rocket api --redis-addr=\"localhost:6379\"")
				os.Exit(1)
			}

			// 否则降级为内存存储并发出警告
			fmt.Printf("警告: Redis连接失败: %v, 将使用内存存储\n", err)
			server.inmemory = true
		}
	}

	// 设置中间件
	server.setupMiddlewares()

	// 设置路由
	server.setupRoutes()

	// 启动工作线程
	go server.processTaskQueue()

	return server
}

// Start 启动服务器
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	return s.engine.Run(addr)
}

// Stop 停止服务器
func (s *Server) Stop() {
	s.cancel()
	close(s.taskQueue)
	if !s.inmemory {
		s.redis.Close()
	}
}

// setupMiddlewares 设置中间件
func (s *Server) setupMiddlewares() {
	// 恢复中间件
	s.engine.Use(gin.Recovery())

	// 日志中间件
	s.engine.Use(gin.Logger())

	// CORS中间件
	s.engine.Use(s.corsMiddleware())

	// JWT认证中间件（仅当启用认证时）
	if s.config.EnableAuth {
		s.engine.Use(s.authMiddleware())
	}
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// API版本v1
	v1 := s.engine.Group("/api/v1")
	{
		// 认证相关
		auth := v1.Group("/auth")
		{
			auth.POST("/login", s.handleLogin)
			auth.POST("/refresh", s.handleRefreshToken)
		}

		// 扫描相关
		scan := v1.Group("/scan")
		{
			scan.POST("/", s.handleCreateScanTask)
			scan.GET("/tasks", s.handleListTasks)
			scan.GET("/tasks/:id", s.handleGetTask)
			scan.DELETE("/tasks/:id", s.handleCancelTask)
			scan.GET("/tasks/:id/result", s.handleGetTaskResult)
		}

		// 系统相关
		system := v1.Group("/system")
		{
			system.GET("/status", s.handleSystemStatus)
			system.GET("/metrics", s.handleSystemMetrics)
		}
	}
}

// corsMiddleware CORS中间件
func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// authMiddleware JWT认证中间件
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过登录和刷新token接口的认证
		if c.Request.URL.Path == "/api/v1/auth/login" ||
			c.Request.URL.Path == "/api/v1/auth/refresh" {
			c.Next()
			return
		}

		// 获取Authorization头
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证信息"})
			c.Abort()
			return
		}

		// 验证JWT token
		tokenString := authHeader[7:] // 去掉"Bearer "前缀
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("无效的签名方法: %v", token.Header["alg"])
			}
			return []byte(s.config.JWTSecret), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// 将用户信息存储到上下文
			c.Set("user_id", claims["user_id"])
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
			c.Abort()
			return
		}
	}
}

// processTaskQueue 处理任务队列
func (s *Server) processTaskQueue() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case task := <-s.taskQueue:
			// 获取工作线程令牌
			s.workers <- struct{}{}

			go func(task *Task) {
				defer func() {
					<-s.workers // 释放工作线程令牌
				}()

				// 更新任务状态
				task.Status = "running"
				startTime := time.Now()
				task.StartTime = &startTime
				s.updateTask(task)

				// 执行扫描
				result, err := s.executeScan(task.Request)

				// 更新任务状态和结果
				endTime := time.Now()
				task.EndTime = &endTime
				if err != nil {
					task.Status = "failed"
					task.Error = err.Error()
				} else {
					task.Status = "completed"
					task.Result = result
				}
				s.updateTask(task)
			}(task)
		}
	}
}

// updateTask 更新任务状态
func (s *Server) updateTask(task *Task) {
	// 更新内存中的任务状态
	s.tasks.Store(task.ID, task)

	// 更新存储中的任务状态
	taskJSON, _ := json.Marshal(task)
	if !s.inmemory {
		s.redis.Set(s.ctx, fmt.Sprintf("task:%s", task.ID), string(taskJSON), 24*time.Hour)
	}
}

// Redis适配器
type redisAdapter struct {
	client *redis.Client
}

// Set 设置值
func (r *redisAdapter) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get 获取值
func (r *redisAdapter) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// ScanKeys 扫描匹配的键
func (r *redisAdapter) ScanKeys(ctx context.Context, pattern string) ([]string, error) {
	var keys []string
	var cursor uint64 = 0
	for {
		var scanKeys []string
		var err error
		scanKeys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}

		keys = append(keys, scanKeys...)

		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

// Close 关闭
func (r *redisAdapter) Close() error {
	return r.client.Close()
}
