package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// handleLogin 处理登录请求
func (s *Server) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// TODO: 实现用户验证逻辑
	if !s.validateUser(req.Username, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 生成JWT token
	token, refreshToken, err := s.generateTokens(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成token失败"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresIn:    3600, // token有效期1小时
	})
}

// handleRefreshToken 处理刷新token请求
func (s *Server) handleRefreshToken(c *gin.Context) {
	refreshToken := c.GetHeader("X-Refresh-Token")
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供刷新token"})
		return
	}

	// 验证刷新token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("无效的签名方法")
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的刷新token"})
		return
	}

	// 从token中获取用户信息
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析token失败"})
		return
	}

	username := claims["username"].(string)

	// 生成新的token
	newToken, newRefreshToken, err := s.generateTokens(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成token失败"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    3600,
	})
}

// handleCreateScanTask 处理创建扫描任务请求
func (s *Server) handleCreateScanTask(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 创建新任务
	task := &Task{
		ID:         uuid.New().String(),
		Status:     "pending",
		CreateTime: time.Now(),
		Request:    &req,
	}

	// 将任务加入队列
	select {
	case s.taskQueue <- task:
		// 更新任务状态
		s.updateTask(task)
		c.JSON(http.StatusOK, gin.H{
			"task_id": task.ID,
			"status":  task.Status,
		})
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "任务队列已满"})
	}
}

// handleListTasks 处理获取任务列表请求
func (s *Server) handleListTasks(c *gin.Context) {
	tasks := make([]*Task, 0)

	if s.inmemory {
		// 从内存中获取所有任务
		s.tasks.Range(func(key, value interface{}) bool {
			task := value.(*Task)
			tasks = append(tasks, task)
			return true
		})
	} else {
		// 从Redis获取所有任务
		pattern := "task:*"
		iter := s.redis.Scan(s.ctx, 0, pattern, 10).Iterator()

		for iter.Next(s.ctx) {
			key := iter.Val()
			taskJSON, err := s.redis.Get(s.ctx, key).Result()
			if err != nil {
				continue
			}

			var task Task
			if err := json.Unmarshal([]byte(taskJSON), &task); err != nil {
				continue
			}
			tasks = append(tasks, &task)
		}
	}

	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

// handleGetTask 处理获取任务请求
func (s *Server) handleGetTask(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供任务ID"})
		return
	}

	var task *Task
	var found bool

	if s.inmemory {
		// 从内存中获取任务
		taskObj, exists := s.tasks.Load(taskID)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
			return
		}
		task = taskObj.(*Task)
		found = true
	} else {
		// 从Redis获取任务信息
		taskJSON, err := s.redis.Get(s.ctx, fmt.Sprintf("task:%s", taskID)).Result()
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
			return
		}

		var taskData Task
		if err := json.Unmarshal([]byte(taskJSON), &taskData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解析任务信息失败"})
			return
		}
		task = &taskData
		found = true
	}

	if found {
		c.JSON(http.StatusOK, task)
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
	}
}

// handleCancelTask 处理取消任务请求
func (s *Server) handleCancelTask(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供任务ID"})
		return
	}

	var task *Task
	var found bool

	if s.inmemory {
		// 从内存中获取任务
		taskObj, exists := s.tasks.Load(taskID)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
			return
		}
		task = taskObj.(*Task)
		found = true
	} else {
		// 从Redis获取任务信息
		taskJSON, err := s.redis.Get(s.ctx, fmt.Sprintf("task:%s", taskID)).Result()
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
			return
		}

		var taskData Task
		if err := json.Unmarshal([]byte(taskJSON), &taskData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解析任务信息失败"})
			return
		}
		task = &taskData
		found = true
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}

	// 只能取消pending或running状态的任务
	if task.Status != "pending" && task.Status != "running" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "任务无法取消"})
		return
	}

	// 更新任务状态
	task.Status = "cancelled"
	endTime := time.Now()
	task.EndTime = &endTime
	s.updateTask(task)

	c.JSON(http.StatusOK, gin.H{"message": "任务已取消"})
}

// handleGetTaskResult 处理获取任务结果请求
func (s *Server) handleGetTaskResult(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供任务ID"})
		return
	}

	var task *Task
	var found bool

	if s.inmemory {
		// 从内存中获取任务
		taskObj, exists := s.tasks.Load(taskID)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
			return
		}
		task = taskObj.(*Task)
		found = true
	} else {
		// 从Redis获取任务信息
		taskJSON, err := s.redis.Get(s.ctx, fmt.Sprintf("task:%s", taskID)).Result()
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
			return
		}

		var taskData Task
		if err := json.Unmarshal([]byte(taskJSON), &taskData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解析任务信息失败"})
			return
		}
		task = &taskData
		found = true
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}

	// 任务必须是已完成状态
	if task.Status != "completed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "任务尚未完成", "status": task.Status})
		return
	}

	// 返回任务结果
	c.JSON(http.StatusOK, task.Result)
}

// handleSystemStatus 处理获取系统状态请求
func (s *Server) handleSystemStatus(c *gin.Context) {
	// 获取任务队列状态
	queueSize := len(s.taskQueue)
	workerCount := len(s.workers)

	// 获取正在运行的任务数
	runningTasks := 0
	s.tasks.Range(func(key, value interface{}) bool {
		task := value.(*Task)
		if task.Status == "running" {
			runningTasks++
		}
		return true
	})

	c.JSON(http.StatusOK, gin.H{
		"queue_size":     queueSize,
		"worker_count":   workerCount,
		"running_tasks":  runningTasks,
		"max_workers":    s.config.MaxConcurrency,
		"queue_capacity": s.config.QueueSize,
	})
}

// handleSystemMetrics 处理获取系统指标请求
func (s *Server) handleSystemMetrics(c *gin.Context) {
	// 统计各种状态的任务数量
	stats := map[string]int{
		"pending":   0,
		"running":   0,
		"completed": 0,
		"failed":    0,
		"cancelled": 0,
	}

	s.tasks.Range(func(key, value interface{}) bool {
		task := value.(*Task)
		stats[task.Status]++
		return true
	})

	c.JSON(http.StatusOK, stats)
}

// generateTokens 生成JWT token和刷新token
func (s *Server) generateTokens(username string) (string, string, error) {
	// 生成访问token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	tokenString, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return "", "", err
	}

	// 生成刷新token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["username"] = username
	refreshClaims["exp"] = time.Now().Add(24 * time.Hour).Unix()

	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshTokenString, nil
}

// validateUser 验证用户凭据
func (s *Server) validateUser(username, password string) bool {
	// TODO: 实现用户验证逻辑
	return true
}
