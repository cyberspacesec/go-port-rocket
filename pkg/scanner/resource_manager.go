package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// ResourceManager 资源管理器
type ResourceManager struct {
	maxFDs           int
	currentFDs       int
	maxMemoryMB      int
	currentMemoryMB  int
	mu               sync.RWMutex
	monitorInterval  time.Duration
	ctx              context.Context
	cancel           context.CancelFunc
}

// NewResourceManager 创建资源管理器
func NewResourceManager() *ResourceManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	rm := &ResourceManager{
		maxMemoryMB:     getAvailableMemoryMB(),
		monitorInterval: time.Second * 5,
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// 获取文件描述符限制
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		rm.maxFDs = int(rlimit.Cur) - 100 // 保留100个给系统
	} else {
		rm.maxFDs = 1000 // 默认值
	}
	
	return rm
}

// StartMonitoring 开始资源监控
func (rm *ResourceManager) StartMonitoring() {
	go rm.monitorResources()
}

// StopMonitoring 停止资源监控
func (rm *ResourceManager) StopMonitoring() {
	rm.cancel()
}

// CanAllocateConnection 检查是否可以分配新连接
func (rm *ResourceManager) CanAllocateConnection() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	return rm.currentFDs < rm.maxFDs-10 // 保留10个缓冲
}

// AllocateConnection 分配连接资源
func (rm *ResourceManager) AllocateConnection() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if rm.currentFDs >= rm.maxFDs-10 {
		return fmt.Errorf("文件描述符不足，当前: %d, 最大: %d", rm.currentFDs, rm.maxFDs)
	}
	
	rm.currentFDs++
	return nil
}

// ReleaseConnection 释放连接资源
func (rm *ResourceManager) ReleaseConnection() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if rm.currentFDs > 0 {
		rm.currentFDs--
	}
}

// GetResourceStatus 获取资源状态
func (rm *ResourceManager) GetResourceStatus() ResourceStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentMemoryMB := int(m.Alloc / 1024 / 1024)
	
	return ResourceStatus{
		FDUsage:     float64(rm.currentFDs) / float64(rm.maxFDs) * 100,
		MemoryUsage: float64(currentMemoryMB) / float64(rm.maxMemoryMB) * 100,
		CurrentFDs:  rm.currentFDs,
		MaxFDs:      rm.maxFDs,
		MemoryMB:    currentMemoryMB,
		MaxMemoryMB: rm.maxMemoryMB,
	}
}

// monitorResources 监控系统资源
func (rm *ResourceManager) monitorResources() {
	ticker := time.NewTicker(rm.monitorInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			status := rm.GetResourceStatus()
			
			// 如果资源使用率过高，发出警告
			if status.FDUsage > 80 {
				fmt.Printf("⚠️  文件描述符使用率过高: %.1f%% (%d/%d)\n", 
					status.FDUsage, status.CurrentFDs, status.MaxFDs)
			}
			
			if status.MemoryUsage > 80 {
				fmt.Printf("⚠️  内存使用率过高: %.1f%% (%dMB/%dMB)\n", 
					status.MemoryUsage, status.MemoryMB, status.MaxMemoryMB)
			}
		}
	}
}

// ResourceStatus 资源状态
type ResourceStatus struct {
	FDUsage     float64 // 文件描述符使用率 (%)
	MemoryUsage float64 // 内存使用率 (%)
	CurrentFDs  int     // 当前文件描述符数
	MaxFDs      int     // 最大文件描述符数
	MemoryMB    int     // 当前内存使用 (MB)
	MaxMemoryMB int     // 最大可用内存 (MB)
}

// getAvailableMemoryMB 获取可用内存
func getAvailableMemoryMB() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// 简单估算：假设可用内存为当前分配内存的10倍
	// 实际应用中可以使用更精确的方法
	return int(m.Sys/1024/1024) * 10
}

// RateLimiter 速率限制器
type RateLimiter struct {
	tokens   chan struct{}
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(ratePerSecond int) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	
	rl := &RateLimiter{
		tokens:   make(chan struct{}, ratePerSecond),
		interval: time.Second / time.Duration(ratePerSecond),
		ctx:      ctx,
		cancel:   cancel,
	}
	
	// 初始填充令牌
	for i := 0; i < ratePerSecond; i++ {
		rl.tokens <- struct{}{}
	}
	
	// 启动令牌补充
	go rl.refillTokens()
	
	return rl
}

// Wait 等待获取令牌
func (rl *RateLimiter) Wait() error {
	select {
	case <-rl.tokens:
		return nil
	case <-rl.ctx.Done():
		return rl.ctx.Err()
	}
}

// TryWait 尝试获取令牌（非阻塞）
func (rl *RateLimiter) TryWait() bool {
	select {
	case <-rl.tokens:
		return true
	default:
		return false
	}
}

// Stop 停止速率限制器
func (rl *RateLimiter) Stop() {
	rl.cancel()
}

// refillTokens 补充令牌
func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default:
				// 令牌桶已满，跳过
			}
		}
	}
}

// ProgressTracker 进度跟踪器
type ProgressTracker struct {
	total     int
	completed int
	startTime time.Time
	mu        sync.RWMutex
}

// NewProgressTracker 创建进度跟踪器
func NewProgressTracker(total int) *ProgressTracker {
	return &ProgressTracker{
		total:     total,
		startTime: time.Now(),
	}
}

// Update 更新进度
func (pt *ProgressTracker) Update(completed int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	
	pt.completed = completed
	
	// 每完成10%显示一次进度
	if completed%max(pt.total/10, 1) == 0 {
		pt.printProgress()
	}
}

// Increment 增加完成数
func (pt *ProgressTracker) Increment() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	
	pt.completed++
	
	// 每完成10%显示一次进度
	if pt.completed%max(pt.total/10, 1) == 0 {
		pt.printProgress()
	}
}

// printProgress 打印进度
func (pt *ProgressTracker) printProgress() {
	elapsed := time.Since(pt.startTime)
	percentage := float64(pt.completed) / float64(pt.total) * 100
	
	var eta time.Duration
	if pt.completed > 0 {
		eta = time.Duration(float64(elapsed) / float64(pt.completed) * float64(pt.total-pt.completed))
	}
	
	fmt.Printf("📊 进度: %d/%d (%.1f%%) | 用时: %v | 预计剩余: %v\n", 
		pt.completed, pt.total, percentage, elapsed.Round(time.Second), eta.Round(time.Second))
}

// GetProgress 获取进度信息
func (pt *ProgressTracker) GetProgress() (int, int, float64, time.Duration) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	
	elapsed := time.Since(pt.startTime)
	percentage := float64(pt.completed) / float64(pt.total) * 100
	
	return pt.completed, pt.total, percentage, elapsed
}

// max 返回较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
