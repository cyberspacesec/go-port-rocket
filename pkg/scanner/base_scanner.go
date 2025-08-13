package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/logger"
	"github.com/cyberspacesec/go-port-rocket/pkg/metrics"
)

// BaseScanner 基础扫描器接口
type BaseScanner interface {
	// Scan 执行扫描
	Scan(ctx context.Context, opts *ScanOptions) ([]ScanResult, error)
	// ValidateOptions 验证扫描选项
	ValidateOptions(opts *ScanOptions) error
	// RequiresRoot 是否需要root权限
	RequiresRoot() bool
}

// baseScanner 基础扫描器实现
type baseScanner struct {
	scanType ScanType
	stats    *ScanStats
	mu       sync.Mutex
	opts     *ScanOptions
}

// newBaseScanner 创建新的基础扫描器
func newBaseScanner(scanType ScanType) *baseScanner {
	return &baseScanner{
		scanType: scanType,
		stats:    NewScanStats(),
	}
}

// Scan 实现基础扫描方法
func (s *baseScanner) Scan(ctx context.Context, opts *ScanOptions) ([]ScanResult, error) {
	if err := s.ValidateOptions(opts); err != nil {
		return nil, err
	}

	s.opts = opts

	// 解析端口范围
	ports, err := parsePorts(opts.Ports)
	if err != nil {
		return nil, err
	}

	// 初始化统计信息
	s.stats = NewScanStats()
	s.stats.TotalPorts = len(ports)

	// 创建工作池
	jobs := make(chan int, len(ports))
	results := make(chan ScanResult, len(ports))
	errors := make(chan ScanError, len(ports))
	var wg sync.WaitGroup

	// 启动工作协程
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					result, err := s.scanPort(ctx, port)
					if err != nil {
						errors <- ScanError{Port: port, Error: err}
						continue
					}
					results <- result
				}
			}
		}()
	}

	// 发送任务
	go func() {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return
			case jobs <- port:
			}
		}
		close(jobs)
	}()

	// 等待所有工作完成
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// 收集结果
	var scanResults []ScanResult
	for {
		select {
		case <-ctx.Done():
			return scanResults, ctx.Err()
		case result, ok := <-results:
			if !ok {
				return scanResults, nil
			}
			scanResults = append(scanResults, result)
			s.updateStats(result)
		case err, ok := <-errors:
			if !ok {
				continue
			}
			s.stats.Errors++
			fmt.Printf("⚠️  扫描端口 %d 时发生错误: %v\n", err.Port, err.Error)
		}
	}
}

// scanPort 扫描单个端口
func (s *baseScanner) scanPort(ctx context.Context, port int) (ScanResult, error) {
	// 实现具体的端口扫描逻辑
	// 这个方法应该被子类重写
	return ScanResult{}, nil
}

// updateStats 更新统计信息
func (s *baseScanner) updateStats(result ScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch result.State {
	case PortStateOpen:
		s.stats.OpenPorts++
	case PortStateClosed:
		s.stats.ClosedPorts++
	case PortStateFiltered:
		s.stats.FilteredPorts++
	}

	// 更新指标
	metrics.IncrementPortsScanned(s.opts.Target, string(s.scanType))
	switch result.State {
	case PortStateOpen:
		metrics.SetOpenPorts(s.opts.Target, string(s.scanType), float64(s.stats.OpenPorts))
	case PortStateClosed:
		metrics.SetClosedPorts(s.opts.Target, string(s.scanType), float64(s.stats.ClosedPorts))
	case PortStateFiltered:
		metrics.SetFilteredPorts(s.opts.Target, string(s.scanType), float64(s.stats.FilteredPorts))
	}
}

// ValidateOptions 验证扫描选项
func (s *baseScanner) ValidateOptions(opts *ScanOptions) error {
	if opts == nil {
		return ErrInvalidOptions
	}
	if opts.Target == "" {
		return ErrInvalidTarget
	}
	if opts.Ports == "" {
		return ErrInvalidPorts
	}

	// 解析端口数量用于智能参数调整
	ports, err := parsePorts(opts.Ports)
	if err != nil {
		return err
	}
	portCount := len(ports)

	// 设置默认超时时间（仅当用户未设置时）
	if opts.Timeout <= 0 {
		if portCount > 10000 {
			opts.Timeout = time.Second * 2 // 大规模扫描使用较短超时
		} else if portCount > 1000 {
			opts.Timeout = time.Second * 3
		} else {
			opts.Timeout = time.Second * 5
		}
	}

	// 智能调整工作线程数
	if opts.Workers <= 0 {
		opts.Workers = calculateOptimalWorkers(portCount)
	} else {
		// 只验证资源限制，不强制修改用户设置
		maxWorkers := calculateMaxWorkers(portCount)
		if opts.Workers > maxWorkers {
			fmt.Printf("⚠️  警告: 工作线程数 %d 可能超出系统资源限制 (建议: %d)\n", opts.Workers, maxWorkers)
			fmt.Printf("   如遇到问题，请考虑降低并发数或增加系统资源限制\n")
		}
	}

	// 智能调整速率限制
	if opts.RateLimit <= 0 {
		opts.RateLimit = calculateOptimalRateLimit(portCount, opts.Workers)
	}

	if opts.Retries < 0 {
		opts.Retries = 3
	}

	// 验证资源限制
	if err := validateSystemResources(opts.Workers, portCount); err != nil {
		return err
	}

	return nil
}

// RequiresRoot 默认不需要root权限
func (s *baseScanner) RequiresRoot() bool {
	return false
}

// GetStats 获取扫描统计信息
func (s *baseScanner) GetStats() *ScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// calculateOptimalWorkers 根据端口数量计算最优工作线程数
func calculateOptimalWorkers(portCount int) int {
	cpuCount := runtime.NumCPU()

	if portCount <= 100 {
		return min(10, cpuCount*2)
	} else if portCount <= 1000 {
		return min(20, cpuCount*4)
	} else if portCount <= 10000 {
		return min(50, cpuCount*8)
	} else {
		// 大规模扫描，限制并发以避免资源耗尽
		return min(100, cpuCount*10)
	}
}

// calculateMaxWorkers 计算最大允许的工作线程数
func calculateMaxWorkers(portCount int) int {
	// 获取系统文件描述符限制
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		logger.Warnf("无法获取文件描述符限制: %v", err)
		return calculateOptimalWorkers(portCount) // 回退到最优值
	}

	// 保留一些文件描述符给系统使用
	availableFDs := int(rlimit.Cur) - 100

	// 每个工作线程可能同时打开的连接数（考虑重试）
	maxConcurrentConnections := availableFDs / 2

	// 根据端口数量和可用资源计算最大工作线程数
	maxByPorts := portCount / 10 // 每10个端口一个线程
	maxByResources := maxConcurrentConnections
	maxByCPU := runtime.NumCPU() * 20 // CPU核心数的20倍

	return min(min(maxByPorts, maxByResources), maxByCPU)
}

// calculateOptimalRateLimit 计算最优速率限制
func calculateOptimalRateLimit(portCount, workers int) int {
	if portCount <= 100 {
		return 1000
	} else if portCount <= 1000 {
		return 500
	} else if portCount <= 10000 {
		return 200
	} else {
		// 大规模扫描，降低速率以避免被目标服务器限制
		return 100
	}
}

// validateSystemResources 验证系统资源是否足够
func validateSystemResources(workers, portCount int) error {
	// 检查文件描述符限制
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		logger.Warnf("无法获取文件描述符限制: %v", err)
		return nil // 不阻止扫描，只是警告
	}

	// 估算需要的文件描述符数量
	estimatedFDs := workers * 2 // 每个工作线程可能需要2个FD
	if estimatedFDs > int(rlimit.Cur)-100 {
		return fmt.Errorf("工作线程数过多，可能导致文件描述符耗尽 (需要: %d, 可用: %d)",
			estimatedFDs, int(rlimit.Cur)-100)
	}

	// 检查内存使用估算
	estimatedMemoryMB := (workers * portCount * 1024) / (1024 * 1024) // 粗略估算
	if estimatedMemoryMB > 1024 {                                     // 超过1GB
		logger.Warnf("扫描可能消耗大量内存 (估算: %d MB)，建议降低并发数或分批扫描", estimatedMemoryMB)
	}

	return nil
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
