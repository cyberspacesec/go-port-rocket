package scanner

import (
	"context"
	"sync"
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
			logger.Error("扫描端口 %d 时发生错误: %v", err.Port, err.Error)
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
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second * 5
	}
	if opts.Workers <= 0 {
		opts.Workers = 100
	}
	if opts.RateLimit <= 0 {
		opts.RateLimit = 1000
	}
	if opts.Retries < 0 {
		opts.Retries = 3
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
