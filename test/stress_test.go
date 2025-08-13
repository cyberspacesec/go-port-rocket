package test

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// StressTestConfig 压力测试配置
type StressTestConfig struct {
	ConcurrentScans int
	Target          string
	Ports           string
	ScanType        scanner.ScanType
	Timeout         time.Duration
	Workers         int
	TestDuration    time.Duration
}

// StressTestResult 压力测试结果
type StressTestResult struct {
	TotalScans      int64
	SuccessfulScans int64
	FailedScans     int64
	TotalErrors     int64
	AvgScanTime     time.Duration
	MaxScanTime     time.Duration
	MinScanTime     time.Duration
	MemoryUsage     MemoryStats
	StartTime       time.Time
	EndTime         time.Time
}

// MemoryStats 内存统计
type MemoryStats struct {
	InitialAlloc uint64
	FinalAlloc   uint64
	MaxAlloc     uint64
	TotalAlloc   uint64
	NumGC        uint32
}

// TestStress100ConcurrentScans 测试100个并发扫描的压力测试
func TestStress100ConcurrentScans(t *testing.T) {
	config := &StressTestConfig{
		ConcurrentScans: 100,
		Target:          "127.0.0.1",
		Ports:           "22,80,443,8080,3306,5432,6379,27017",
		ScanType:        scanner.ScanTypeTCP,
		Timeout:         time.Second * 3,
		Workers:         5,
		TestDuration:    time.Minute * 2,
	}

	t.Logf("开始压力测试: %d 个并发扫描，持续 %v", config.ConcurrentScans, config.TestDuration)

	result, err := runStressTest(config)
	if err != nil {
		t.Fatalf("压力测试失败: %v", err)
	}

	// 输出详细结果
	printStressTestResult(t, result)

	// 验证测试结果
	validateStressTestResult(t, result)
}

// runStressTest 执行压力测试
func runStressTest(config *StressTestConfig) (*StressTestResult, error) {
	result := &StressTestResult{
		StartTime:   time.Now(),
		MinScanTime: time.Hour, // 初始化为一个很大的值
	}

	// 记录初始内存状态
	var initialMemStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&initialMemStats)
	result.MemoryUsage.InitialAlloc = initialMemStats.Alloc

	// 创建上下文，控制测试持续时间
	ctx, cancel := context.WithTimeout(context.Background(), config.TestDuration)
	defer cancel()

	// 统计变量
	var totalScans, successfulScans, failedScans, totalErrors int64
	var scanTimes []time.Duration
	var scanTimesMutex sync.Mutex

	// 启动并发扫描
	var wg sync.WaitGroup
	for i := 0; i < config.ConcurrentScans; i++ {
		wg.Add(1)
		go func(scannerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					// 执行单次扫描
					scanStart := time.Now()
					err := performSingleScan(config)
					scanDuration := time.Since(scanStart)

					atomic.AddInt64(&totalScans, 1)

					// 记录扫描时间
					scanTimesMutex.Lock()
					scanTimes = append(scanTimes, scanDuration)
					if scanDuration > result.MaxScanTime {
						result.MaxScanTime = scanDuration
					}
					if scanDuration < result.MinScanTime {
						result.MinScanTime = scanDuration
					}
					scanTimesMutex.Unlock()

					if err != nil {
						atomic.AddInt64(&failedScans, 1)
						atomic.AddInt64(&totalErrors, 1)
						log.Printf("扫描器 %d 失败: %v", scannerID, err)
					} else {
						atomic.AddInt64(&successfulScans, 1)
					}

					// 短暂休息避免过度消耗资源
					time.Sleep(time.Millisecond * 100)
				}
			}
		}(i)
	}

	// 等待所有扫描完成或超时
	wg.Wait()

	// 记录最终内存状态
	var finalMemStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&finalMemStats)

	// 计算平均扫描时间
	var totalScanTime time.Duration
	for _, duration := range scanTimes {
		totalScanTime += duration
	}
	if len(scanTimes) > 0 {
		result.AvgScanTime = totalScanTime / time.Duration(len(scanTimes))
	}

	// 填充结果
	result.EndTime = time.Now()
	result.TotalScans = totalScans
	result.SuccessfulScans = successfulScans
	result.FailedScans = failedScans
	result.TotalErrors = totalErrors
	result.MemoryUsage.FinalAlloc = finalMemStats.Alloc
	result.MemoryUsage.MaxAlloc = finalMemStats.TotalAlloc
	result.MemoryUsage.TotalAlloc = finalMemStats.TotalAlloc
	result.MemoryUsage.NumGC = finalMemStats.NumGC - initialMemStats.NumGC

	return result, nil
}

// performSingleScan 执行单次扫描
func performSingleScan(config *StressTestConfig) error {
	opts := &scanner.ScanOptions{
		Target:   config.Target,
		Ports:    config.Ports,
		ScanType: config.ScanType,
		Timeout:  config.Timeout,
		Workers:  config.Workers,
	}

	s, err := scanner.NewScanner(opts)
	if err != nil {
		return fmt.Errorf("创建扫描器失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout*2)
	defer cancel()

	_, err = s.Scan(ctx)
	return err
}

// printStressTestResult 打印压力测试结果
func printStressTestResult(t *testing.T, result *StressTestResult) {
	duration := result.EndTime.Sub(result.StartTime)
	successRate := float64(result.SuccessfulScans) / float64(result.TotalScans) * 100
	scansPerSecond := float64(result.TotalScans) / duration.Seconds()

	t.Logf("=== 压力测试结果 ===")
	t.Logf("测试持续时间: %v", duration)
	t.Logf("总扫描次数: %d", result.TotalScans)
	t.Logf("成功扫描: %d", result.SuccessfulScans)
	t.Logf("失败扫描: %d", result.FailedScans)
	t.Logf("成功率: %.2f%%", successRate)
	t.Logf("扫描速率: %.2f scans/sec", scansPerSecond)
	t.Logf("平均扫描时间: %v", result.AvgScanTime)
	t.Logf("最大扫描时间: %v", result.MaxScanTime)
	t.Logf("最小扫描时间: %v", result.MinScanTime)

	// 内存使用情况
	memDiff := int64(result.MemoryUsage.FinalAlloc) - int64(result.MemoryUsage.InitialAlloc)
	t.Logf("=== 内存使用情况 ===")
	t.Logf("初始内存: %.2f MB", float64(result.MemoryUsage.InitialAlloc)/1024/1024)
	t.Logf("最终内存: %.2f MB", float64(result.MemoryUsage.FinalAlloc)/1024/1024)
	t.Logf("内存变化: %+.2f MB", float64(memDiff)/1024/1024)
	t.Logf("总分配内存: %.2f MB", float64(result.MemoryUsage.TotalAlloc)/1024/1024)
	t.Logf("GC次数: %d", result.MemoryUsage.NumGC)
}

// validateStressTestResult 验证压力测试结果
func validateStressTestResult(t *testing.T, result *StressTestResult) {
	// 检查是否有扫描完成
	if result.TotalScans == 0 {
		t.Fatal("❌ 没有完成任何扫描")
	}

	// 检查成功率
	successRate := float64(result.SuccessfulScans) / float64(result.TotalScans) * 100
	if successRate < 70 {
		t.Errorf("❌ 成功率过低: %.2f%% (期望 >= 70%%)", successRate)
	}

	// 检查内存使用
	memDiff := int64(result.MemoryUsage.FinalAlloc) - int64(result.MemoryUsage.InitialAlloc)
	memDiffMB := float64(memDiff) / 1024 / 1024
	if memDiffMB > 100 {
		t.Errorf("❌ 内存使用增长过多: %.2f MB (期望 < 100 MB)", memDiffMB)
	}

	// 检查平均扫描时间
	if result.AvgScanTime > time.Second*10 {
		t.Errorf("❌ 平均扫描时间过长: %v (期望 < 10s)", result.AvgScanTime)
	}

	t.Logf("✅ 压力测试验证通过！")
	t.Logf("   - 成功率: %.2f%%", successRate)
	t.Logf("   - 内存使用: %+.2f MB", memDiffMB)
	t.Logf("   - 平均扫描时间: %v", result.AvgScanTime)
}

// TestRaceConditions 测试竞态条件
func TestRaceConditions(t *testing.T) {
	t.Log("测试竞态条件")

	const numGoroutines = 100
	const iterations = 10

	var wg sync.WaitGroup
	var errors int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				opts := &scanner.ScanOptions{
					Target:   "127.0.0.1",
					Ports:    "80,443",
					ScanType: scanner.ScanTypeTCP,
					Timeout:  time.Millisecond * 500,
					Workers:  2,
				}

				s, err := scanner.NewScanner(opts)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err = s.Scan(ctx)
				cancel()

				if err != nil {
					atomic.AddInt64(&errors, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	totalOperations := numGoroutines * iterations
	errorRate := float64(errors) / float64(totalOperations) * 100

	t.Logf("总操作数: %d", totalOperations)
	t.Logf("错误数: %d", errors)
	t.Logf("错误率: %.2f%%", errorRate)

	if errorRate > 30 {
		t.Errorf("❌ 错误率过高: %.2f%% (期望 < 30%%)", errorRate)
	} else {
		t.Logf("✅ 竞态条件测试通过")
	}
}
