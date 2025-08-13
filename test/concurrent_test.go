package test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// TestConcurrent100Scans 测试100个并发扫描
func TestConcurrent100Scans(t *testing.T) {
	const numConcurrentScans = 100
	const testTarget = "127.0.0.1"
	const testPorts = "80,443,22,21,25"

	t.Logf("开始测试 %d 个并发扫描", numConcurrentScans)

	// 记录初始内存状态
	var initialMemStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&initialMemStats)

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	var totalScans int64

	// 创建错误收集器
	errors := make(chan error, numConcurrentScans)

	// 启动100个并发扫描
	for i := 0; i < numConcurrentScans; i++ {
		wg.Add(1)
		go func(scanID int) {
			defer wg.Done()

			// 创建扫描选项
			opts := &scanner.ScanOptions{
				Target:  testTarget,
				Ports:   testPorts,
				ScanType: scanner.ScanTypeTCP,
				Timeout: time.Second * 2,
				Workers: 5, // 每个扫描使用较少的worker避免资源竞争
			}

			// 创建扫描器
			s, err := scanner.NewScanner(opts)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				errors <- fmt.Errorf("扫描器 %d 创建失败: %v", scanID, err)
				return
			}

			// 执行扫描
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			results, err := s.Scan(ctx)
			atomic.AddInt64(&totalScans, 1)

			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				errors <- fmt.Errorf("扫描器 %d 执行失败: %v", scanID, err)
				return
			}

			if len(results) == 0 {
				errors <- fmt.Errorf("扫描器 %d 返回空结果", scanID)
				return
			}

			atomic.AddInt64(&successCount, 1)
			t.Logf("扫描器 %d 完成，发现 %d 个结果", scanID, len(results))

		}(i)
	}

	// 等待所有扫描完成
	wg.Wait()
	close(errors)

	// 收集错误信息
	var errorList []error
	for err := range errors {
		errorList = append(errorList, err)
	}

	// 记录最终内存状态
	var finalMemStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&finalMemStats)

	// 输出测试结果
	t.Logf("=== 并发扫描测试结果 ===")
	t.Logf("总扫描数: %d", totalScans)
	t.Logf("成功扫描: %d", successCount)
	t.Logf("失败扫描: %d", errorCount)
	t.Logf("成功率: %.2f%%", float64(successCount)/float64(totalScans)*100)

	// 内存使用情况
	memDiff := finalMemStats.Alloc - initialMemStats.Alloc
	t.Logf("内存使用变化: %d bytes (%.2f MB)", memDiff, float64(memDiff)/1024/1024)
	t.Logf("当前内存分配: %.2f MB", float64(finalMemStats.Alloc)/1024/1024)
	t.Logf("系统内存: %.2f MB", float64(finalMemStats.Sys)/1024/1024)

	// 输出错误信息
	if len(errorList) > 0 {
		t.Logf("=== 错误详情 ===")
		for i, err := range errorList {
			if i < 10 { // 只显示前10个错误
				t.Logf("错误 %d: %v", i+1, err)
			}
		}
		if len(errorList) > 10 {
			t.Logf("... 还有 %d 个错误", len(errorList)-10)
		}
	}

	// 验证测试结果
	if successCount == 0 {
		t.Fatal("所有扫描都失败了")
	}

	// 如果成功率低于80%，认为测试失败
	successRate := float64(successCount) / float64(totalScans) * 100
	if successRate < 80 {
		t.Fatalf("成功率过低: %.2f%% (期望 >= 80%%)", successRate)
	}

	t.Logf("✅ 并发测试通过！成功率: %.2f%%", successRate)
}

// TestResourceManagement 测试资源管理
func TestResourceManagement(t *testing.T) {
	t.Log("测试资源管理器")

	// 创建资源管理器
	rm := scanner.NewResourceManager()
	rm.StartMonitoring()
	defer rm.StopMonitoring()

	// 测试连接分配
	const maxConnections = 50
	var allocatedConnections int

	for i := 0; i < maxConnections*2; i++ {
		if rm.CanAllocateConnection() {
			err := rm.AllocateConnection()
			if err != nil {
				t.Logf("连接分配失败: %v", err)
				break
			}
			allocatedConnections++
		} else {
			t.Logf("达到连接限制，已分配: %d", allocatedConnections)
			break
		}
	}

	// 释放所有连接
	for i := 0; i < allocatedConnections; i++ {
		rm.ReleaseConnection()
	}

	// 获取资源状态
	status := rm.GetResourceStatus()
	t.Logf("资源状态 - FD使用率: %.1f%%, 内存使用率: %.1f%%", 
		status.FDUsage, status.MemoryUsage)

	t.Log("✅ 资源管理测试通过")
}

// TestMemoryLeaks 检测内存泄漏
func TestMemoryLeaks(t *testing.T) {
	t.Log("检测内存泄漏")

	var initialMemStats, finalMemStats runtime.MemStats

	// 记录初始内存
	runtime.GC()
	runtime.ReadMemStats(&initialMemStats)

	// 执行多轮扫描
	const rounds = 10
	for round := 0; round < rounds; round++ {
		opts := &scanner.ScanOptions{
			Target:  "127.0.0.1",
			Ports:   "80,443",
			ScanType: scanner.ScanTypeTCP,
			Timeout: time.Second,
			Workers: 10,
		}

		s, err := scanner.NewScanner(opts)
		if err != nil {
			t.Fatalf("创建扫描器失败: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		_, err = s.Scan(ctx)
		cancel()

		if err != nil {
			t.Logf("第 %d 轮扫描失败: %v", round+1, err)
		}

		// 每轮后强制GC
		runtime.GC()
	}

	// 记录最终内存
	runtime.GC()
	runtime.ReadMemStats(&finalMemStats)

	memGrowth := finalMemStats.Alloc - initialMemStats.Alloc
	t.Logf("内存增长: %d bytes (%.2f MB)", memGrowth, float64(memGrowth)/1024/1024)

	// 如果内存增长超过10MB，可能存在内存泄漏
	if memGrowth > 10*1024*1024 {
		t.Errorf("可能存在内存泄漏，内存增长: %.2f MB", float64(memGrowth)/1024/1024)
	} else {
		t.Log("✅ 内存泄漏检测通过")
	}
}

// BenchmarkConcurrentScans 并发扫描性能基准测试
func BenchmarkConcurrentScans(b *testing.B) {
	opts := &scanner.ScanOptions{
		Target:  "127.0.0.1",
		Ports:   "80,443,22",
		ScanType: scanner.ScanTypeTCP,
		Timeout: time.Second,
		Workers: 10,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s, err := scanner.NewScanner(opts)
			if err != nil {
				b.Fatalf("创建扫描器失败: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			_, err = s.Scan(ctx)
			cancel()

			if err != nil {
				b.Logf("扫描失败: %v", err)
			}
		}
	})
}
