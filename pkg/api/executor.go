package api

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/output"
	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// executeScan 执行扫描任务
func (s *Server) executeScan(req *ScanRequest) (*ScanResult, error) {
	// 创建扫描选项
	opts := &scanner.ScanOptions{
		Target:           req.Target,
		Ports:            req.Ports,
		ScanType:         scanner.ScanType(req.ScanType),
		Timeout:          req.Timeout,
		Workers:          req.Workers,
		EnableOS:         req.EnableOS,
		EnableService:    req.EnableService,
		VersionIntensity: req.VersionIntensity,
		GuessOS:          req.GuessOS,
		LimitOSScan:      req.LimitOSScan,
	}

	// 创建扫描器
	scanner, err := scanner.NewScanner(opts)
	if err != nil {
		return nil, fmt.Errorf("创建扫描器失败: %v", err)
	}

	// 创建输出缓冲区
	var buf bytes.Buffer

	// 创建输出选项
	outputOpts := &output.Options{
		Format:    req.OutputFormat,
		Pretty:    req.PrettyOutput,
		Writer:    &buf,
		Target:    req.Target,
		ScanType:  req.ScanType,
		StartTime: time.Now(),
	}

	// 创建输出处理器
	outputHandler, err := output.NewOutput(outputOpts)
	if err != nil {
		return nil, fmt.Errorf("创建输出处理器失败: %v", err)
	}

	// 执行扫描
	ctx := context.Background()
	results, err := scanner.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("扫描执行失败: %v", err)
	}

	// 更新输出选项的结束时间
	outputOpts.EndTime = time.Now()
	outputOpts.Duration = outputOpts.EndTime.Sub(outputOpts.StartTime)

	// 写入扫描结果
	if err := outputHandler.Write(results); err != nil {
		return nil, fmt.Errorf("写入扫描结果失败: %v", err)
	}

	// 创建扫描结果
	scanResult := &ScanResult{
		Status:    "completed",
		Progress:  100.0,
		StartTime: outputOpts.StartTime,
		EndTime:   outputOpts.EndTime,
		Result:    buf.String(),
	}

	return scanResult, nil
}

// validateScanRequest 验证扫描请求参数
func (s *Server) validateScanRequest(req *ScanRequest) error {
	if req.Target == "" {
		return fmt.Errorf("目标地址不能为空")
	}

	if req.Ports == "" {
		return fmt.Errorf("端口范围不能为空")
	}

	if req.ScanType == "" {
		req.ScanType = "tcp" // 默认使用TCP扫描
	}

	if req.Timeout == 0 {
		req.Timeout = 5 * time.Second // 默认超时时间5秒
	}

	if req.Workers <= 0 {
		req.Workers = 100 // 默认100个工作线程
	}

	if req.OutputFormat == "" {
		req.OutputFormat = "json" // 默认使用JSON输出格式
	}

	if req.VersionIntensity < 0 || req.VersionIntensity > 9 {
		req.VersionIntensity = 7 // 默认版本检测强度为7
	}

	return nil
}

// updateProgress 更新任务进度
func (s *Server) updateProgress(taskID string, progress float64) error {
	// 直接从内存中获取任务，避免使用storage
	taskValue, ok := s.tasks.Load(taskID)
	if !ok {
		return fmt.Errorf("任务不存在")
	}

	task, ok := taskValue.(*Task)
	if !ok {
		return fmt.Errorf("任务类型错误")
	}

	// 更新进度
	if task.Result == nil {
		task.Result = &ScanResult{}
	}
	task.Result.Progress = progress

	// 保存更新后的任务信息
	s.updateTask(task)

	return nil
}
