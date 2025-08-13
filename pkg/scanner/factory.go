package scanner

import (
	"context"
	"fmt"
	"time"
)

// ScannerFactory 扫描器工厂
type ScannerFactory struct{}

// NewScannerFactory 创建新的扫描器工厂
func NewScannerFactory() *ScannerFactory {
	return &ScannerFactory{}
}

// CreateScanner 创建指定类型的扫描器
func (f *ScannerFactory) CreateScanner(scanType ScanType) (BaseScanner, error) {
	switch scanType {
	case ScanTypeTCP:
		return NewTCPScanner(), nil
	case ScanTypeSYN:
		return NewSYNScanner(), nil
	case ScanTypeFIN:
		return nil, fmt.Errorf("FIN扫描暂未实现")
	case ScanTypeNULL:
		return nil, fmt.Errorf("NULL扫描暂未实现")
	case ScanTypeXMAS:
		return nil, fmt.Errorf("XMAS扫描暂未实现")
	case ScanTypeACK:
		return nil, fmt.Errorf("ACK扫描暂未实现")
	case ScanTypeUDP:
		return nil, fmt.Errorf("UDP扫描暂未实现")
	case ScanTypeMAIMON:
		return nil, fmt.Errorf("MAIMON扫描暂未实现")
	default:
		return nil, fmt.Errorf("不支持的扫描类型: %s", scanType)
	}
}

// GetSupportedScanTypes 获取支持的扫描类型列表
func (f *ScannerFactory) GetSupportedScanTypes() []ScanType {
	return []ScanType{
		ScanTypeTCP,
		ScanTypeSYN,
		ScanTypeFIN,
		ScanTypeNULL,
		ScanTypeXMAS,
		ScanTypeACK,
		ScanTypeUDP,
		ScanTypeMAIMON,
	}
}

// GetImplementedScanTypes 获取已实现的扫描类型列表
func (f *ScannerFactory) GetImplementedScanTypes() []ScanType {
	return []ScanType{
		ScanTypeTCP,
		ScanTypeSYN,
	}
}

// IsScanTypeSupported 检查扫描类型是否支持
func (f *ScannerFactory) IsScanTypeSupported(scanType ScanType) bool {
	for _, t := range f.GetSupportedScanTypes() {
		if t == scanType {
			return true
		}
	}
	return false
}

// IsScanTypeImplemented 检查扫描类型是否已实现
func (f *ScannerFactory) IsScanTypeImplemented(scanType ScanType) bool {
	for _, t := range f.GetImplementedScanTypes() {
		if t == scanType {
			return true
		}
	}
	return false
}

// CreateScannerWithOptions 使用选项创建扫描器
func (f *ScannerFactory) CreateScannerWithOptions(opts *ScanOptions) (*Scanner, error) {
	// 验证选项
	if opts == nil {
		return nil, fmt.Errorf("扫描选项不能为空")
	}

	// 检查扫描类型是否已实现
	if !f.IsScanTypeImplemented(opts.ScanType) {
		return nil, fmt.Errorf("扫描类型 %s 暂未实现", opts.ScanType)
	}

	// 创建Scanner实例
	return NewScanner(opts)
}

// QuickScan 快速扫描函数，减少重复代码
func QuickScan(target string, ports []int, scanType ScanType, timeout time.Duration, workers int) ([]ScanResult, error) {
	factory := NewScannerFactory()

	// 创建扫描选项 - 使用默认配置，不强制启用OS检测
	opts := &ScanOptions{
		Target:   target,
		Ports:    joinPortsToString(ports),
		ScanType: scanType,
		Timeout:  timeout,
		Workers:  workers,
		EnableOS: false, // 默认禁用OS检测，避免超时问题
		GuessOS:  false, // 默认禁用OS猜测
	}

	// 创建Scanner实例
	scanner, err := factory.CreateScannerWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("创建Scanner失败: %v", err)
	}

	// 执行扫描
	ctx := context.Background()
	scanResults, err := scanner.Scan(ctx)
	if err != nil {
		return nil, err
	}

	// 转换结果类型
	results := make([]ScanResult, len(scanResults))
	for i, result := range scanResults {
		results[i] = *result
	}

	return results, nil
}

// QuickScanWithOptions 使用完整选项的快速扫描函数
func QuickScanWithOptions(opts *ScanOptions) ([]ScanResult, error) {
	factory := NewScannerFactory()

	// 创建Scanner实例
	scanner, err := factory.CreateScannerWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("创建Scanner失败: %v", err)
	}

	// 执行扫描
	ctx := context.Background()
	scanResults, err := scanner.Scan(ctx)
	if err != nil {
		return nil, err
	}

	// 转换结果类型
	results := make([]ScanResult, len(scanResults))
	for i, result := range scanResults {
		results[i] = *result
	}

	return results, nil
}
