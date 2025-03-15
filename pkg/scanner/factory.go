package scanner

import (
	"fmt"
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
