package test

import (
	"testing"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// TestConfigurationRespected 测试用户配置是否被正确应用
func TestConfigurationRespected(t *testing.T) {
	// 测试TCP扫描配置
	t.Run("TCP扫描配置测试", func(t *testing.T) {
		scanOpts := &scanner.ScanOptions{
			Target:           "127.0.0.1",
			Ports:            "22,80,443",
			ScanType:         scanner.ScanTypeTCP,
			Timeout:          2 * time.Second,
			Workers:          5,
			EnableService:    false, // 明确禁用服务检测
			EnableOS:         false, // 明确禁用OS检测
			ServiceProbe:     false, // 明确禁用服务探测
			BannerProbe:      false, // 明确禁用Banner抓取
			VersionIntensity: 0,     // 禁用版本检测
		}

		results, err := scanner.ExecuteScan(scanOpts)
		if err != nil {
			t.Fatalf("TCP扫描失败: %v", err)
		}

		// 验证结果
		if len(results) == 0 {
			t.Error("TCP扫描没有返回任何结果")
		}

		// 验证配置被正确应用（服务和OS信息应该为空）
		for _, result := range results {
			if result.Service != nil {
				t.Errorf("端口 %d: 服务检测应该被禁用，但返回了服务信息: %+v", result.Port, result.Service)
			}
			if result.OS != nil {
				t.Errorf("端口 %d: OS检测应该被禁用，但返回了OS信息: %+v", result.Port, result.OS)
			}
		}
	})

	// 测试SYN扫描配置（如果有权限）
	t.Run("SYN扫描配置测试", func(t *testing.T) {
		scanOpts := &scanner.ScanOptions{
			Target:           "127.0.0.1",
			Ports:            "80",
			ScanType:         scanner.ScanTypeSYN,
			Timeout:          2 * time.Second,
			Workers:          5,
			EnableService:    false, // 明确禁用服务检测
			EnableOS:         false, // 明确禁用OS检测
			ServiceProbe:     false, // 明确禁用服务探测
			BannerProbe:      false, // 明确禁用Banner抓取
			VersionIntensity: 0,     // 禁用版本检测
		}

		results, err := scanner.ExecuteScan(scanOpts)
		// SYN扫描可能需要root权限，所以我们允许权限错误
		if err != nil {
			if err == scanner.ErrRootRequired ||
				err.Error() == "root privileges required" ||
				err.Error() == "扫描失败: root privileges required" {
				t.Skip("SYN扫描需要root权限，跳过测试")
				return
			}
			t.Fatalf("SYN扫描失败: %v", err)
		}

		// 验证配置被正确应用
		for _, result := range results {
			if result.Service != nil {
				t.Errorf("端口 %d: 服务检测应该被禁用，但返回了服务信息: %+v", result.Port, result.Service)
			}
			if result.OS != nil {
				t.Errorf("端口 %d: OS检测应该被禁用，但返回了OS信息: %+v", result.Port, result.OS)
			}
		}
	})

	// 测试UDP扫描配置
	t.Run("UDP扫描配置测试", func(t *testing.T) {
		scanOpts := &scanner.ScanOptions{
			Target:           "127.0.0.1",
			Ports:            "53",
			ScanType:         scanner.ScanTypeUDP,
			Timeout:          2 * time.Second,
			Workers:          5,
			EnableService:    false, // 明确禁用服务检测
			EnableOS:         false, // 明确禁用OS检测
			ServiceProbe:     false, // 明确禁用服务探测
			BannerProbe:      false, // 明确禁用Banner抓取
			VersionIntensity: 0,     // 禁用版本检测
		}

		results, err := scanner.ExecuteScan(scanOpts)
		if err != nil {
			t.Fatalf("UDP扫描失败: %v", err)
		}

		// 验证配置被正确应用
		for _, result := range results {
			if result.Service != nil {
				t.Errorf("端口 %d: 服务检测应该被禁用，但返回了服务信息: %+v", result.Port, result.Service)
			}
			if result.OS != nil {
				t.Errorf("端口 %d: OS检测应该被禁用，但返回了OS信息: %+v", result.Port, result.OS)
			}
		}
	})
}
