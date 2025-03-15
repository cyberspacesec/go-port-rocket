package metrics

import (
	"testing"
	"time"

	"go-port-rocket/config"

	"github.com/stretchr/testify/assert"
)

func TestInitMetrics(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "metrics disabled",
			cfg: &config.Config{
				Metrics: config.MetricsConfig{
					Enabled: false,
					Address: ":9090",
					Path:    "/metrics",
				},
			},
			wantErr: false,
		},
		{
			name: "metrics enabled",
			cfg: &config.Config{
				Metrics: config.MetricsConfig{
					Enabled: true,
					Address: ":9090",
					Path:    "/metrics",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.SetConfig(tt.cfg)
			err := InitMetrics()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetricsFunctions(t *testing.T) {
	// 初始化指标系统
	cfg := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: true,
			Address: ":9091",
			Path:    "/metrics",
		},
	}
	config.SetConfig(cfg)
	err := InitMetrics()
	assert.NoError(t, err)

	// 测试各种指标函数
	target := "127.0.0.1"
	scanType := "tcp"

	// 记录扫描耗时
	RecordScanDuration(target, scanType, time.Second)

	// 增加已扫描端口计数
	IncrementPortsScanned(target, scanType)

	// 设置开放端口数量
	SetOpenPorts(target, scanType, 5)

	// 设置关闭端口数量
	SetClosedPorts(target, scanType, 10)

	// 设置被过滤端口数量
	SetFilteredPorts(target, scanType, 2)

	// 增加扫描错误计数
	IncrementScanErrors(target, scanType, "timeout")

	// 更新goroutine数量
	UpdateGoroutines(100)

	// 更新内存使用量
	UpdateMemoryUsage(1024 * 1024)

	// 设置扫描速率
	SetScanRate(target, scanType, 1000)
}

func TestMetricsWithoutInit(t *testing.T) {
	// 测试在未初始化的情况下调用指标函数
	target := "127.0.0.1"
	scanType := "tcp"

	// 这些调用不应该导致panic
	RecordScanDuration(target, scanType, time.Second)
	IncrementPortsScanned(target, scanType)
	SetOpenPorts(target, scanType, 5)
	SetClosedPorts(target, scanType, 10)
	SetFilteredPorts(target, scanType, 2)
	IncrementScanErrors(target, scanType, "timeout")
	UpdateGoroutines(100)
	UpdateMemoryUsage(1024 * 1024)
	SetScanRate(target, scanType, 1000)
}
