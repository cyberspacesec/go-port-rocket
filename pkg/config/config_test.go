package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// 创建临时目录和配置文件
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	// 创建测试配置内容
	configContent := `
scan:
  default_timeout: 5s
  default_workers: 100
  max_workers: 1000
  retry_count: 3
  retry_delay: 1s
  rate_limit: 1000
  connection_timeout: 5s

log:
  level: info
  format: text
  output_file: go-port-rocket.log
  max_size: 100
  max_backups: 3
  max_age: 28

output:
  default_format: text
  default_file: scan_results.txt

metrics:
  enabled: true
  address: :9090
  path: /metrics
`

	// 写入配置文件
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	assert.NoError(t, err)

	tests := []struct {
		name       string
		configPath string
		wantErr    bool
	}{
		{
			name:       "valid config file",
			configPath: configFile,
			wantErr:    false,
		},
		{
			name:       "non-existent config file",
			configPath: "non-existent.yaml",
			wantErr:    false, // 应该使用默认值
		},
		{
			name:       "empty config path",
			configPath: "",
			wantErr:    false, // 应该使用默认值
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadConfig(tt.configPath)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, cfg)

			if tt.configPath == configFile {
				// 验证加载的配置值
				assert.Equal(t, 5*time.Second, cfg.Scan.DefaultTimeout)
				assert.Equal(t, 100, cfg.Scan.DefaultWorkers)
				assert.Equal(t, 1000, cfg.Scan.MaxWorkers)
				assert.Equal(t, 3, cfg.Scan.RetryCount)
				assert.Equal(t, time.Second, cfg.Scan.RetryDelay)
				assert.Equal(t, 1000, cfg.Scan.RateLimit)
				assert.Equal(t, 5*time.Second, cfg.Scan.ConnectionTimeout)

				assert.Equal(t, "info", cfg.Log.Level)
				assert.Equal(t, "text", cfg.Log.Format)
				assert.Equal(t, "go-port-rocket.log", cfg.Log.OutputFile)
				assert.Equal(t, 100, cfg.Log.MaxSize)
				assert.Equal(t, 3, cfg.Log.MaxBackups)
				assert.Equal(t, 28, cfg.Log.MaxAge)

				assert.Equal(t, "text", cfg.Output.DefaultFormat)
				assert.Equal(t, "scan_results.txt", cfg.Output.DefaultFile)

				assert.True(t, cfg.Metrics.Enabled)
				assert.Equal(t, ":9090", cfg.Metrics.Address)
				assert.Equal(t, "/metrics", cfg.Metrics.Path)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	// 测试初始状态
	cfg := GetConfig()
	assert.Nil(t, cfg)

	// 设置配置
	testConfig := &Config{}
	SetConfig(testConfig)

	// 验证获取的配置
	cfg = GetConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, testConfig, cfg)
}

func TestSetConfig(t *testing.T) {
	// 设置配置
	testConfig := &Config{
		Metrics: MetricsConfig{
			Enabled: true,
			Address: ":9090",
			Path:    "/metrics",
		},
	}
	SetConfig(testConfig)

	// 验证配置是否正确设置
	cfg := GetConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, testConfig, cfg)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, ":9090", cfg.Metrics.Address)
	assert.Equal(t, "/metrics", cfg.Metrics.Path)
}

func TestEnsureConfigDir(t *testing.T) {
	// 保存原始的HOME环境变量
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	// 创建临时目录作为HOME
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)

	// 测试创建配置目录
	err := EnsureConfigDir()
	assert.NoError(t, err)

	// 验证目录是否创建
	configDir := filepath.Join(tmpDir, ".go-port-rocket")
	info, err := os.Stat(configDir)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
}
