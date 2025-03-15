package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config 配置结构体
type Config struct {
	Scan struct {
		DefaultTimeout    time.Duration `mapstructure:"default_timeout"`
		DefaultWorkers    int           `mapstructure:"default_workers"`
		MaxWorkers        int           `mapstructure:"max_workers"`
		RetryCount        int           `mapstructure:"retry_count"`
		RetryDelay        time.Duration `mapstructure:"retry_delay"`
		RateLimit         int           `mapstructure:"rate_limit"`
		ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
	} `mapstructure:"scan"`

	Log struct {
		Level      string `mapstructure:"level"`
		Format     string `mapstructure:"format"`
		OutputFile string `mapstructure:"output_file"`
		MaxSize    int    `mapstructure:"max_size"`
		MaxBackups int    `mapstructure:"max_backups"`
		MaxAge     int    `mapstructure:"max_age"`
	} `mapstructure:"log"`

	Output struct {
		DefaultFormat string `mapstructure:"default_format"`
		DefaultFile   string `mapstructure:"default_file"`
	} `mapstructure:"output"`

	Metrics MetricsConfig `mapstructure:"metrics"`
}

// MetricsConfig 指标配置结构体
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Address string `mapstructure:"address"`
	Path    string `mapstructure:"path"`
}

var (
	globalConfig *Config
)

// LoadConfig 加载配置
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.go-port-rocket")
	viper.AddConfigPath("/etc/go-port-rocket")

	if configPath != "" {
		viper.SetConfigFile(configPath)
	}

	// 设置默认值
	setDefaults()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %v", err)
		}
	}

	// 读取环境变量
	viper.AutomaticEnv()

	// 解析配置
	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}

	globalConfig = config
	return config, nil
}

// GetConfig 获取全局配置
func GetConfig() *Config {
	return globalConfig
}

// SetConfig 设置全局配置
func SetConfig(cfg *Config) {
	globalConfig = cfg
}

// setDefaults 设置默认值
func setDefaults() {
	// 扫描配置默认值
	viper.SetDefault("scan.default_timeout", "2s")
	viper.SetDefault("scan.default_workers", 100)
	viper.SetDefault("scan.max_workers", 1000)
	viper.SetDefault("scan.retry_count", 3)
	viper.SetDefault("scan.retry_delay", "1s")
	viper.SetDefault("scan.rate_limit", 1000)
	viper.SetDefault("scan.connection_timeout", "5s")

	// 日志配置默认值
	viper.SetDefault("log.level", "debug")
	viper.SetDefault("log.format", "text")
	viper.SetDefault("log.output_file", "go-port-rocket.log")
	viper.SetDefault("log.max_size", 100)
	viper.SetDefault("log.max_backups", 3)
	viper.SetDefault("log.max_age", 28)

	// 输出配置默认值
	viper.SetDefault("output.default_format", "text")
	viper.SetDefault("output.default_file", "scan_results.txt")

	// 指标配置默认值
	viper.SetDefault("metrics.enabled", false)
	viper.SetDefault("metrics.address", ":9090")
	viper.SetDefault("metrics.path", "/metrics")
}

// EnsureConfigDir 确保配置目录存在
func EnsureConfigDir() error {
	configDir := filepath.Join(os.Getenv("HOME"), ".go-port-rocket")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %v", err)
	}
	return nil
}
