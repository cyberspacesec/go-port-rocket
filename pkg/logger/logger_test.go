package logger

import (
	"os"
	"path/filepath"
	"testing"

	"go-port-rocket/config"

	"github.com/stretchr/testify/assert"
)

func TestInitLogger(t *testing.T) {
	// 创建临时目录
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// 创建配置
	cfg := &config.Config{}
	cfg.Log.Level = "debug"
	cfg.Log.Format = "json"
	cfg.Log.OutputFile = logFile
	cfg.Log.MaxSize = 1
	cfg.Log.MaxBackups = 1
	cfg.Log.MaxAge = 1

	// 设置全局配置
	config.SetConfig(cfg)

	// 初始化日志系统
	err := InitLogger()
	assert.NoError(t, err)

	// 验证日志文件是否创建
	_, err = os.Stat(logFile)
	assert.NoError(t, err)

	// 测试各种日志级别
	Debug("debug message")
	Debugf("debug message %s", "formatted")
	Info("info message")
	Infof("info message %s", "formatted")
	Warn("warn message")
	Warnf("warn message %s", "formatted")
	Error("error message")
	Errorf("error message %s", "formatted")

	// 验证日志内容
	content, err := os.ReadFile(logFile)
	assert.NoError(t, err)
	assert.NotEmpty(t, content)
}

func TestGetLogger(t *testing.T) {
	// 初始化前应该返回nil
	logger := GetLogger()
	assert.Nil(t, logger)

	// 创建临时目录
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// 创建配置
	cfg := &config.Config{}
	cfg.Log.Level = "info"
	cfg.Log.Format = "text"
	cfg.Log.OutputFile = logFile

	// 设置全局配置
	config.SetConfig(cfg)

	// 初始化日志系统
	err := InitLogger()
	assert.NoError(t, err)

	// 初始化后应该返回非nil
	logger = GetLogger()
	assert.NotNil(t, logger)
}

func TestLoggerWithoutConfig(t *testing.T) {
	// 测试在没有配置的情况下调用日志函数
	Debug("debug message")
	Debugf("debug message %s", "formatted")
	Info("info message")
	Infof("info message %s", "formatted")
	Warn("warn message")
	Warnf("warn message %s", "formatted")
	Error("error message")
	Errorf("error message %s", "formatted")
	// 这些调用不应该导致panic
}

func TestLoggerWithInvalidConfig(t *testing.T) {
	// 创建无效配置
	cfg := &config.Config{}
	cfg.Log.Level = "invalid"
	cfg.Log.Format = "invalid"
	cfg.Log.OutputFile = "/invalid/path/test.log"

	// 设置全局配置
	config.SetConfig(cfg)

	// 初始化日志系统应该返回错误
	err := InitLogger()
	assert.Error(t, err)
}

func TestFatalFunctions(t *testing.T) {
	// 这些函数会导致程序退出，所以我们只测试它们是否存在
	assert.NotPanics(t, func() {
		// 不实际调用Fatal/Fatalf，因为它们会导致程序退出
		_ = Fatal
		_ = Fatalf
	})
}
