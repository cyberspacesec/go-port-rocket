package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/config"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	globalLogger *logrus.Logger
)

// InitLogger 初始化日志系统
func InitLogger() error {
	cfg := config.GetConfig()
	if cfg == nil {
		return fmt.Errorf("配置未初始化")
	}

	// 创建日志目录
	logDir := filepath.Dir(cfg.Log.OutputFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 设置日志级别
	level, err := logrus.ParseLevel(cfg.Log.Level)
	if err != nil {
		return fmt.Errorf("解析日志级别失败: %v", err)
	}

	// 创建日志记录器
	logger := logrus.New()
	logger.SetLevel(level)

	// 设置日志格式
	switch cfg.Log.Format {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	default:
		// 自定义文本格式化器 - 添加颜色
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
			ForceColors:     true,
			DisableColors:   false,
			PadLevelText:    true,
			// 定义不同级别日志的颜色
			DisableLevelTruncation: false,
			QuoteEmptyFields:       true,
		})
	}

	// 设置日志输出
	if cfg.Log.OutputFile != "" {
		// 使用 lumberjack 进行日志轮转
		logger.SetOutput(&lumberjack.Logger{
			Filename:   cfg.Log.OutputFile,
			MaxSize:    cfg.Log.MaxSize,    // 每个日志文件的最大大小（MB）
			MaxBackups: cfg.Log.MaxBackups, // 保留的旧日志文件数量
			MaxAge:     cfg.Log.MaxAge,     // 日志文件保留天数
			Compress:   true,               // 压缩旧日志文件
		})
	}

	globalLogger = logger
	return nil
}

// GetLogger 获取全局日志记录器
func GetLogger() *logrus.Logger {
	return globalLogger
}

// Debug 记录调试级别日志
func Debug(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debug(args...)
	}
}

// Debugf 记录调试级别格式化日志
func Debugf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugf(format, args...)
	}
}

// Info 记录信息级别日志
func Info(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Info(args...)
	}
}

// Infof 记录信息级别格式化日志
func Infof(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infof(format, args...)
	}
}

// Warn 记录警告级别日志
func Warn(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warn(args...)
	}
}

// Warnf 记录警告级别格式化日志
func Warnf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnf(format, args...)
	}
}

// Error 记录错误级别日志
func Error(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Error(args...)
	}
}

// Errorf 记录错误级别格式化日志
func Errorf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorf(format, args...)
	}
}

// Fatal 记录致命错误级别日志并退出
func Fatal(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Fatal(args...)
	}
}

// Fatalf 记录致命错误级别格式化日志并退出
func Fatalf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Fatalf(format, args...)
	}
}
