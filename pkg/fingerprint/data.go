package fingerprint

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

//go:embed data/nmap-service-probes data/nmap-os-db data/nmap-services
var embeddedData embed.FS

// 记录已经提取的临时目录，以便程序退出时清理
var extractedTempDirs []string

// ExtractEmbeddedData 提取嵌入的Nmap指纹数据到临时目录
func ExtractEmbeddedData() (string, error) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "go-port-rocket-fingerprints")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %v", err)
	}

	// 添加到临时目录列表中，以便退出时清理
	extractedTempDirs = append(extractedTempDirs, tempDir)

	// 提取所有嵌入的文件
	err = fs.WalkDir(embeddedData, "data", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// 跳过根目录
		if path == "data" {
			return nil
		}

		// 获取目标路径
		relPath, err := filepath.Rel("data", path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(tempDir, relPath)

		// 如果是目录，创建它
		if d.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		// 读取文件内容
		data, err := embeddedData.ReadFile(path)
		if err != nil {
			return err
		}

		// 写入文件
		return os.WriteFile(destPath, data, 0644)
	})

	if err != nil {
		os.RemoveAll(tempDir) // 清理临时目录
		return "", err
	}

	return tempDir, nil
}

// GetEmbeddedFingerprintPath 获取嵌入指纹数据的路径
func GetEmbeddedFingerprintPath() (string, error) {
	return ExtractEmbeddedData()
}

// CleanupTempDirs 清理所有创建的临时目录
func CleanupTempDirs() {
	for _, dir := range extractedTempDirs {
		os.RemoveAll(dir)
	}
	extractedTempDirs = nil
}

// init 注册程序退出时的清理函数
func init() {
	// 确保在程序退出时清理临时目录
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		CleanupTempDirs()
		os.Exit(0)
	}()
}
