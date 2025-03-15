package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// 批量扫描的选项
type BatchScanOptions struct {
	InputFile    string // 输入文件路径
	OutputFolder string // 输出文件夹
	OutputFormat string // 输出格式 (text, csv, json, xml)
	Ports        string // 要扫描的端口
	Timeout      int    // 超时时间(秒)
	Workers      int    // 工作线程数
	Concurrent   int    // 并发扫描的目标数
}

func main() {
	// 添加快速模式参数
	fastMode := flag.Bool("fast", false, "快速模式 - 只扫描少量端口")

	// 解析命令行参数
	inputFile := flag.String("input", "", "包含目标列表的文件路径（每行一个目标）")
	outputFolder := flag.String("output", "batch_results", "保存扫描结果的文件夹")
	outputFormat := flag.String("format", "text", "输出格式: text, csv, json, xml")
	ports := flag.String("ports", "22,80,443", "要扫描的端口（逗号分隔或范围）")
	timeout := flag.Int("timeout", 2, "单个目标扫描的超时时间(秒)")
	workers := flag.Int("workers", 20, "单个目标的扫描线程数")
	concurrent := flag.Int("concurrent", 2, "并发扫描的目标数")

	flag.Parse()

	// 如果是快速模式，进一步减少端口范围
	if *fastMode {
		*ports = "22,80"
		*concurrent = 1
		fmt.Println("使用快速模式，只扫描最基本的端口 (22,80)")
	}

	// 如果没有提供输入文件，使用示例目标
	if *inputFile == "" {
		fmt.Println("未提供输入文件，使用示例目标进行批量扫描演示")
		*inputFile = createExampleInputFile()
	}

	// 初始化扫描选项
	options := &BatchScanOptions{
		InputFile:    *inputFile,
		OutputFolder: *outputFolder,
		OutputFormat: *outputFormat,
		Ports:        *ports,
		Timeout:      *timeout,
		Workers:      *workers,
		Concurrent:   *concurrent,
	}

	// 执行批量扫描
	err := runBatchScan(options)
	if err != nil {
		fmt.Printf("批量扫描出错: %v\n", err)
		os.Exit(1)
	}
}

// 创建示例输入文件
func createExampleInputFile() string {
	// 示例目标
	targets := []string{
		"scanme.nmap.org",
		"example.com",
	}

	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "port-rocket-batch-targets-*.txt")
	if err != nil {
		fmt.Printf("创建临时文件失败: %v\n", err)
		os.Exit(1)
	}

	// 写入目标
	for _, target := range targets {
		tmpFile.WriteString(target + "\n")
	}

	tmpFile.Close()
	fmt.Printf("已创建示例目标文件: %s\n", tmpFile.Name())

	return tmpFile.Name()
}

// 执行批量扫描
func runBatchScan(options *BatchScanOptions) error {
	startTime := time.Now()

	// 打印扫描配置
	fmt.Println("====================================")
	fmt.Println("       批量端口扫描")
	fmt.Println("====================================")
	fmt.Printf("输入文件: %s\n", options.InputFile)
	fmt.Printf("输出文件夹: %s\n", options.OutputFolder)
	fmt.Printf("输出格式: %s\n", options.OutputFormat)
	fmt.Printf("端口范围: %s\n", options.Ports)
	fmt.Printf("超时时间: %d秒\n", options.Timeout)
	fmt.Printf("单目标工作线程: %d\n", options.Workers)
	fmt.Printf("并发扫描目标数: %d\n", options.Concurrent)
	fmt.Println("====================================")

	// 读取目标文件
	targets, err := readTargets(options.InputFile)
	if err != nil {
		return fmt.Errorf("读取目标文件失败: %v", err)
	}

	fmt.Printf("从文件 %s 中读取了 %d 个目标\n", options.InputFile, len(targets))

	// 创建输出文件夹
	err = os.MkdirAll(options.OutputFolder, 0755)
	if err != nil {
		return fmt.Errorf("创建输出文件夹失败: %v", err)
	}

	// 创建CSV摘要文件
	summaryFile, err := createSummaryFile(options.OutputFolder)
	if err != nil {
		return fmt.Errorf("创建摘要文件失败: %v", err)
	}
	defer summaryFile.Close()

	csvWriter := csv.NewWriter(summaryFile)
	csvWriter.Write([]string{"目标", "总端口数", "开放端口数", "关闭端口数", "过滤端口数", "扫描时间(秒)", "开放端口列表"})

	// 使用信号量控制并发
	semaphore := make(chan struct{}, options.Concurrent)
	var wg sync.WaitGroup

	// 进度统计
	var (
		completedTargets int
		totalTargets     = len(targets)
		progressMutex    sync.Mutex
	)

	// 扫描所有目标
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{} // 占用一个并发槽

		go func(target string) {
			defer func() {
				<-semaphore // 释放一个并发槽
				wg.Done()

				// 更新进度
				progressMutex.Lock()
				completedTargets++
				progressMutex.Unlock()

				// 打印进度
				fmt.Printf("\r扫描进度: %d/%d (%.1f%%)",
					completedTargets, totalTargets,
					float64(completedTargets)/float64(totalTargets)*100.0)
			}()

			// 为目标创建输出文件
			outputBaseName := sanitizeFilename(target)
			outputFile := filepath.Join(options.OutputFolder, outputBaseName)

			// 执行扫描
			scanStart := time.Now()

			scanOptions := &scanner.ScanOptions{
				Target:   target,
				Ports:    options.Ports,
				ScanType: scanner.ScanTypeTCP,
				Timeout:  time.Duration(options.Timeout) * time.Second,
				Workers:  options.Workers,
			}

			scanResults, err := scanner.ExecuteScan(scanOptions)
			scanDuration := time.Since(scanStart)

			// 统计结果
			var (
				openCount     = 0
				closedCount   = 0
				filteredCount = 0
				openPorts     = []string{}
			)

			if err == nil {
				for _, result := range scanResults {
					switch result.State {
					case scanner.PortStateOpen:
						openCount++
						openPorts = append(openPorts, fmt.Sprintf("%d", result.Port))
					case scanner.PortStateClosed:
						closedCount++
					case scanner.PortStateFiltered:
						filteredCount++
					}
				}
			}

			// 保存单独的结果文件
			saveOutputFile(scanResults, err, outputFile, options.OutputFormat)

			// 添加到摘要CSV
			progressMutex.Lock()
			csvWriter.Write([]string{
				target,
				fmt.Sprintf("%d", len(scanResults)),
				fmt.Sprintf("%d", openCount),
				fmt.Sprintf("%d", closedCount),
				fmt.Sprintf("%d", filteredCount),
				fmt.Sprintf("%.2f", scanDuration.Seconds()),
				strings.Join(openPorts, ", "),
			})
			csvWriter.Flush()
			progressMutex.Unlock()
		}(target)
	}

	// 等待所有扫描完成
	wg.Wait()

	// 扫描完成
	totalDuration := time.Since(startTime)
	fmt.Printf("\n\n扫描完成！总耗时: %.2f秒\n", totalDuration.Seconds())
	fmt.Printf("扫描结果已保存至: %s\n", options.OutputFolder)
	fmt.Printf("摘要文件: %s\n", filepath.Join(options.OutputFolder, "summary.csv"))

	return nil
}

// 读取目标文件
func readTargets(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释行
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	return targets, scanner.Err()
}

// 创建扫描摘要文件
func createSummaryFile(outputFolder string) (*os.File, error) {
	summaryPath := filepath.Join(outputFolder, "summary.csv")
	return os.Create(summaryPath)
}

// 将扫描结果保存到文件
func saveOutputFile(results []scanner.ScanResult, scanErr error, outputBasePath string, format string) {
	var outputPath string

	switch format {
	case "json":
		outputPath = outputBasePath + ".json"
		// 简化示例，实际代码应生成JSON格式
		file, _ := os.Create(outputPath)
		defer file.Close()
		file.WriteString("{\n  \"results\": [\n")
		for i, result := range results {
			if i > 0 {
				file.WriteString(",\n")
			}
			file.WriteString(fmt.Sprintf("    {\"port\": %d, \"state\": \"%s\"}",
				result.Port, result.State))
		}
		file.WriteString("\n  ]\n}")

	case "xml":
		outputPath = outputBasePath + ".xml"
		// 简化示例，实际代码应生成XML格式
		file, _ := os.Create(outputPath)
		defer file.Close()
		file.WriteString("<scan>\n")
		for _, result := range results {
			file.WriteString(fmt.Sprintf("  <port number=\"%d\" state=\"%s\" />\n",
				result.Port, result.State))
		}
		file.WriteString("</scan>")

	case "csv":
		outputPath = outputBasePath + ".csv"
		file, _ := os.Create(outputPath)
		defer file.Close()
		csvWriter := csv.NewWriter(file)
		csvWriter.Write([]string{"Port", "State", "Service"})
		for _, result := range results {
			serviceName := ""
			if result.Service != nil {
				serviceName = result.Service.Name
			}
			csvWriter.Write([]string{
				fmt.Sprintf("%d", result.Port),
				string(result.State),
				serviceName,
			})
		}
		csvWriter.Flush()

	default: // text
		outputPath = outputBasePath + ".txt"
		file, _ := os.Create(outputPath)
		defer file.Close()
		file.WriteString(fmt.Sprintf("扫描结果: %s\n\n", outputBasePath))

		if scanErr != nil {
			file.WriteString(fmt.Sprintf("扫描错误: %v\n", scanErr))
			return
		}

		file.WriteString("PORT     STATE     SERVICE\n")
		for _, result := range results {
			serviceName := ""
			if result.Service != nil {
				serviceName = result.Service.Name
			}
			file.WriteString(fmt.Sprintf("%-8d %-9s %s\n",
				result.Port, result.State, serviceName))
		}
	}
}

// 处理文件名使其安全
func sanitizeFilename(filename string) string {
	// 替换不安全的字符
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " "}
	safe := []string{"_", "_", "_", "_", "_", "_", "_", "_", "_", "_"}

	for i, char := range unsafe {
		filename = strings.ReplaceAll(filename, char, safe[i])
	}

	return filename
}
