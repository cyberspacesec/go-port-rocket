package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

func main() {
	// 创建基本扫描选项
	scanOptions := &scanner.ScanOptions{
		Target:        "scanme.nmap.org",   // 扫描目标，nmap官方提供的测试服务器
		Ports:         "21-25,80,443,3306", // 扫描端口范围
		ScanType:      scanner.ScanTypeTCP, // TCP扫描类型
		Timeout:       time.Second * 5,     // 扫描超时
		Workers:       20,                  // 工作线程数
		EnableService: true,                // 启用服务检测
	}

	// 执行扫描
	fmt.Println("开始端口扫描...")
	startTime := time.Now()
	scanResult, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		log.Fatalf("扫描过程中出错: %v", err)
	}
	endTime := time.Now()

	// 统计开放/关闭/过滤端口数量
	var openPorts, closedPorts, filteredPorts int
	for _, result := range scanResult {
		switch result.State {
		case scanner.PortStateOpen:
			openPorts++
		case scanner.PortStateClosed:
			closedPorts++
		case scanner.PortStateFiltered:
			filteredPorts++
		}
	}

	// 创建输出目录（如果不存在）
	outputDir := "./output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	// 准备UDP结果（空）和服务信息
	var udpResults []scanner.UDPScanResult
	var serviceInfo = make(map[int]*scanner.ServiceInfo)
	var hostStatus []scanner.HostStatus

	// 提取服务信息
	for _, result := range scanResult {
		if result.State == scanner.PortStateOpen && result.ServiceName != "" {
			serviceInfo[result.Port] = &scanner.ServiceInfo{
				Name:    result.ServiceName,
				Port:    result.Port,
				Version: result.Version,
			}
			if result.Service != nil && result.Service.Product != "" {
				serviceInfo[result.Port].Product = result.Service.Product
			}
		}
	}

	// ExecuteScan返回的是值切片[]ScanResult，不是指针切片[]*ScanResult
	// 所以直接使用scanResult而不需要解引用
	scanResults := scanResult

	// 创建输出数据
	outputData := scanner.CreateScanOutputFromResults(
		scanOptions.Target,
		scanResults,
		udpResults,
		serviceInfo,
		hostStatus,
		startTime,
		endTime,
	)

	// 输出不同格式的结果
	outputFormats := []struct {
		name   string
		format string
		file   string
	}{
		{"文本格式", scanner.OutputFormatText, filepath.Join(outputDir, "scan_result.txt")},
		{"JSON格式", scanner.OutputFormatJSON, filepath.Join(outputDir, "scan_result.json")},
		{"XML格式", scanner.OutputFormatXML, filepath.Join(outputDir, "scan_result.xml")},
		{"CSV格式", scanner.OutputFormatCSV, filepath.Join(outputDir, "scan_result.csv")},
	}

	// 输出扫描结果到不同格式
	for _, format := range outputFormats {
		outputOptions := &scanner.OutputOptions{
			Format:     format.format,
			OutputFile: format.file,
			Verbose:    true,
		}

		if err := scanner.SaveScanResult(outputData, outputOptions); err != nil {
			log.Printf("保存 %s 失败: %v", format.name, err)
			continue
		}
		fmt.Printf("已保存 %s 到文件: %s\n", format.name, format.file)
	}

	// 打印扫描摘要
	duration := endTime.Sub(startTime)
	fmt.Println("\n扫描摘要:")
	fmt.Printf("目标: %s\n", scanOptions.Target)
	fmt.Printf("端口范围: %s\n", scanOptions.Ports)
	fmt.Printf("扫描时长: %.2f秒\n", duration.Seconds())
	fmt.Printf("总端口数: %d\n", len(scanResult))
	fmt.Printf("开放端口: %d\n", openPorts)
	fmt.Printf("关闭端口: %d\n", closedPorts)
	fmt.Printf("过滤端口: %d\n", filteredPorts)

	fmt.Println("\n请查看 ./output 目录下的结果文件")
}
