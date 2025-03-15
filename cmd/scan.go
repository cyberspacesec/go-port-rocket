package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scanTarget           string
	scanPorts            string
	scanTypeOption       string
	scanTimeout          time.Duration
	scanWorkers          int
	scanOutputFile       string
	scanEnableService    bool
	scanServiceProbe     bool
	scanBannerProbe      bool
	scanVersionIntensity int
	scanEnableOS         bool
	scanGuessOS          bool
	scanLimitOSScan      bool
)

func init() {
	// 创建scan命令
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "执行端口扫描",
		Long: `执行端口扫描，支持多种扫描方式。
例如：
  go-port-rocket scan -t 192.168.1.1 -p 1-1000 -s tcp
  go-port-rocket scan -t example.com -p 80,443,8080-8090 -s syn
  go-port-rocket scan -t example.com -p 53,161,162 -s udp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 验证必要参数
			if scanTarget == "" {
				return fmt.Errorf("必须指定目标 (-t)")
			}
			if scanPorts == "" {
				return fmt.Errorf("必须指定端口范围 (-p)")
			}

			// 设置服务检测选项
			var serviceOptions *scanner.ServiceDetectionOptions
			if scanEnableService {
				serviceOptions = &scanner.ServiceDetectionOptions{
					EnableVersionDetection: scanEnableService,
					VersionIntensity:       scanVersionIntensity,
					BannerGrab:             scanBannerProbe,
					Timeout:                scanTimeout,
					EnableOSDetection:      scanEnableOS,
				}
			}

			// 创建扫描选项
			opts := &scanner.ScanOptions{
				Target:           scanTarget,
				Ports:            scanPorts,
				ScanType:         scanner.ScanType(scanTypeOption),
				Timeout:          scanTimeout,
				Workers:          scanWorkers,
				OutputFile:       scanOutputFile,
				EnableService:    scanEnableService,
				ServiceProbe:     scanServiceProbe,
				BannerProbe:      scanBannerProbe,
				VersionIntensity: scanVersionIntensity,
				Service:          serviceOptions,
				EnableOS:         scanEnableOS,
				GuessOS:          scanGuessOS,
				LimitOSScan:      scanLimitOSScan,
			}

			// 记录开始时间
			startTime := time.Now()

			// 执行扫描
			results, err := scanner.ExecuteScan(opts)
			if err != nil {
				return fmt.Errorf("扫描失败: %v", err)
			}

			// 记录结束时间
			endTime := time.Now()

			// 打印结果到控制台
			scanner.PrintResults(results)

			// 如果指定了输出文件，则保存结果到文件
			if scanOutputFile != "" {
				// 将扫描结果转换为适合输出的格式
				var udpResults []scanner.UDPScanResult // 由于我们没有UDP扫描结果，创建一个空切片
				var serviceInfo map[int]*scanner.ServiceInfo = make(map[int]*scanner.ServiceInfo)
				var hostStatus []scanner.HostStatus // 没有主机状态，创建一个空切片

				// 提取服务信息
				for _, result := range results {
					if result.State == scanner.PortStateOpen && result.ServiceName != "" {
						serviceInfo[result.Port] = &scanner.ServiceInfo{
							Name: result.ServiceName,
							Port: result.Port,
						}
					}
				}

				// 创建输出数据
				output := scanner.CreateScanOutputFromResults(
					scanTarget,
					results,
					udpResults,
					serviceInfo,
					hostStatus,
					startTime,
					endTime,
				)

				// 确定输出格式（基于文件扩展名或默认为JSON）
				format := scanner.OutputFormatJSON
				isHtml := false
				if len(scanOutputFile) > 4 {
					ext := strings.ToLower(filepath.Ext(scanOutputFile))
					switch ext {
					case ".xml":
						format = scanner.OutputFormatXML
					case ".csv":
						format = scanner.OutputFormatCSV
					case ".txt":
						format = scanner.OutputFormatText
					case ".htm", ".html":
						isHtml = true // 标记为HTML格式
					}
				}

				// 对于HTML格式，使用我们自己的HTML生成函数
				if isHtml {
					fmt.Printf("正在保存扫描结果到HTML文件: %s\n", scanOutputFile)

					// 使用ConvertScannerResultToOutput函数生成HTML
					if err := ConvertScannerResultToOutput(results, scanOutputFile, scanTarget, string(scanTypeOption), startTime, endTime); err != nil {
						fmt.Printf("保存扫描结果到HTML文件 %s 失败: %v\n", scanOutputFile, err)
					} else {
						fmt.Printf("扫描结果已保存到: %s\n", scanOutputFile)
					}
				} else {
					// 对于其他格式，保持原有处理方式
					// 保存到文件
					fmt.Printf("正在保存扫描结果到文件: %s (格式: %s)\n", scanOutputFile, format)
					outputOptions := &scanner.OutputOptions{
						Format:     format,
						OutputFile: scanOutputFile,
						Verbose:    true,
					}

					if err := scanner.SaveScanResult(output, outputOptions); err != nil {
						fmt.Printf("保存扫描结果到文件 %s 失败: %v\n", scanOutputFile, err)
					} else {
						fmt.Printf("扫描结果已保存到: %s\n", scanOutputFile)
					}
				}
			}

			return nil
		},
	}

	// 添加命令行参数
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "目标IP地址或域名")
	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "", "端口范围，例如：80,443,8080-8090")
	scanCmd.Flags().StringVarP(&scanTypeOption, "scan", "s", "tcp", "扫描类型：tcp, syn, fin, null, xmas, ack, udp")
	scanCmd.Flags().DurationVarP(&scanTimeout, "timeout", "T", 2*time.Second, "超时时间")
	scanCmd.Flags().IntVarP(&scanWorkers, "workers", "w", 100, "并发工作线程数")
	scanCmd.Flags().StringVarP(&scanOutputFile, "output", "o", "", "输出文件路径")

	// 添加服务检测相关参数
	scanCmd.Flags().BoolVar(&scanEnableService, "service-detection", false, "启用服务检测")
	scanCmd.Flags().BoolVar(&scanServiceProbe, "service-probe", false, "启用服务探测")
	scanCmd.Flags().BoolVar(&scanBannerProbe, "banner-grab", false, "获取服务banner")
	scanCmd.Flags().IntVar(&scanVersionIntensity, "version-intensity", 7, "版本检测强度 (0-9)")

	// 添加操作系统检测相关参数
	scanCmd.Flags().BoolVarP(&scanEnableOS, "os-detection", "O", false, "启用操作系统检测")
	scanCmd.Flags().BoolVar(&scanGuessOS, "guess-os", false, "根据TTL猜测操作系统")
	scanCmd.Flags().BoolVar(&scanLimitOSScan, "limit-os-scan", false, "限制对开放端口的主机进行OS扫描")

	// 绑定到viper配置
	viper.BindPFlag("scan.target", scanCmd.Flags().Lookup("target"))
	viper.BindPFlag("scan.ports", scanCmd.Flags().Lookup("ports"))
	viper.BindPFlag("scan.type", scanCmd.Flags().Lookup("scan"))
	viper.BindPFlag("scan.timeout", scanCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("scan.workers", scanCmd.Flags().Lookup("workers"))
	viper.BindPFlag("scan.output", scanCmd.Flags().Lookup("output"))
	viper.BindPFlag("scan.service_detection", scanCmd.Flags().Lookup("service-detection"))
	viper.BindPFlag("scan.service_probe", scanCmd.Flags().Lookup("service-probe"))
	viper.BindPFlag("scan.banner_grab", scanCmd.Flags().Lookup("banner-grab"))
	viper.BindPFlag("scan.version_intensity", scanCmd.Flags().Lookup("version-intensity"))
	viper.BindPFlag("scan.os_detection", scanCmd.Flags().Lookup("os-detection"))
	viper.BindPFlag("scan.guess_os", scanCmd.Flags().Lookup("guess-os"))
	viper.BindPFlag("scan.limit_os_scan", scanCmd.Flags().Lookup("limit-os-scan"))

	// 设置必填参数
	scanCmd.MarkFlagRequired("target")
	scanCmd.MarkFlagRequired("ports")

	// 添加到根命令
	RootCmd.AddCommand(scanCmd)
}
