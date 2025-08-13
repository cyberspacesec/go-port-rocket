package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/api"
	"github.com/cyberspacesec/go-port-rocket/pkg/output"
	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	// 扫描参数
	target           string
	ports            string
	scanType         string
	timeout          time.Duration
	workers          int
	outputFormat     string
	outputFile       string
	prettyOutput     bool
	enableOS         bool
	enableService    bool
	versionIntensity int
	guessOS          bool
	limitOSScan      bool

	// API服务配置
	apiHost       string
	apiPort       int
	jwtSecret     string
	redisAddr     string
	redisPass     string
	redisDB       int
	maxWorkers    int
	queueSize     int
	enableAuth    bool
	allowInMemory bool

	// MCP扫描和API参数本地变量
	mcpConfigData string
	mcpInputFile  string
)

// MCPScanConfig 多行命令处理扫描配置
type MCPScanConfig struct {
	Target           string `json:"target"`                      // 扫描目标
	Ports            string `json:"ports"`                       // 端口范围
	ScanType         string `json:"scan_type"`                   // 扫描类型 (tcp/udp)
	Timeout          string `json:"timeout,omitempty"`           // 超时时间
	Workers          int    `json:"workers,omitempty"`           // 工作线程数
	OutputFormat     string `json:"format,omitempty"`            // 输出格式
	OutputFile       string `json:"output,omitempty"`            // 输出文件
	PrettyOutput     bool   `json:"pretty,omitempty"`            // 美化输出
	EnableOS         bool   `json:"os_detection,omitempty"`      // 启用操作系统检测
	EnableService    bool   `json:"service_detection,omitempty"` // 启用服务检测
	VersionIntensity int    `json:"version_intensity,omitempty"` // 版本检测强度
	GuessOS          bool   `json:"guess_os,omitempty"`          // 推测操作系统
	LimitOSScan      bool   `json:"limit_os,omitempty"`          // 限制操作系统扫描
}

// MCPAPIConfig API服务MCP配置
type MCPAPIConfig struct {
	Host          string `json:"host,omitempty"`           // 监听地址
	Port          int    `json:"port,omitempty"`           // 监听端口
	JWTSecret     string `json:"jwt_secret,omitempty"`     // JWT密钥
	RedisAddr     string `json:"redis_addr,omitempty"`     // Redis地址
	RedisPassword string `json:"redis_password,omitempty"` // Redis密码
	RedisDB       int    `json:"redis_db,omitempty"`       // Redis数据库
	MaxWorkers    int    `json:"max_workers,omitempty"`    // 最大工作线程数
	QueueSize     int    `json:"queue_size,omitempty"`     // 任务队列大小
	EnableAuth    bool   `json:"enable_auth,omitempty"`    // 启用认证
}

// 初始化命令
func init() {
	// 扫描命令 - 已在scan.go中定义
	/* scanCmd已在scan.go中定义，注释掉这部分代码
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "执行端口扫描",
		Long:  `执行端口扫描，支持TCP和UDP协议，可以进行服务识别和操作系统检测。`,
		Run:   runScan,
	}

	// 扫描参数
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "扫描目标 (IP地址或域名)")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "端口范围 (例如: 80,443 或 1-1024)")
	scanCmd.Flags().StringVarP(&scanType, "scan-type", "s", "tcp", "扫描类型 (tcp 或 udp)")
	scanCmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "超时时间")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 100, "工作线程数")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "输出格式 (text, json, xml, html)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件路径")
	scanCmd.Flags().BoolVarP(&prettyOutput, "pretty", "P", false, "美化输出")
	scanCmd.Flags().BoolVarP(&enableOS, "os-detection", "O", false, "启用操作系统检测")
	scanCmd.Flags().BoolVar(&enableService, "service-detection", false, "启用服务检测")
	scanCmd.Flags().IntVar(&versionIntensity, "version-intensity", 7, "版本检测强度 (0-9)")
	scanCmd.Flags().BoolVar(&guessOS, "guess-os", false, "推测操作系统")
	scanCmd.Flags().BoolVar(&limitOSScan, "limit-os", false, "限制操作系统扫描")
	scanCmd.MarkPersistentFlagRequired("target")
	scanCmd.MarkPersistentFlagRequired("ports")
	*/

	// API服务命令
	apiCmd := &cobra.Command{
		Use:   "api",
		Short: "启动API服务",
		Long:  `启动HTTP API服务，提供端口扫描功能的RESTful接口。`,
		Run:   runAPIServer,
	}

	// API服务参数
	apiCmd.Flags().StringVar(&apiHost, "host", "0.0.0.0", "API服务监听地址")
	apiCmd.Flags().IntVar(&apiPort, "port", 8080, "API服务监听端口")
	apiCmd.Flags().StringVar(&jwtSecret, "jwt-secret", "", "JWT密钥")
	apiCmd.Flags().StringVar(&redisAddr, "redis-addr", "localhost:6379", "Redis服务器地址")
	apiCmd.Flags().StringVar(&redisPass, "redis-pass", "", "Redis密码")
	apiCmd.Flags().IntVar(&redisDB, "redis-db", 0, "Redis数据库编号")
	apiCmd.Flags().IntVar(&maxWorkers, "max-workers", 10, "最大工作线程数")
	apiCmd.Flags().IntVar(&queueSize, "queue-size", 100, "任务队列大小")
	apiCmd.Flags().BoolVar(&enableAuth, "enable-auth", true, "启用认证")
	apiCmd.Flags().BoolVar(&allowInMemory, "allow-inmemory", false, "允许在Redis连接失败时降级使用内存存储")

	// 添加命令
	RootCmd.AddCommand(apiCmd)
}

// runScan 执行扫描
func runScan(cmd *cobra.Command, args []string) {
	// 创建扫描选项
	scanOpts := &scanner.ScanOptions{
		Target:           target,
		Ports:            ports,
		ScanType:         scanner.ScanType(scanType),
		Timeout:          timeout,
		Workers:          workers,
		EnableOS:         enableOS,
		EnableService:    enableService,
		VersionIntensity: versionIntensity,
		GuessOS:          guessOS,
		LimitOSScan:      limitOSScan,
	}

	// 创建扫描器
	scanner, err := scanner.NewScanner(scanOpts)
	if err != nil {
		fmt.Printf("创建扫描器失败: %v\n", err)
		os.Exit(1)
	}

	// 创建输出选项
	var writer = os.Stdout
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Printf("创建输出文件失败: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		writer = file
	}

	outputOpts := &output.Options{
		Format:    outputFormat,
		Pretty:    prettyOutput,
		Writer:    writer,
		Target:    target,
		ScanType:  scanType,
		StartTime: time.Now(),
	}

	// 创建输出处理器
	outputHandler, err := output.NewOutput(outputOpts)
	if err != nil {
		fmt.Printf("创建输出处理器失败: %v\n", err)
		os.Exit(1)
	}

	// 执行扫描
	fmt.Printf("开始扫描目标: %s\n", target)
	results, err := scanner.Scan(cmd.Context())
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		os.Exit(1)
	}

	// 更新输出选项的结束时间
	outputOpts.EndTime = time.Now()
	outputOpts.Duration = outputOpts.EndTime.Sub(outputOpts.StartTime)

	// 写入结果
	if err := outputHandler.Write(results); err != nil {
		fmt.Printf("写入结果失败: %v\n", err)
		os.Exit(1)
	}
}

// runAPIServer 运行API服务
func runAPIServer(cmd *cobra.Command, args []string) {
	// 检查必要参数
	if enableAuth && jwtSecret == "" {
		fmt.Println("错误: 启用认证时必须提供JWT密钥")
		fmt.Println("\n您可以使用以下方式解决此问题:")
		fmt.Println("1. 提供JWT密钥: ./go-port-rocket api --jwt-secret=\"your-secret-key\"")
		fmt.Println("2. 禁用认证功能: ./go-port-rocket api --enable-auth=false")
		fmt.Println("\n示例:")
		fmt.Println("  ./go-port-rocket api --enable-auth=false --port=8888")
		fmt.Println("  ./go-port-rocket api --jwt-secret=\"secure-key\" --port=8888")
		os.Exit(1)
	}

	// 在创建服务之前先打印API使用提示
	fmt.Printf("API服务正在启动...\n\n")
	fmt.Println("您可以使用以下命令进行测试:")

	// 根据是否启用认证，提供不同的示例
	if enableAuth {
		fmt.Printf("1. 登录获取令牌:\n   curl -s -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"admin\",\"password\":\"password\"}' http://%s:%d/api/v1/auth/login\n\n", apiHost, apiPort)
		fmt.Printf("2. 使用令牌创建扫描任务:\n   curl -s -X POST -H \"Content-Type: application/json\" -H \"Authorization: Bearer YOUR_TOKEN\" -d '{\"target\":\"localhost\",\"ports\":\"80,443\",\"scan_type\":\"tcp\"}' http://%s:%d/api/v1/scan/\n\n", apiHost, apiPort)
	} else {
		fmt.Printf("1. 创建扫描任务:\n   curl -s -X POST -H \"Content-Type: application/json\" -d '{\"target\":\"localhost\",\"ports\":\"80,443\",\"scan_type\":\"tcp\"}' http://%s:%d/api/v1/scan/\n\n", apiHost, apiPort)
	}

	fmt.Printf("3. 查看任务状态:\n   curl -s http://%s:%d/api/v1/scan/tasks/{task_id}\n\n", apiHost, apiPort)
	fmt.Printf("4. 查看系统状态:\n   curl -s http://%s:%d/api/v1/system/status\n\n", apiHost, apiPort)
	fmt.Println("📚 完整API文档请访问: https://cyberspacesec.github.io/go-port-rocket/docs/http-api.html")
	fmt.Println()
	fmt.Println("按 Ctrl+C 停止服务")
	fmt.Println("------------------------------------------------------")

	// 创建API服务配置
	config := &api.ServerConfig{
		Host:           apiHost,
		Port:           apiPort,
		JWTSecret:      jwtSecret,
		RedisAddr:      redisAddr,
		RedisPassword:  redisPass,
		RedisDB:        redisDB,
		MaxConcurrency: maxWorkers,
		QueueSize:      queueSize,
		EnableAuth:     enableAuth,
		AllowInMemory:  allowInMemory,
	}

	// 创建API服务
	server := api.NewServer(config)

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动API服务
	go func() {
		fmt.Printf("API服务已启动，监听地址: %s:%d\n", apiHost, apiPort)

		if err := server.Start(); err != nil {
			fmt.Printf("API服务启动失败: %v\n", err)
			os.Exit(1)
		}
	}()

	// 等待退出信号
	<-sigChan
	fmt.Println("\n正在关闭API服务...")
	server.Stop()
	fmt.Println("API服务已关闭")
}
