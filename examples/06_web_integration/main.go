package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// ScanRequest 扫描请求结构体
type ScanRequest struct {
	Target      string `json:"target"`      // 扫描目标
	Ports       string `json:"ports"`       // 端口范围
	ScanType    string `json:"scan_type"`   // 扫描类型
	EnableOS    bool   `json:"enable_os"`   // 启用操作系统检测
	Concurrency int    `json:"concurrency"` // 并发数
	Timeout     int    `json:"timeout"`     // 超时（秒）
}

// ScanResponse 扫描响应结构体
type ScanResponse struct {
	Success   bool                  `json:"success"`    // 是否成功
	Message   string                `json:"message"`    // 消息
	Results   []*scanner.ScanResult `json:"results"`    // 扫描结果
	StartTime time.Time             `json:"start_time"` // 开始时间
	EndTime   time.Time             `json:"end_time"`   // 结束时间
	Duration  float64               `json:"duration"`   // 扫描用时（秒）
}

// ErrorResponse 错误响应结构体
type ErrorResponse struct {
	Success bool   `json:"success"` // 是否成功
	Error   string `json:"error"`   // 错误信息
}

// 主函数
func main() {
	// 设置扫描处理程序
	http.HandleFunc("/api/scan", scanHandler)

	// 提供静态文件（HTML、CSS、JS等）
	http.Handle("/", http.FileServer(http.Dir("./static")))

	// 启动服务器
	port := 8080
	fmt.Printf("启动Web服务器在 http://localhost:%d\n", port)
	fmt.Println("使用 Ctrl+C 停止服务器")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// scanHandler 处理扫描请求
func scanHandler(w http.ResponseWriter, r *http.Request) {
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	// 只允许POST请求
	if r.Method != http.MethodPost {
		writeError(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体
	var req ScanRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 参数验证
	if req.Target == "" {
		writeError(w, "必须指定目标", http.StatusBadRequest)
		return
	}

	if req.Ports == "" {
		writeError(w, "必须指定端口范围", http.StatusBadRequest)
		return
	}

	// 设置默认值
	if req.ScanType == "" {
		req.ScanType = "tcp"
	}

	if req.Concurrency <= 0 {
		req.Concurrency = 50
	}

	if req.Timeout <= 0 {
		req.Timeout = 5
	}

	// 创建扫描选项
	scanOptions := &scanner.ScanOptions{
		Target:        req.Target,
		Ports:         req.Ports,
		ScanType:      scanner.ScanType(req.ScanType),
		Timeout:       time.Duration(req.Timeout) * time.Second,
		Workers:       req.Concurrency,
		EnableOS:      req.EnableOS,
		EnableService: true,
	}

	// 创建扫描器
	scannerInstance, err := scanner.NewScanner(scanOptions)
	if err != nil {
		writeError(w, "创建扫描器失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置最大扫描时间（避免长时间运行的扫描）
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	// 执行扫描
	startTime := time.Now()
	results, err := scannerInstance.Scan(ctx)
	endTime := time.Now()

	if err != nil {
		writeError(w, "扫描执行失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 构建响应
	response := ScanResponse{
		Success:   true,
		Message:   "扫描完成",
		Results:   results,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime).Seconds(),
	}

	// 返回JSON响应
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		log.Printf("编码响应失败: %v", err)
	}
}

// writeError 输出错误响应
func writeError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Success: false,
		Error:   message,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("编码错误响应失败: %v", err)
	}
}
