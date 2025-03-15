package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// 扫描相关指标
	scanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "port_scan_duration_seconds",
			Help:    "端口扫描耗时",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"target", "scan_type"},
	)

	portsScanned = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ports_scanned_total",
			Help: "已扫描的端口总数",
		},
		[]string{"target", "scan_type"},
	)

	openPorts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "open_ports",
			Help: "开放的端口数量",
		},
		[]string{"target", "scan_type"},
	)

	closedPorts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "closed_ports",
			Help: "关闭的端口数量",
		},
		[]string{"target", "scan_type"},
	)

	filteredPorts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "filtered_ports",
			Help: "被过滤的端口数量",
		},
		[]string{"target", "scan_type"},
	)

	// 错误相关指标
	scanErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_errors_total",
			Help: "扫描错误总数",
		},
		[]string{"target", "scan_type", "error_type"},
	)

	// 资源使用指标
	goroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "goroutines",
			Help: "当前goroutine数量",
		},
	)

	memoryUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "memory_usage_bytes",
			Help: "当前内存使用量",
		},
	)

	// 性能指标
	scanRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scan_rate_ports_per_second",
			Help: "扫描速率（每秒端口数）",
		},
		[]string{"target", "scan_type"},
	)

	// 注册所有指标
	once sync.Once
)

// InitMetrics 初始化指标系统
func InitMetrics() error {
	cfg := config.GetConfig()
	if cfg == nil {
		return nil
	}

	if !cfg.Metrics.Enabled {
		return nil
	}

	once.Do(func() {
		// 注册所有指标
		prometheus.MustRegister(scanDuration)
		prometheus.MustRegister(portsScanned)
		prometheus.MustRegister(openPorts)
		prometheus.MustRegister(closedPorts)
		prometheus.MustRegister(filteredPorts)
		prometheus.MustRegister(scanErrors)
		prometheus.MustRegister(goroutines)
		prometheus.MustRegister(memoryUsage)
		prometheus.MustRegister(scanRate)

		// 启动HTTP服务器
		go func() {
			http.Handle(cfg.Metrics.Path, promhttp.Handler())
			if err := http.ListenAndServe(cfg.Metrics.Address, nil); err != nil {
				panic(err)
			}
		}()
	})

	return nil
}

// RecordScanDuration 记录扫描耗时
func RecordScanDuration(target, scanType string, duration time.Duration) {
	scanDuration.WithLabelValues(target, scanType).Observe(duration.Seconds())
}

// IncrementPortsScanned 增加已扫描端口计数
func IncrementPortsScanned(target, scanType string) {
	portsScanned.WithLabelValues(target, scanType).Inc()
}

// SetOpenPorts 设置开放端口数量
func SetOpenPorts(target, scanType string, count float64) {
	openPorts.WithLabelValues(target, scanType).Set(count)
}

// SetClosedPorts 设置关闭端口数量
func SetClosedPorts(target, scanType string, count float64) {
	closedPorts.WithLabelValues(target, scanType).Set(count)
}

// SetFilteredPorts 设置被过滤端口数量
func SetFilteredPorts(target, scanType string, count float64) {
	filteredPorts.WithLabelValues(target, scanType).Set(count)
}

// IncrementScanErrors 增加扫描错误计数
func IncrementScanErrors(target, scanType, errorType string) {
	scanErrors.WithLabelValues(target, scanType, errorType).Inc()
}

// UpdateGoroutines 更新goroutine数量
func UpdateGoroutines(count float64) {
	goroutines.Set(count)
}

// UpdateMemoryUsage 更新内存使用量
func UpdateMemoryUsage(bytes float64) {
	memoryUsage.Set(bytes)
}

// SetScanRate 设置扫描速率
func SetScanRate(target, scanType string, rate float64) {
	scanRate.WithLabelValues(target, scanType).Set(rate)
}
