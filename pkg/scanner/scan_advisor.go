package scanner

import (
	"fmt"
	"strings"
	"time"
)

// ScanAdvisor 扫描建议器
type ScanAdvisor struct {
	opts      *ScanOptions
	portCount int
}

// NewScanAdvisor 创建扫描建议器
func NewScanAdvisor(opts *ScanOptions) (*ScanAdvisor, error) {
	ports, err := parsePorts(opts.Ports)
	if err != nil {
		return nil, err
	}

	return &ScanAdvisor{
		opts:      opts,
		portCount: len(ports),
	}, nil
}

// AnalyzeAndSuggest 分析扫描配置并提供建议
func (sa *ScanAdvisor) AnalyzeAndSuggest() []string {
	var suggestions []string

	// 分析端口范围 - 降低阈值
	if sa.portCount > 5000 {
		suggestions = append(suggestions, sa.suggestPortOptimization())
	}

	// 分析并发设置 - 降低阈值
	if sa.opts.Workers > 30 {
		suggestions = append(suggestions, sa.suggestConcurrencyOptimization())
	}

	// 分析超时设置 - 降低阈值
	if sa.opts.Timeout > 3*time.Second && sa.portCount > 500 {
		suggestions = append(suggestions, sa.suggestTimeoutOptimization())
	}

	// 分析功能启用 - 降低阈值
	if sa.isAllFeaturesEnabled() && sa.portCount > 100 {
		suggestions = append(suggestions, sa.suggestFeatureOptimization())
	}

	// 分析目标类型
	if sa.isPublicTarget() {
		suggestions = append(suggestions, sa.suggestTargetOptimization())
	}

	// 估算扫描时间 - 降低阈值
	estimatedTime := sa.estimateScanTime()
	if estimatedTime > 5*time.Minute {
		suggestions = append(suggestions, sa.suggestTimeOptimization(estimatedTime))
	}

	// 添加通用建议
	if sa.portCount > 1000 && sa.opts.Workers > 20 {
		suggestions = append(suggestions, "⚠️ 大规模扫描建议: 考虑分批扫描以获得更好的性能和稳定性")
	}

	return suggestions
}

// suggestPortOptimization 端口优化建议
func (sa *ScanAdvisor) suggestPortOptimization() string {
	return fmt.Sprintf("🔍 端口范围优化建议:\n"+
		"   当前要扫描 %d 个端口，建议:\n"+
		"   • 使用常见端口: \"21-25,53,80,110,143,443,993,995\"\n"+
		"   • 或分批扫描: \"1-1000\", \"1001-2000\" 等\n"+
		"   • 或使用预定义端口集: \"--top-ports 1000\"",
		sa.portCount)
}

// suggestConcurrencyOptimization 并发优化建议
func (sa *ScanAdvisor) suggestConcurrencyOptimization() string {
	optimal := calculateOptimalWorkers(sa.portCount)
	return fmt.Sprintf("⚡ 并发优化建议:\n"+
		"   当前并发数 %d 可能过高，建议:\n"+
		"   • 降低到 %d (根据端口数量优化)\n"+
		"   • 大规模扫描时使用 10-20 个并发\n"+
		"   • 避免超过系统文件描述符限制",
		sa.opts.Workers, optimal)
}

// suggestTimeoutOptimization 超时优化建议
func (sa *ScanAdvisor) suggestTimeoutOptimization() string {
	return fmt.Sprintf("⏱️ 超时优化建议:\n"+
		"   当前超时 %.1f 秒对于 %d 个端口可能过长，建议:\n"+
		"   • 大规模扫描使用 1-2 秒超时\n"+
		"   • 本地网络可使用 0.5 秒\n"+
		"   • 公网扫描使用 2-3 秒",
		sa.opts.Timeout.Seconds(), sa.portCount)
}

// suggestFeatureOptimization 功能优化建议
func (sa *ScanAdvisor) suggestFeatureOptimization() string {
	return "🔧 功能优化建议:\n" +
		"   启用了所有检测功能会显著增加扫描时间，建议:\n" +
		"   • 首次扫描只检测端口开放状态\n" +
		"   • 对开放端口再进行服务检测\n" +
		"   • 分阶段进行: 端口扫描 → 服务检测 → 版本识别"
}

// suggestTargetOptimization 目标优化建议
func (sa *ScanAdvisor) suggestTargetOptimization() string {
	return "🎯 目标优化建议:\n" +
		"   检测到公网目标，建议:\n" +
		"   • 降低扫描速度以避免被防火墙拦截\n" +
		"   • 使用随机化端口顺序\n" +
		"   • 考虑使用代理或分布式扫描\n" +
		"   • 遵守目标服务器的使用条款"
}

// suggestTimeOptimization 时间优化建议
func (sa *ScanAdvisor) suggestTimeOptimization(estimatedTime time.Duration) string {
	return fmt.Sprintf("⏰ 时间优化建议:\n"+
		"   预估扫描时间: %s，建议:\n"+
		"   • 分批扫描以获得更快的初步结果\n"+
		"   • 优先扫描常见端口\n"+
		"   • 使用更短的超时时间\n"+
		"   • 考虑使用SYN扫描(需要root权限)",
		formatDuration(estimatedTime))
}

// isAllFeaturesEnabled 检查是否启用了所有功能
func (sa *ScanAdvisor) isAllFeaturesEnabled() bool {
	return sa.opts.EnableService && sa.opts.EnableOS &&
		sa.opts.ServiceProbe && sa.opts.BannerProbe
}

// isPublicTarget 检查是否为公网目标
func (sa *ScanAdvisor) isPublicTarget() bool {
	target := strings.ToLower(sa.opts.Target)
	// 简单检查，实际应该更完善
	return !strings.Contains(target, "127.0.0.1") &&
		!strings.Contains(target, "localhost") &&
		!strings.HasPrefix(target, "192.168.") &&
		!strings.HasPrefix(target, "10.") &&
		!strings.HasPrefix(target, "172.")
}

// estimateScanTime 估算扫描时间
func (sa *ScanAdvisor) estimateScanTime() time.Duration {
	baseTimePerPort := sa.opts.Timeout

	// 考虑功能开销
	if sa.opts.EnableService {
		baseTimePerPort += time.Second
	}
	if sa.opts.EnableOS {
		baseTimePerPort += time.Second * 2
	}
	if sa.opts.BannerProbe {
		baseTimePerPort += time.Millisecond * 500
	}

	// 考虑并发
	totalTime := time.Duration(sa.portCount) * baseTimePerPort / time.Duration(sa.opts.Workers)

	return totalTime
}

// formatDuration 格式化时间显示
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f秒", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1f分钟", d.Minutes())
	} else {
		return fmt.Sprintf("%.1f小时", d.Hours())
	}
}

// PrintSuggestions 打印建议
func (sa *ScanAdvisor) PrintSuggestions() {
	suggestions := sa.AnalyzeAndSuggest()

	if len(suggestions) == 0 {
		fmt.Println("✅ 扫描配置看起来不错！")
		return
	}

	fmt.Println("💡 扫描配置建议 (可选优化，不会强制修改您的设置):")
	for i, suggestion := range suggestions {
		fmt.Printf("\n%d. %s\n", i+1, suggestion)
	}

	fmt.Println("\n📝 这些只是建议，工具会按您的设置执行扫描")
	fmt.Println("   如遇到性能问题，可参考上述建议进行调整")
}

// GetOptimizedConfig 获取优化后的配置
func (sa *ScanAdvisor) GetOptimizedConfig() *ScanOptions {
	optimized := *sa.opts // 复制原配置

	// 应用优化
	if sa.portCount > 10000 {
		optimized.Workers = min(50, calculateOptimalWorkers(sa.portCount))
		optimized.Timeout = time.Second * 2
	} else if sa.portCount > 1000 {
		optimized.Workers = min(30, calculateOptimalWorkers(sa.portCount))
		optimized.Timeout = time.Second * 3
	}

	// 大规模扫描时建议禁用一些功能以提高速度，但不强制覆盖用户设置
	// 只有当用户没有明确设置时才应用优化
	if sa.portCount > 5000 {
		// 注意：这里不再强制覆盖用户的EnableOS设置
		// 如果用户明确启用了OS检测，我们尊重用户的选择
		// optimized.EnableOS = false  // 移除强制覆盖

		// 只在用户没有设置版本检测强度时才优化
		if sa.opts.VersionIntensity == 0 {
			optimized.VersionIntensity = 3
		}
	}

	return &optimized
}
