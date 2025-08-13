package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// Output 输出接口
type Output interface {
	Write(results []*scanner.ScanResult) error
}

// TextOutput 文本输出
type TextOutput struct {
	opts *Options
}

// JSONOutput JSON输出
type JSONOutput struct {
	opts *Options
}

// XMLOutput XML输出
type XMLOutput struct {
	opts *Options
}

// HTMLOutput HTML输出
type HTMLOutput struct {
	opts *Options
}

// NewOutput 创建新的输出处理器
func NewOutput(opts *Options) (Output, error) {
	if opts == nil {
		return nil, fmt.Errorf("输出选项不能为空")
	}

	// 如果指定了输出文件，确保目录存在
	if writer, ok := opts.Writer.(*os.File); ok {
		dir := filepath.Dir(writer.Name())
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建输出目录失败: %v", err)
		}
	}

	// 根据格式创建对应的输出处理器
	switch strings.ToLower(opts.Format) {
	case "text":
		return &TextOutput{opts: opts}, nil
	case "json":
		return &JSONOutput{opts: opts}, nil
	case "xml":
		return &XMLOutput{opts: opts}, nil
	case "html":
		return &HTMLOutput{opts: opts}, nil
	default:
		return nil, fmt.Errorf("不支持的输出格式: %s", opts.Format)
	}
}

// Write 写入文本输出
func (o *TextOutput) Write(results []*scanner.ScanResult) error {
	stats := calculateStatistics(results, o.opts.Duration)

	// 写入扫描标题和信息
	fmt.Fprintf(o.opts.Writer, "\n%s\n", ColorizeHeader("╭─────────────────────────────────────────────────────╮"))
	fmt.Fprintf(o.opts.Writer, "%s\n", ColorizeHeader("│               Go-Port-Rocket 扫描报告                │"))
	fmt.Fprintf(o.opts.Writer, "%s\n\n", ColorizeHeader("╰─────────────────────────────────────────────────────╯"))

	// 写入扫描基本信息
	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  扫描目标:"), ColorizeHighlight(o.opts.Target))
	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  扫描类型:"), ColorizeInfo(o.opts.ScanType))
	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  开始时间:"), o.opts.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  结束时间:"), o.opts.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(o.opts.Writer, "%s %.2f %s\n\n", ColorizeTitle("●  扫描耗时:"), stats.ScanDuration.Seconds(), "秒")

	// 写入端口结果
	fmt.Fprintf(o.opts.Writer, "%s\n", ColorizeHeader("╭─────────────────────────────────────────────────────╮"))
	fmt.Fprintf(o.opts.Writer, "%s\n", ColorizeHeader("│                    端口扫描结果                     │"))
	fmt.Fprintf(o.opts.Writer, "%s\n", ColorizeHeader("╰─────────────────────────────────────────────────────╯"))

	if len(results) == 0 {
		fmt.Fprintf(o.opts.Writer, "\n%s\n\n", ColorizeWarning("未发现开放端口"))
	} else {
		// 使用更美观的表格格式输出端口结果
		fmt.Fprintf(o.opts.Writer, "\n%-15s %-10s %-20s %-25s\n",
			ColorizeTitle("端口"),
			ColorizeTitle("状态"),
			ColorizeTitle("服务"),
			ColorizeTitle("操作系统"))
		fmt.Fprintf(o.opts.Writer, "%s\n", strings.Repeat("─", 70))

		for _, result := range results {
			// 根据端口状态设置不同颜色
			var portStatus string
			switch result.State {
			case scanner.PortStateOpen:
				portStatus = ColorizeOpen("开放")
			case scanner.PortStateClosed:
				portStatus = ColorizeClosed("关闭")
			case scanner.PortStateFiltered:
				portStatus = ColorizeFiltered("过滤")
			default:
				portStatus = string(result.State)
			}

			// 端口和协议
			portInfo := fmt.Sprintf("%d/%s", result.Port, o.opts.ScanType)

			// 服务信息
			serviceInfo := ""
			if result.Service != nil {
				serviceInfo = result.Service.Name
				if result.Service.Version != "" {
					serviceInfo += " " + result.Service.Version
				}
				if result.Service.Product != "" {
					serviceInfo += " (" + result.Service.Product + ")"
				}
			}

			// 操作系统信息
			osInfo := ""
			if result.OS != nil {
				osInfo = result.OS.Name
				if result.OS.Version != "" {
					osInfo += " " + result.OS.Version
				}
			}

			fmt.Fprintf(o.opts.Writer, "%-15s %-10s %-20s %-25s\n",
				ColorizeHighlight(portInfo),
				portStatus,
				ColorizeInfo(serviceInfo),
				ColorizeInfo(osInfo))

			// 如果存在Banner信息，则显示
			var bannerText string
			if result.Banner != "" {
				// 优先使用ScanResult中直接存储的Banner
				bannerText = result.Banner
			} else if result.Service != nil && result.Service.Banner != "" {
				// 其次使用Service中的Banner
				bannerText = result.Service.Banner
			}

			if bannerText != "" {
				fmt.Fprintf(o.opts.Writer, "  %s\n", ColorizeTitle("● Banner 信息:"))

				// 处理多行Banner
				bannerLines := strings.Split(bannerText, "\n")

				// 计算Banner的行数，以决定显示方式
				validLines := 0
				for _, line := range bannerLines {
					if strings.TrimSpace(line) != "" {
						validLines++
					}
				}

				// Banner内容框
				if validLines > 0 {
					fmt.Fprintf(o.opts.Writer, "    %s\n", strings.Repeat("─", 70))
				}

				for i, line := range bannerLines {
					// 过滤掉空行和只包含控制字符的行
					if strings.TrimSpace(line) == "" {
						continue
					}

					// 对可能的控制字符进行转义处理
					escapedLine := strings.Map(func(r rune) rune {
						if r < 32 && r != '\t' && r != '\n' && r != '\r' {
							return '.'
						}
						return r
					}, line)

					// 使用行号格式化
					fmt.Fprintf(o.opts.Writer, "    %s %s\n",
						ColorizeNumber(fmt.Sprintf("%2d│", i+1)),
						ColorizeInfo(escapedLine))
				}

				if validLines > 0 {
					fmt.Fprintf(o.opts.Writer, "    %s\n", strings.Repeat("─", 70))
				}
			}
		}
		fmt.Fprintln(o.opts.Writer, "")
	}

	// 写入统计信息
	fmt.Fprintf(o.opts.Writer, "%s\n", ColorizeHeader("╭─────────────────────────────────────────────────────╮"))
	fmt.Fprintf(o.opts.Writer, "%s\n", ColorizeHeader("│                    扫描统计信息                     │"))
	fmt.Fprintf(o.opts.Writer, "%s\n\n", ColorizeHeader("╰─────────────────────────────────────────────────────╯"))

	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  总端口数:"), ColorizeNumber(fmt.Sprintf("%d", stats.TotalPorts)))
	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  开放端口:"), ColorizeNumber(fmt.Sprintf("%d", stats.OpenPorts)))
	fmt.Fprintf(o.opts.Writer, "%s %s\n", ColorizeTitle("●  关闭端口:"), ColorizeNumber(fmt.Sprintf("%d", stats.ClosedPorts)))
	fmt.Fprintf(o.opts.Writer, "%s %s\n\n", ColorizeTitle("●  过滤端口:"), ColorizeNumber(fmt.Sprintf("%d", stats.FilteredPorts)))

	return nil
}

// Write 写入JSON输出
func (o *JSONOutput) Write(results []*scanner.ScanResult) error {
	report := NewScanReport(o.opts, results)

	encoder := json.NewEncoder(o.opts.Writer)
	if o.opts.Pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}

// Write 写入XML输出
func (o *XMLOutput) Write(results []*scanner.ScanResult) error {
	// 创建带XML标签的报告结构
	type XMLScanReport struct {
		XMLName    xml.Name              `xml:"ScanResult"`
		Target     string                `xml:"target"`
		ScanType   string                `xml:"scan_type"`
		StartTime  time.Time             `xml:"start_time"`
		EndTime    time.Time             `xml:"end_time"`
		Duration   float64               `xml:"duration"`
		Results    []*scanner.ScanResult `xml:"ports>port"`
		Statistics *Statistics           `xml:"statistics"`
	}

	report := NewScanReport(o.opts, results)
	xmlReport := XMLScanReport{
		Target:     report.Target,
		ScanType:   report.ScanType,
		StartTime:  report.StartTime,
		EndTime:    report.EndTime,
		Duration:   report.Duration,
		Results:    report.Results,
		Statistics: report.Statistics,
	}

	encoder := xml.NewEncoder(o.opts.Writer)
	if o.opts.Pretty {
		encoder.Indent("", "  ")
	}
	fmt.Fprintf(o.opts.Writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	return encoder.Encode(xmlReport)
}

// Write 写入HTML输出
func (o *HTMLOutput) Write(results []*scanner.ScanResult) error {
	const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>端口扫描报告</title>
    <style>
        :root {
            --primary-color: #4a6cf7;
            --success-color: #28a745;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #17a2b8;
            --dark-color: #343a40;
            --light-color: #f8f9fa;
            --border-color: #dee2e6;
            --text-color: #212529;
            --bg-color: #f5f5f5;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            color: var(--text-color);
            background-color: var(--bg-color);
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            background-color: white;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            border-radius: 0.25rem;
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary-color), #304ffe);
            color: white;
            padding: 2rem;
            text-align: center;
            position: relative;
        }
        
        .logo {
            font-size: 1.8rem;
            font-weight: bold;
            margin-bottom: 1rem;
        }
        
        .subtitle {
            font-size: 1.1rem;
            opacity: 0.8;
        }
        
        main {
            padding: 2rem;
        }
        
        .section {
            margin-bottom: 2.5rem;
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            overflow: hidden;
        }
        
        .section-header {
            background-color: var(--light-color);
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-body {
            padding: 1.5rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .summary-item {
            background-color: var(--light-color);
            padding: 1rem;
            border-radius: 0.25rem;
            text-align: center;
        }
        
        .summary-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }
        
        .summary-label {
            color: var(--dark-color);
            font-size: 0.9rem;
        }
        
        .port-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
        
        .port-table th, .port-table td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }
        
        .port-table th {
            background-color: var(--light-color);
            font-weight: 600;
        }
        
        .port-table tbody tr:hover {
            background-color: rgba(0,0,0,0.02);
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.85rem;
            font-weight: 600;
            text-align: center;
        }
        
        .badge-open {
            background-color: var(--success-color);
            color: white;
        }
        
        .badge-closed {
            background-color: var(--danger-color);
            color: white;
        }
        
        .badge-filtered {
            background-color: var(--warning-color);
            color: var(--dark-color);
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }
        
        .info-item {
            display: flex;
            margin-bottom: 0.5rem;
        }
        
        .info-label {
            font-weight: 600;
            min-width: 8rem;
        }
        
        .info-value {
            flex: 1;
        }
        
        .collapsible {
            cursor: pointer;
        }
        
        .collapse-icon {
            transition: transform 0.2s ease;
        }
        
        .collapsed .collapse-icon {
            transform: rotate(-90deg);
        }
        
        .collapsible-content {
            overflow: hidden;
            max-height: 1000px;
            transition: max-height 0.3s ease-in-out;
        }
        
        .collapsed .collapsible-content {
            max-height: 0;
        }
        
        .detail-row {
            display: none;
            background-color: rgba(0,0,0,0.02);
        }
        
        .detail-row td {
            padding: 0;
        }
        
        .detail-content {
            padding: 1rem;
            border-top: 1px solid var(--border-color);
        }
        
        .banner-box {
            background-color: var(--dark-color);
            color: var(--light-color);
            border-radius: 0.25rem;
            padding: 1rem;
            font-family: monospace;
            overflow-x: auto;
            white-space: pre-wrap;
            margin-top: 1rem;
            line-height: 1.2;
        }
        
        .banner-line {
            display: flex;
        }
        
        .banner-line-number {
            color: #6c757d;
            padding-right: 1rem;
            user-select: none;
            text-align: right;
            min-width: 3rem;
        }
        
        .service-highlight {
            color: #ff79c6;
        }
        
        .version-highlight {
            color: #50fa7b;
        }
        
        .os-highlight {
            color: #f1fa8c;
        }
        
        .protocol-highlight {
            color: #bd93f9;
        }
        
        footer {
            text-align: center;
            padding: 1.5rem;
            color: #6c757d;
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
        }
        
        .port-filters {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            background-color: var(--light-color);
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            padding: 0.5rem 1rem;
            cursor: pointer;
            font-size: 0.9rem;
        }
        
        .filter-btn:hover {
            background-color: var(--border-color);
        }
        
        .filter-btn.active {
            background-color: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }
        
        .hidden {
            display: none;
        }
        
        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .port-table th:nth-child(3),
            .port-table td:nth-child(3) {
                display: none;
            }
        }
        
        /* 图表样式 */
        .chart-container {
            margin-top: 1rem;
            height: 200px;
            position: relative;
        }
        
        .chart-bar {
            display: flex;
            height: 100%;
            align-items: flex-end;
            gap: 1rem;
            padding-bottom: 2rem;
        }
        
        .chart-column {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
        }
        
        .chart-value {
            background-color: var(--primary-color);
            width: 80%;
            transition: height 1s ease-out;
            border-radius: 0.25rem 0.25rem 0 0;
            min-height: 1px;
        }
        
        .chart-column:nth-child(1) .chart-value {
            background-color: var(--primary-color);
        }
        
        .chart-column:nth-child(2) .chart-value {
            background-color: var(--success-color);
        }
        
        .chart-column:nth-child(3) .chart-value {
            background-color: var(--danger-color);
        }
        
        .chart-column:nth-child(4) .chart-value {
            background-color: var(--warning-color);
        }
        
        .chart-label {
            position: absolute;
            bottom: -2rem;
            font-size: 0.8rem;
            text-align: center;
        }
        
        .chart-number {
            position: absolute;
            top: -1.5rem;
            font-size: 0.8rem;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">Go-Port-Rocket 端口扫描报告</div>
            <div class="subtitle">扫描目标: {{.Target}}</div>
        </header>
        
        <main>
            <!-- 扫描信息概要 -->
            <div class="section">
                <div class="section-header collapsible">
                    <span>扫描信息概要</span>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="section-body collapsible-content">
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">扫描目标:</div>
                            <div class="info-value">{{.Target}}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">扫描类型:</div>
                            <div class="info-value">{{.ScanType}}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">开始时间:</div>
                            <div class="info-value">{{.StartTime.Format "2006-01-02 15:04:05"}}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">结束时间:</div>
                            <div class="info-value">{{.EndTime.Format "2006-01-02 15:04:05"}}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">扫描耗时:</div>
                            <div class="info-value">{{printf "%.2f" .Duration}} 秒</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 统计信息 -->
            <div class="section">
                <div class="section-header collapsible">
                    <span>扫描统计信息</span>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="section-body collapsible-content">
                    <div class="summary-grid">
                        <div class="summary-item">
                            <div class="summary-value">{{.Statistics.TotalPorts}}</div>
                            <div class="summary-label">总端口数</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-value">{{.Statistics.OpenPorts}}</div>
                            <div class="summary-label">开放端口</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-value">{{.Statistics.ClosedPorts}}</div>
                            <div class="summary-label">关闭端口</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-value">{{.Statistics.FilteredPorts}}</div>
                            <div class="summary-label">过滤端口</div>
                        </div>
                    </div>

                    <div class="chart-container">
                        <div class="chart-bar">
                            <div class="chart-column">
                                <div class="chart-value" data-value="{{.Statistics.TotalPorts}}"></div>
                                <div class="chart-number">{{.Statistics.TotalPorts}}</div>
                                <div class="chart-label">总端口数</div>
                            </div>
                            <div class="chart-column">
                                <div class="chart-value" data-value="{{.Statistics.OpenPorts}}"></div>
                                <div class="chart-number">{{.Statistics.OpenPorts}}</div>
                                <div class="chart-label">开放端口</div>
                            </div>
                            <div class="chart-column">
                                <div class="chart-value" data-value="{{.Statistics.ClosedPorts}}"></div>
                                <div class="chart-number">{{.Statistics.ClosedPorts}}</div>
                                <div class="chart-label">关闭端口</div>
                            </div>
                            <div class="chart-column">
                                <div class="chart-value" data-value="{{.Statistics.FilteredPorts}}"></div>
                                <div class="chart-number">{{.Statistics.FilteredPorts}}</div>
                                <div class="chart-label">过滤端口</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 端口扫描结果 -->
            <div class="section">
                <div class="section-header collapsible">
                    <span>端口扫描结果</span>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="section-body collapsible-content">
                    <div class="port-filters">
                        <button class="filter-btn active" data-filter="all">全部</button>
                        <button class="filter-btn" data-filter="open">开放端口</button>
                        <button class="filter-btn" data-filter="closed">关闭端口</button>
                        <button class="filter-btn" data-filter="filtered">过滤端口</button>
                    </div>
                    
                    <table class="port-table">
                        <thead>
                            <tr>
                                <th>端口</th>
                                <th>协议</th>
                                <th>状态</th>
                                <th>服务</th>
                                <th>详情</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range $index, $result := .Results}}
                            <tr class="port-row" data-state="{{$result.State}}">
                                <td>{{$result.Port}}</td>
                                <td>{{$.ScanType}}</td>
                                <td>
                                    {{if eq $result.State "open"}}
                                    <span class="badge badge-open">开放</span>
                                    {{else if eq $result.State "closed"}}
                                    <span class="badge badge-closed">关闭</span>
                                    {{else}}
                                    <span class="badge badge-filtered">过滤</span>
                                    {{end}}
                                </td>
                                <td>
                                    {{if $result.Service}}
                                        {{$result.Service.Name}}
                                        {{if $result.Service.Version}} {{$result.Service.Version}}{{end}}
                                        {{if $result.Service.Product}} ({{$result.Service.Product}}){{end}}
                                    {{else}}
                                        {{$result.ServiceName}}
                                    {{end}}
                                </td>
                                <td>
                                    {{if or $result.Service $result.OS (ne $result.Banner "")}}
                                    <button class="toggle-details" data-index="{{$index}}">详情</button>
                                    {{end}}
                                </td>
                            </tr>
                            <tr id="details-{{$index}}" class="detail-row">
                                <td colspan="5">
                                    <div class="detail-content">
                                        {{if $result.Service}}
                                        <div class="info-item">
                                            <div class="info-label">服务名称:</div>
                                            <div class="info-value">{{$result.Service.Name}}</div>
                                        </div>
                                        {{if $result.Service.Version}}
                                        <div class="info-item">
                                            <div class="info-label">版本:</div>
                                            <div class="info-value">{{$result.Service.Version}}</div>
                                        </div>
                                        {{end}}
                                        {{if $result.Service.Product}}
                                        <div class="info-item">
                                            <div class="info-label">产品:</div>
                                            <div class="info-value">{{$result.Service.Product}}</div>
                                        </div>
                                        {{end}}
                                        {{end}}
                                        
                                        {{if $result.OS}}
                                        <div class="info-item">
                                            <div class="info-label">操作系统:</div>
                                            <div class="info-value">
                                                {{$result.OS.Name}}
                                                {{if $result.OS.Version}} {{$result.OS.Version}}{{end}}
                                                {{if $result.OS.Family}} ({{$result.OS.Family}}){{end}}
                                                - 置信度: {{printf "%.1f" $result.OS.Confidence}}%
                                            </div>
                                        </div>
                                        {{end}}
                                        
                                        {{$bannerText := ""}}
                                        {{if ne $result.Banner ""}}
                                            {{$bannerText = $result.Banner}}
                                        {{else if and $result.Service $result.Service.Banner}}
                                            {{$bannerText = $result.Service.Banner}}
                                        {{end}}
                                        
                                        {{if ne $bannerText ""}}
                                        <div class="info-item">
                                            <div class="info-label">Banner 信息:</div>
                                            <div class="info-value"></div>
                                        </div>
                                        <div class="banner-box">
                                            {{$lines := splitBanner $bannerText}}
                                            {{range $i, $line := $lines}}
                                            <div class="banner-line">
                                                <span class="banner-line-number">{{inc $i}}</span>
                                                <span class="banner-line-content">{{highlightHTML $line}}</span>
                                            </div>
                                            {{end}}
                                        </div>
                                        {{end}}
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- 安全建议 -->
            <div class="section">
                <div class="section-header collapsible">
                    <span>安全建议</span>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="section-body collapsible-content">
                    <ul style="padding-left: 1.5rem;">
                        {{if gt .Statistics.OpenPorts 0}}
                        <li>建议检查所有开放端口是否必要，关闭不需要的服务以减小攻击面</li>
                        <li>确保所有开放的服务都已更新到最新版本并正确配置安全选项</li>
                        {{if gt .Statistics.FilteredPorts 0}}
                        <li>已发现被过滤端口，建议检查防火墙规则的有效性和完整性</li>
                        {{end}}
                        {{else if gt .Statistics.FilteredPorts 0}}
                        <li>所有端口均被过滤，表明防火墙工作良好，建议持续维护更新防火墙策略</li>
                        {{else}}
                        <li>未发现开放端口，建议定期扫描确保安全状态</li>
                        {{end}}
                    </ul>
                </div>
            </div>
        </main>
        
        <footer>
            <div>Powered by Go-Port-Rocket | 生成时间: {{now}}</div>
            <div style="margin-top:0.5rem;">版本: v1.0.0 | 作者: CC11001100</div>
        </footer>
    </div>

    <script>
        // 初始化图表高度
        function initCharts() {
            const chartBars = document.querySelectorAll('.chart-value');
            const maxValue = Math.max(...Array.from(chartBars).map(bar => parseInt(bar.dataset.value) || 0));
            
            chartBars.forEach(bar => {
                const value = parseInt(bar.dataset.value) || 0;
                const height = maxValue > 0 ? (value / maxValue * 100) : 0;
                bar.style.height = height + '%';
            });
        }
        
        // 详情切换
        document.querySelectorAll('.toggle-details').forEach(button => {
            button.addEventListener('click', () => {
                const index = button.dataset.index;
                const detailRow = document.getElementById('details-' + index);
                
                if (detailRow.style.display === 'table-row') {
                    detailRow.style.display = 'none';
                    button.textContent = '详情';
                } else {
                    // 先关闭所有其他详情
                    document.querySelectorAll('.detail-row').forEach(row => {
                        row.style.display = 'none';
                    });
                    document.querySelectorAll('.toggle-details').forEach(btn => {
                        btn.textContent = '详情';
                    });
                    
                    // 打开当前详情
                    detailRow.style.display = 'table-row';
                    button.textContent = '关闭';
                }
            });
        });
        
        // 折叠/展开区域
        document.querySelectorAll('.collapsible').forEach(header => {
            header.addEventListener('click', () => {
                const section = header.parentElement;
                section.classList.toggle('collapsed');
            });
        });
        
        // 端口过滤
        document.querySelectorAll('.filter-btn').forEach(button => {
            button.addEventListener('click', () => {
                // 取消所有按钮激活状态
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                
                // 激活当前按钮
                button.classList.add('active');
                
                // 获取过滤器类型
                const filter = button.dataset.filter;
                
                // 过滤表格行
                document.querySelectorAll('.port-row').forEach(row => {
                    if (filter === 'all' || row.dataset.state === filter) {
                        row.classList.remove('hidden');
                    } else {
                        row.classList.add('hidden');
                        
                        // 隐藏相关的详情行
                        const index = row.querySelector('.toggle-details')?.dataset.index;
                        if (index) {
                            const detailRow = document.getElementById('details-' + index);
                            if (detailRow) {
                                detailRow.style.display = 'none';
                            }
                        }
                    }
                });
            });
        });
        
        // 页面加载完成后初始化
        window.addEventListener('load', () => {
            initCharts();
        });
    </script>
</body>
</html>
`

	// 创建自定义函数
	funcMap := template.FuncMap{
		"now": func() string {
			return time.Now().Format("2006-01-02 15:04:05")
		},
		"inc": func(i int) int {
			return i + 1
		},
		"splitBanner": func(s string) []string {
			// 处理空字符串
			if s == "" {
				return []string{}
			}
			// 分割Banner为行
			lines := strings.Split(s, "\n")
			// 过滤空行
			var result []string
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					// 处理控制字符
					escapedLine := strings.Map(func(r rune) rune {
						if r < 32 && r != '\t' && r != '\n' && r != '\r' {
							return '.'
						}
						return r
					}, line)
					result = append(result, escapedLine)
				}
			}
			return result
		},
		"highlightHTML": func(line string) template.HTML {
			// 定义高亮规则
			patterns := []struct {
				regex   *regexp.Regexp
				replace string
			}{
				// 版本号匹配
				{regexp.MustCompile(`([0-9]+\.[0-9]+(\.[0-9]+)(\.[0-9]+)?)`),
					`<span class="version-highlight">$1</span>`},
				// 服务器/产品名称匹配
				{regexp.MustCompile(`(Apache|Nginx|IIS|lighttpd|OpenSSH|Sendmail|Postfix|Exim|Dovecot|MySQL|MariaDB|PostgreSQL|MongoDB|Redis|Memcached)`),
					`<span class="service-highlight">$1</span>`},
				// 操作系统匹配
				{regexp.MustCompile(`(Ubuntu|Debian|CentOS|Fedora|Red\s*Hat|RHEL|Windows|FreeBSD|OpenBSD|NetBSD|macOS|Darwin)`),
					`<span class="os-highlight">$1</span>`},
				// 协议匹配
				{regexp.MustCompile(`(HTTP|HTTPS|FTP|SFTP|SSH|SMTP|POP3|IMAP|DNS|DHCP|SNMP|SMB|CIFS|RDP|Telnet|IRC)`),
					`<span class="protocol-highlight">$1</span>`},
			}

			// 应用高亮
			for _, pattern := range patterns {
				line = pattern.regex.ReplaceAllString(line, pattern.replace)
			}

			return template.HTML(line)
		},
	}

	report := NewScanReport(o.opts, results)

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %v", err)
	}

	return tmpl.Execute(o.opts.Writer, report)
}
