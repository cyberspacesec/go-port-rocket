package scanner

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// 输出格式常量
const (
	OutputFormatText = "text"
	OutputFormatJSON = "json"
	OutputFormatXML  = "xml"
	OutputFormatCSV  = "csv"
)

// ScanSummary 扫描摘要信息
type ScanSummary struct {
	Target        string        // 目标
	StartTime     time.Time     // 开始时间
	EndTime       time.Time     // 结束时间
	Duration      time.Duration // 持续时间
	TotalPorts    int           // 总端口数
	OpenPorts     int           // 开放端口数
	ClosedPorts   int           // 关闭端口数
	FilteredPorts int           // 被过滤端口数
}

// OutputOptions 输出选项
type OutputOptions struct {
	Format     string // 输出格式: text, json, xml, csv
	OutputFile string // 输出文件路径
	Verbose    bool   // 是否输出详细信息
}

// PortScanOutput 端口扫描输出数据
type PortScanOutput struct {
	Summary         ScanSummary   `json:"summary" xml:"summary"`
	OpenPorts       []PortInfo    `json:"open_ports" xml:"open_ports>port"`
	ClosedPorts     []PortInfo    `json:"closed_ports,omitempty" xml:"closed_ports>port,omitempty"`
	FilteredPorts   []PortInfo    `json:"filtered_ports,omitempty" xml:"filtered_ports>port,omitempty"`
	HostDiscovery   []HostStatus  `json:"host_discovery,omitempty" xml:"host_discovery>host,omitempty"`
	ServiceVersions []ServiceInfo `json:"service_versions,omitempty" xml:"service_versions>service,omitempty"`
	OSDetection     []OSInfo      `json:"os_detection,omitempty" xml:"os_detection>os,omitempty"`
}

// PortInfo 端口信息
type PortInfo struct {
	Port        int    `json:"port" xml:"number,attr"`
	Protocol    string `json:"protocol" xml:"protocol,attr"`
	State       string `json:"state" xml:"state"`
	ServiceName string `json:"service,omitempty" xml:"service,omitempty"`
	Reason      string `json:"reason,omitempty" xml:"reason,omitempty"`
}

// OSInfo OS检测信息
type OSInfo struct {
	Name       string      `json:"name" xml:"name"`
	Family     string      `json:"family,omitempty" xml:"family,omitempty"`
	Version    string      `json:"version,omitempty" xml:"version,omitempty"`
	Confidence float64     `json:"confidence" xml:"confidence"`
	Metadata   MetadataMap `json:"metadata,omitempty" xml:"metadata,omitempty"`
}

// MetadataMap 用于XML兼容的元数据映射
type MetadataMap struct {
	Items []MetadataItem `json:"items" xml:"item"`
}

// MetadataItem 元数据项
type MetadataItem struct {
	Key   string `json:"key" xml:"key,attr"`
	Value string `json:"value" xml:"value"`
}

// SaveScanResult 保存扫描结果到文件
func SaveScanResult(result *PortScanOutput, options *OutputOptions) error {
	if options == nil {
		options = &OutputOptions{
			Format:     OutputFormatText,
			OutputFile: "",
			Verbose:    false,
		}
	}

	// 如果没有指定输出文件，则输出到标准输出
	var output *os.File
	var err error
	if options.OutputFile == "" {
		output = os.Stdout
	} else {
		output, err = os.Create(options.OutputFile)
		if err != nil {
			return fmt.Errorf("创建输出文件失败: %v", err)
		}
		defer output.Close()
	}

	// 根据格式输出结果
	switch strings.ToLower(options.Format) {
	case OutputFormatJSON:
		return outputJSON(result, output)
	case OutputFormatXML:
		return outputXML(result, output)
	case OutputFormatCSV:
		return outputCSV(result, output)
	case OutputFormatText:
		fallthrough
	default:
		return outputText(result, output, options.Verbose)
	}
}

// outputJSON 输出JSON格式
func outputJSON(result *PortScanOutput, output *os.File) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputXML 输出XML格式
func outputXML(result *PortScanOutput, output *os.File) error {
	fmt.Fprintln(output, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintln(output, `<scan_result>`)
	encoder := xml.NewEncoder(output)
	encoder.Indent("  ", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	fmt.Fprintln(output, `</scan_result>`)
	return nil
}

// outputCSV 输出CSV格式
func outputCSV(result *PortScanOutput, output *os.File) error {
	writer := csv.NewWriter(output)
	defer writer.Flush()

	// 写入标题
	header := []string{"端口", "协议", "状态", "服务", "原因"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// 写入开放端口
	for _, port := range result.OpenPorts {
		record := []string{
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			port.State,
			port.ServiceName,
			port.Reason,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	// 如果需要，写入关闭和被过滤的端口
	if len(result.ClosedPorts) > 0 {
		for _, port := range result.ClosedPorts {
			record := []string{
				fmt.Sprintf("%d", port.Port),
				port.Protocol,
				port.State,
				port.ServiceName,
				port.Reason,
			}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}

	if len(result.FilteredPorts) > 0 {
		for _, port := range result.FilteredPorts {
			record := []string{
				fmt.Sprintf("%d", port.Port),
				port.Protocol,
				port.State,
				port.ServiceName,
				port.Reason,
			}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}

	return nil
}

// outputText 输出文本格式
func outputText(result *PortScanOutput, output *os.File, verbose bool) error {
	// 定义颜色代码
	colorReset := "\033[0m"
	colorBold := "\033[1m"
	colorBlue := "\033[34m"
	colorCyan := "\033[36m"
	colorGreen := "\033[32m"
	colorYellow := "\033[33m"
	colorMagenta := "\033[35m"
	colorBrightCyan := "\033[96m"
	colorBrightYellow := "\033[93m"

	// 添加颜色标签函数
	header := func(text string) string { return colorBlue + colorBold + text + colorReset }
	title := func(text string) string { return colorCyan + colorBold + text + colorReset }
	highlight := func(text string) string { return colorMagenta + colorBold + text + colorReset }
	info := func(text string) string { return colorBrightCyan + text + colorReset }
	number := func(text string) string { return colorBrightYellow + text + colorReset }
	success := func(text string) string { return colorGreen + text + colorReset }
	warning := func(text string) string { return colorYellow + colorBold + text + colorReset }

	// 写入报告标题
	fmt.Fprintf(output, "\n%s\n", header("╭─────────────────────────────────────────────────────╮"))
	fmt.Fprintf(output, "%s\n", header("│               Go-Port-Rocket 扫描报告                │"))
	fmt.Fprintf(output, "%s\n\n", header("╰─────────────────────────────────────────────────────╯"))

	// 写入扫描基本信息
	fmt.Fprintf(output, "%s %s\n", title("●  扫描目标:"), highlight(result.Summary.Target))
	fmt.Fprintf(output, "%s %s\n", title("●  开始时间:"), result.Summary.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(output, "%s %s\n", title("●  结束时间:"), result.Summary.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(output, "%s %.2f %s\n\n", title("●  扫描耗时:"), result.Summary.Duration.Seconds(), "秒")

	// 开放端口结果
	fmt.Fprintf(output, "%s\n", header("╭─────────────────────────────────────────────────────╮"))
	fmt.Fprintf(output, "%s\n", header("│                    开放端口结果                     │"))
	fmt.Fprintf(output, "%s\n", header("╰─────────────────────────────────────────────────────╯"))

	if len(result.OpenPorts) == 0 {
		fmt.Fprintf(output, "\n%s\n\n", warning("未发现开放端口"))
	} else {
		// 使用表格格式显示端口详情
		fmt.Fprintf(output, "\n%-15s %-10s %-30s\n",
			title("端口"), title("状态"), title("服务"))
		fmt.Fprintf(output, "%s\n", strings.Repeat("─", 60))

		for _, port := range result.OpenPorts {
			// 服务信息
			svcInfo := port.ServiceName

			fmt.Fprintf(output, "%-15s %-10s %-30s\n",
				highlight(fmt.Sprintf("%d/%s", port.Port, port.Protocol)),
				success("开放"),
				info(svcInfo))
		}
		fmt.Fprintln(output)
	}

	// 服务版本信息
	if len(result.ServiceVersions) > 0 {
		fmt.Fprintf(output, "%s\n", header("╭─────────────────────────────────────────────────────╮"))
		fmt.Fprintf(output, "%s\n", header("│                    服务版本信息                     │"))
		fmt.Fprintf(output, "%s\n", header("╰─────────────────────────────────────────────────────╯"))

		fmt.Fprintf(output, "\n%-6s %-12s %-15s %-20s %s\n",
			title("端口"), title("服务"), title("产品"), title("版本"), title("额外信息"))
		fmt.Fprintf(output, "%s\n", strings.Repeat("─", 80))

		for _, svc := range result.ServiceVersions {
			fmt.Fprintf(output, "%-6s %-12s %-15s %-20s %s\n",
				number(fmt.Sprintf("%d", svc.Port)),
				info(svc.Name),
				info(svc.Product),
				info(svc.Version),
				info(svc.ExtraInfo))

			// 如果存在Banner信息，则显示
			if svc.FullBanner != "" {
				fmt.Fprintf(output, "  %s\n", title("● Banner 信息:"))

				// 处理多行Banner
				bannerLines := strings.Split(svc.FullBanner, "\n")

				// 计算Banner的行数，以决定显示方式
				validLines := 0
				for _, line := range bannerLines {
					if strings.TrimSpace(line) != "" {
						validLines++
					}
				}

				// Banner内容框
				if validLines > 0 {
					fmt.Fprintf(output, "    %s\n", strings.Repeat("─", 70))
				}

				for i, line := range bannerLines {
					// 过滤掉空行和只包含控制字符的行
					if strings.TrimSpace(line) == "" {
						continue
					}

					// 对可能的控制字符进行转义处理，同时保留彩色输出功能
					escapedLine := strings.Map(func(r rune) rune {
						if r < 32 && r != '\t' && r != '\n' && r != '\r' {
							return '.'
						}
						return r
					}, line)

					// 对特定关键信息进行高亮显示
					// 如版本号、产品名称、协议信息等
					highlightedLine := highlightBannerKeywords(escapedLine)

					fmt.Fprintf(output, "    %s %s\n",
						number(fmt.Sprintf("%2d│", i+1)),
						info(highlightedLine))
				}

				if validLines > 0 {
					fmt.Fprintf(output, "    %s\n", strings.Repeat("─", 70))
				}

				fmt.Fprintln(output)
			}
		}
		fmt.Fprintln(output)
	}

	// 操作系统信息
	if len(result.OSDetection) > 0 {
		fmt.Fprintf(output, "%s\n", header("╭─────────────────────────────────────────────────────╮"))
		fmt.Fprintf(output, "%s\n", header("│                 操作系统检测结果                    │"))
		fmt.Fprintf(output, "%s\n", header("╰─────────────────────────────────────────────────────╯"))

		fmt.Fprintf(output, "\n%-15s %-15s %-15s %-10s\n",
			title("操作系统"), title("系统家族"), title("版本"), title("置信度"))
		fmt.Fprintf(output, "%s\n", strings.Repeat("─", 60))

		for _, os := range result.OSDetection {
			fmt.Fprintf(output, "%-15s %-15s %-15s %-10s\n",
				highlight(os.Name),
				info(os.Family),
				info(os.Version),
				number(fmt.Sprintf("%.2f%%", os.Confidence)))
		}
		fmt.Fprintln(output)
	}

	// 统计信息
	fmt.Fprintf(output, "%s\n", header("╭─────────────────────────────────────────────────────╮"))
	fmt.Fprintf(output, "%s\n", header("│                    扫描统计信息                     │"))
	fmt.Fprintf(output, "%s\n\n", header("╰─────────────────────────────────────────────────────╯"))

	fmt.Fprintf(output, "%s %s\n", title("●  总端口数:"), number(fmt.Sprintf("%d", result.Summary.TotalPorts)))
	fmt.Fprintf(output, "%s %s\n", title("●  开放端口:"), number(fmt.Sprintf("%d", result.Summary.OpenPorts)))
	fmt.Fprintf(output, "%s %s\n", title("●  关闭端口:"), number(fmt.Sprintf("%d", result.Summary.ClosedPorts)))
	fmt.Fprintf(output, "%s %s\n\n", title("●  过滤端口:"), number(fmt.Sprintf("%d", result.Summary.FilteredPorts)))

	return nil
}

// CreateScanOutputFromResults 从扫描结果创建输出数据
func CreateScanOutputFromResults(target string, tcpResults []ScanResult, udpResults []UDPScanResult,
	serviceInfo map[int]*ServiceInfo, hostStatus []HostStatus,
	startTime time.Time, endTime time.Time) *PortScanOutput {

	output := &PortScanOutput{
		Summary: ScanSummary{
			Target:    target,
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  endTime.Sub(startTime),
		},
		OpenPorts:     make([]PortInfo, 0),
		ClosedPorts:   make([]PortInfo, 0),
		FilteredPorts: make([]PortInfo, 0),
		OSDetection:   make([]OSInfo, 0),
	}

	// 处理TCP扫描结果
	totalTCP := len(tcpResults)
	openTCP := 0
	closedTCP := 0
	filteredTCP := 0
	for _, result := range tcpResults {
		portInfo := PortInfo{
			Port:        result.Port,
			Protocol:    "tcp",
			ServiceName: result.ServiceName,
		}

		switch result.State {
		case PortStateOpen:
			portInfo.State = "open"
			portInfo.Reason = "syn-ack"
			output.OpenPorts = append(output.OpenPorts, portInfo)
			openTCP++
		case PortStateClosed:
			portInfo.State = "closed"
			portInfo.Reason = "reset"
			output.ClosedPorts = append(output.ClosedPorts, portInfo)
			closedTCP++
		case PortStateFiltered:
			portInfo.State = "filtered"
			portInfo.Reason = "no-response"
			output.FilteredPorts = append(output.FilteredPorts, portInfo)
			filteredTCP++
		}
	}

	// 处理UDP扫描结果
	totalUDP := len(udpResults)
	openUDP := 0
	filteredUDP := 0
	for _, result := range udpResults {
		portInfo := PortInfo{
			Port:     result.Port,
			Protocol: "udp",
			Reason:   result.Reason,
		}

		switch result.State {
		case "open":
			portInfo.State = "open"
			output.OpenPorts = append(output.OpenPorts, portInfo)
			openUDP++
		case "filtered":
			portInfo.State = "filtered"
			output.FilteredPorts = append(output.FilteredPorts, portInfo)
			filteredUDP++
		case "open|filtered":
			portInfo.State = "open|filtered"
			output.FilteredPorts = append(output.FilteredPorts, portInfo)
			filteredUDP++
		default:
			portInfo.State = "closed"
			output.ClosedPorts = append(output.ClosedPorts, portInfo)
		}
	}

	// 添加服务版本信息
	if serviceInfo != nil && len(serviceInfo) > 0 {
		for port, info := range serviceInfo {
			if info == nil {
				continue
			}
			// 设置端口号
			info.Port = port
			output.ServiceVersions = append(output.ServiceVersions, *info)
		}
	}

	// 添加主机状态信息
	if hostStatus != nil && len(hostStatus) > 0 {
		output.HostDiscovery = hostStatus
	}

	// 添加OS检测结果
	seenOSInfo := make(map[string]bool)
	for _, result := range tcpResults {
		if result.OS != nil && !seenOSInfo[result.OS.Name] {
			seenOSInfo[result.OS.Name] = true

			// 提取元数据
			var items []MetadataItem
			if result.OS.Metadata != nil {
				for k, v := range result.OS.Metadata {
					items = append(items, MetadataItem{
						Key:   k,
						Value: fmt.Sprintf("%v", v),
					})
				}
			}

			osInfo := OSInfo{
				Name:       result.OS.Name,
				Family:     result.OS.Family,
				Version:    result.OS.Version,
				Confidence: result.OS.Confidence,
				Metadata: MetadataMap{
					Items: items,
				},
			}
			output.OSDetection = append(output.OSDetection, osInfo)
		}
	}

	// 更新统计信息
	output.Summary.TotalPorts = totalTCP + totalUDP
	output.Summary.OpenPorts = openTCP + openUDP
	output.Summary.ClosedPorts = closedTCP + (totalUDP - openUDP - filteredUDP)
	output.Summary.FilteredPorts = filteredTCP + filteredUDP

	return output
}

// AddPortToServiceInfo 在ServiceInfo结构中添加端口字段
type ServiceInfoWithPort struct {
	ServiceInfo
	Port int
}

// highlightBannerKeywords 对Banner中的关键词进行高亮
func highlightBannerKeywords(line string) string {
	// 定义颜色代码
	colorReset := "\033[0m"
	colorYellow := "\033[33m"
	colorGreen := "\033[32m"
	colorRed := "\033[31m"
	colorMagenta := "\033[35m"

	// 定义需要高亮的关键词和对应颜色
	patterns := []struct {
		regex *regexp.Regexp
		color string
	}{
		// 版本号匹配
		{regexp.MustCompile(`[vV]ersion:?\s*([0-9]+\.[0-9]+(\.[0-9]+)?)`), colorGreen},
		{regexp.MustCompile(`([0-9]+\.[0-9]+(\.[0-9]+)(\.[0-9]+)?)`), colorGreen},
		// 服务器/产品名称匹配
		{regexp.MustCompile(`(Apache|Nginx|IIS|lighttpd|OpenSSH|Sendmail|Postfix|Exim|Dovecot|MySQL|MariaDB|PostgreSQL|MongoDB|Redis|Memcached)`), colorMagenta},
		// 操作系统匹配
		{regexp.MustCompile(`(Ubuntu|Debian|CentOS|Fedora|Red\s*Hat|RHEL|Windows|FreeBSD|OpenBSD|NetBSD|macOS|Darwin)`), colorYellow},
		// 认证/安全信息匹配
		{regexp.MustCompile(`(Authentication|Login|Password|Credentials|SSL|TLS|Encryption|Cipher)`), colorRed},
		// 协议匹配
		{regexp.MustCompile(`(HTTP|HTTPS|FTP|SFTP|SSH|SMTP|POP3|IMAP|DNS|DHCP|SNMP|SMB|CIFS|RDP|Telnet|IRC)`), colorMagenta},
	}

	result := line

	// 逐个应用高亮模式
	for _, pattern := range patterns {
		// 查找所有匹配
		matches := pattern.regex.FindAllStringSubmatchIndex(result, -1)

		// 如果有匹配，从后向前替换，避免位置偏移问题
		if len(matches) > 0 {
			var newResult string
			lastEnd := len(result)

			// 从后向前处理
			for i := len(matches) - 1; i >= 0; i-- {
				match := matches[i]
				if len(match) >= 2 {
					start, end := match[0], match[1]

					// 高亮处理
					newResult = pattern.color + result[start:end] + colorReset + result[end:lastEnd] + newResult
					lastEnd = start
				}
			}

			// 添加最前面的未匹配部分
			if lastEnd > 0 {
				newResult = result[:lastEnd] + newResult
			}

			result = newResult
		}
	}

	return result
}
