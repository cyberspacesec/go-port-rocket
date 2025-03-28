package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"
)

// ConvertScannerResultToOutput 将scanner包的扫描结果转换为HTML
func ConvertScannerResultToOutput(results []scanner.ScanResult, outputFile string, target string, scanType string, startTime, endTime time.Time) error {
	// 创建HTML输出文件
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建HTML输出文件失败: %v", err)
	}
	defer file.Close()

	// 计算执行时间，如果非常短（不到100毫秒）可能是因为权限问题导致程序提前退出
	executionTime := endTime.Sub(startTime)
	possiblePrematureExit := executionTime < 100*time.Millisecond

	// 检查是否为需要root权限的扫描类型
	needsRoot := false
	rootErrorOccurred := false

	// 检查扫描类型是否需要root权限
	switch strings.ToLower(scanType) {
	case "syn", "fin", "null", "xmas", "ack", "udp":
		needsRoot = true
	}

	// 检查扫描中是否有异常状态的端口（有可能是由于权限问题导致）
	hasResults := len(results) > 0
	allFiltered := hasResults
	allUnknown := hasResults

	for _, result := range results {
		// 如果有任何一个端口不是过滤状态，就说明不全是过滤
		if result.State != scanner.PortStateFiltered {
			allFiltered = false
		}

		// 如果有任何一个端口不是未知状态，就说明不全是未知
		if result.State != scanner.PortStateUnknown {
			allUnknown = false
		}

		// 如果有元数据，检查是否包含权限错误信息
		if result.Metadata != nil {
			if errMsg, ok := result.Metadata["error"]; ok {
				if errStr, isString := errMsg.(string); isString &&
					(strings.Contains(strings.ToLower(errStr), "permission") ||
						strings.Contains(strings.ToLower(errStr), "権限") ||
						strings.Contains(strings.ToLower(errStr), "权限")) {
					rootErrorOccurred = true
					break
				}
			}
		}
	}

	// 如果是需要root权限的扫描类型，并且程序可能提前退出，则认为是权限错误
	if needsRoot && possiblePrematureExit {
		rootErrorOccurred = true
	}

	// 如果需要root权限的扫描类型且所有端口都是过滤状态或未知状态（且有扫描结果），很可能是权限问题
	if needsRoot && hasResults && (allFiltered || allUnknown) {
		rootErrorOccurred = true
	}

	// 统计信息
	openCount := 0
	closedCount := 0
	filteredCount := 0

	// 计算统计数据
	for _, result := range results {
		switch result.State {
		case scanner.PortStateOpen:
			openCount++
		case scanner.PortStateClosed:
			closedCount++
		case scanner.PortStateFiltered:
			filteredCount++
		}
	}

	// 输出HTML内容
	htmlTemplate := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Go-Port-Rocket 扫描报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0"></script>
    <script src="https://cdn.jsdelivr.net/npm/moment@2.29.1/moment.min.js"></script>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        h1 {
            margin: 0;
            font-size: 24px;
        }
        .info-section {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .info-item {
            margin-bottom: 10px;
        }
        .info-label {
            font-weight: bold;
            color: #2c3e50;
            display: inline-block;
            width: 120px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #2c3e50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .open {
            color: #27ae60;
            font-weight: bold;
        }
        .closed {
            color: #e74c3c;
        }
        .filtered {
            color: #f39c12;
        }
        .banner {
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #f9f9f9;
            padding: 8px;
            border-left: 3px solid #ddd;
            margin: 10px 0;
            font-size: 14px;
            overflow-x: auto;
        }
        .banner-explanation {
            color: #2c3e50;
            background-color: #fffde7;
            border-left: 3px solid #f1c40f;
            padding: 12px;
            margin-top: 8px;
            font-size: 14px;
            line-height: 1.5;
            border-radius: 4px;
        }
        .hex-data {
            color: #e74c3c;
            font-weight: bold;
        }
        .stats-section {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            margin: 0 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }
        .open-stat .stat-number {
            color: #27ae60;
        }
        .closed-stat .stat-number {
            color: #e74c3c;
        }
        .filtered-stat .stat-number {
            color: #f39c12;
        }
        footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #7f8c8d;
        }
        /* 端口筛选器样式 */
        .filter-container {
            display: flex;
            margin-bottom: 15px;
            align-items: center;
        }
        .filter-label {
            margin-right: 10px;
            font-weight: bold;
            color: #2c3e50;
        }
        .filter-btn {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            padding: 8px 12px;
            margin-right: 5px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .filter-btn:hover {
            background-color: #e9e9e9;
        }
        .filter-btn.active {
            background-color: #2c3e50;
            color: white;
            border-color: #2c3e50;
        }
        .filter-btn.open-btn.active {
            background-color: #27ae60;
            border-color: #27ae60;
        }
        .filter-btn.closed-btn.active {
            background-color: #e74c3c;
            border-color: #e74c3c;
        }
        .filter-btn.filtered-btn.active {
            background-color: #f39c12;
            border-color: #f39c12;
        }
        .port-row {
            display: table-row;
        }
        .port-row.hidden {
            display: none;
        }
        .search-container {
            margin-left: auto;
        }
        .search-input {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 150px;
        }
        .error-section {
            border-left: 4px solid #e74c3c;
            background-color: #fdf7f7;
        }
        .warning-section {
            border-left: 4px solid #f39c12;
            background-color: #fef9e7;
        }
        .error-message, .warning-message {
            padding: 10px;
            line-height: 1.6;
        }
        .solution-box {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }
        .solution-box h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .solution-box ul {
            padding-left: 20px;
        }
        pre {
            background-color: #f1f1f1;
            padding: 8px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 5px 0;
            font-family: monospace;
        }
        .note {
            font-style: italic;
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 15px;
        }
        /* 数据可视化样式 */
        .charts-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        .chart-container {
            flex: 1;
            min-width: 300px;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .chart-title {
            font-size: 18px;
            color: #2c3e50;
            margin-bottom: 15px;
            text-align: center;
            font-weight: bold;
        }
        .heatmap-container {
            width: 100%;
            overflow-x: auto;
            margin-top: 20px;
        }
        .port-cell {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin: 1px;
            border-radius: 2px;
            text-align: center;
            font-size: 10px;
            line-height: 20px;
            color: white;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .port-cell:hover {
            transform: scale(1.2);
            z-index: 10;
        }
        .port-cell.open {
            background-color: #27ae60;
        }
        .port-cell.closed {
            background-color: #e74c3c;
        }
        .port-cell.filtered {
            background-color: #f39c12;
        }
        .port-legend {
            display: flex;
            justify-content: center;
            margin-top: 10px;
            gap: 15px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            font-size: 12px;
        }
        .legend-color {
            width: 15px;
            height: 15px;
            border-radius: 2px;
            margin-right: 5px;
        }
        .timeline-controls {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 15px;
            gap: 10px;
        }
        .scan-selector {
            padding: 5px;
            border-radius: 4px;
            border: 1px solid #ddd;
        }
        .tab-container {
            margin-top: 20px;
        }
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
        }
        .tab {
            padding: 10px 15px;
            cursor: pointer;
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-bottom: none;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
        }
        .tab.active {
            background-color: white;
            border-bottom: 1px solid white;
            margin-bottom: -1px;
            font-weight: bold;
        }
        .tab-content {
            display: none;
            padding: 15px;
            background-color: white;
            border: 1px solid #ddd;
            border-top: none;
        }
        .tab-content.active {
            display: block;
        }
        .tooltip-container {
            position: absolute;
            background-color: rgba(0,0,0,0.8);
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 100;
            pointer-events: none;
            display: none;
        }
        
        /* 协议解析器样式 */
        .protocol-analyzer {
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        .analyzer-header {
            background-color: #2c3e50;
            color: white;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .analyzer-header h2 {
            margin: 0;
            font-size: 18px;
        }
        .tabs {
            display: flex;
        }
        .tab {
            padding: 8px 15px;
            background-color: rgba(255,255,255,0.1);
            cursor: pointer;
            margin-left: 5px;
            border-radius: 3px;
            transition: background-color 0.2s;
        }
        .tab.active {
            background-color: rgba(255,255,255,0.3);
            font-weight: bold;
        }
        .analyzer-content {
            display: none;
            padding: 15px;
        }
        .analyzer-content.active {
            display: block;
        }
        .protocol-fields {
            font-family: monospace;
        }
        .protocol-field {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 4px;
            background-color: #f8f9fa;
            transition: background-color 0.2s;
            cursor: pointer;
        }
        .protocol-field:hover {
            background-color: #eaecef;
        }
        .field-name {
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }
        .field-value {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }
        .field-description {
            margin-top: 5px;
            color: #666;
            font-size: 13px;
            font-family: Arial, sans-serif;
        }
        .hex-tooltip {
            position: absolute;
            background-color: rgba(0,0,0,0.8);
            color: white;
            padding: 8px;
            border-radius: 4px;
            font-size: 12px;
            max-width: 300px;
            display: none;
            z-index: 1000;
        }
        /* 十六进制数据不同类型的颜色 */
        .hex-type-header { background-color: #3498db; }
        .hex-type-data { background-color: #2ecc71; }
        .hex-type-timestamp { background-color: #9b59b6; }
        .hex-type-identifier { background-color: #f39c12; }
        .hex-type-payload { background-color: #e74c3c; }
        .hex-viewer {
            padding: 15px;
            font-family: monospace;
            overflow-x: auto;
            white-space: nowrap;
            position: relative;
            line-height: 2;
        }
        .hex-byte {
            display: inline-block;
            margin: 0 2px;
            padding: 2px 4px;
            border-radius: 3px;
            cursor: pointer;
            position: relative;
        }
        .hex-byte:hover {
            background-color: #f1f1f1;
        }
        .hex-field {
            border: 1px solid transparent;
            border-radius: 3px;
        }
        .field-header {
            background-color: #3498db;
            color: white;
        }
        .field-data {
            background-color: #2ecc71;
            color: white;
        }
        .field-checksum {
            background-color: #e74c3c;
            color: white;
        }
        .field-options {
            background-color: #f39c12;
            color: white;
        }
        .field-payload {
            background-color: #9b59b6;
            color: white;
        }
        .protocol-details {
            padding: 15px;
            border-top: 1px solid #eee;
        }
        .protocol-field {
            margin-bottom: 10px;
            padding: 8px;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .protocol-field:hover {
            background-color: #f9f9f9;
        }
        .field-name {
            font-weight: bold;
            margin-right: 10px;
            color: #2c3e50;
        }
        .field-value {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 2px 5px;
            border-radius: 3px;
        }
        .field-description {
            margin-top: 5px;
            color: #7f8c8d;
            font-size: 13px;
        }
        .analyzer-tabs {
            display: flex;
            background-color: #f8f9fa;
            border-bottom: 1px solid #eee;
        }
        .analyzer-tab {
            padding: 10px 15px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        .analyzer-tab.active {
            border-bottom: 2px solid #3498db;
            color: #3498db;
            font-weight: bold;
        }
        .analyzer-content {
            display: none;
            padding: 15px;
        }
        .analyzer-content.active {
            display: block;
        }
        .hex-tooltip {
            position: absolute;
            background-color: rgba(44, 62, 80, 0.9);
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 100;
            max-width: 300px;
            pointer-events: none;
            display: none;
            word-wrap: break-word;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        .protocol-accordion {
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        .accordion-header {
            padding: 10px 15px;
            background-color: #f8f9fa;
            cursor: pointer;
            border-bottom: 1px solid #ddd;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .accordion-content {
            padding: 15px;
            display: none;
        }
        .accordion-header.active {
            background-color: #e9ecef;
        }
        .accordion-header.active + .accordion-content {
            display: block;
        }
        .accordion-icon {
            transition: transform 0.3s;
        }
        .accordion-header.active .accordion-icon {
            transform: rotate(180deg);
        }
        .bytes-row {
            display: flex;
            margin-bottom: 8px;
        }
        .offset {
            width: 60px;
            color: #7f8c8d;
        }
        .hex-bytes {
            flex: 2;
        }
        .ascii-bytes {
            flex: 1;
            margin-left: 15px;
            color: #7f8c8d;
        }
        .ascii-byte {
            display: inline-block;
            width: 8px;
        }
        .field-highlight {
            background-color: #fffde7;
            transition: background-color 0.3s;
        }
    </style>
</head>
<body>
    <header>
        <h1>Go-Port-Rocket 端口扫描报告</h1>
    </header>

    <div class="info-section">
        <div class="info-item">
            <span class="info-label">扫描目标:</span>
            <span>` + target + `</span>
        </div>
        <div class="info-item">
            <span class="info-label">扫描类型:</span>
            <span>` + scanType + `</span>
        </div>
        <div class="info-item">
            <span class="info-label">开始时间:</span>
            <span>` + startTime.Format("2006-01-02 15:04:05") + `</span>
        </div>
        <div class="info-item">
            <span class="info-label">结束时间:</span>
            <span>` + endTime.Format("2006-01-02 15:04:05") + `</span>
        </div>
        <div class="info-item">
            <span class="info-label">扫描耗时:</span>
            <span>` + fmt.Sprintf("%.2f 秒", endTime.Sub(startTime).Seconds()) + `</span>
        </div>
    </div>`

	// 如果需要root权限的扫描类型发生了权限错误，添加错误提示框
	if needsRoot && rootErrorOccurred {
		htmlTemplate += `
    <div class="info-section error-section">
        <h2>⚠️ 扫描权限错误</h2>
        <div class="error-message">
            <p><strong>警告:</strong> 检测到可能的权限不足问题</p>
            <p>您选择的扫描类型 <strong>` + scanType + `</strong> 需要管理员/root权限才能执行。</p>
            <p>以下情况可能表明权限不足：</p>
            <ul>
                <li>程序异常退出，显示 "root privileges required" 错误</li>
                <li>所有端口显示为"过滤"或"未知"状态</li>
                <li>扫描结果异常或不完整</li>
                <li>扫描速度异常缓慢</li>
            </ul>
            <div class="solution-box">
                <h3>解决方案:</h3>
                <ul>
                    <li>在Linux/macOS系统上，使用 <code>sudo</code> 命令运行扫描: <pre>sudo go-port-rocket scan -t ` + target + ` -p ... -s ` + scanType + `</pre></li>
                    <li>在Windows系统上，以管理员身份运行命令提示符或PowerShell</li>
                    <li>或者使用不需要特殊权限的TCP扫描类型: <pre>go-port-rocket scan -t ` + target + ` -p ... -s tcp</pre></li>
                </ul>
            </div>
            <p class="note">注意: 某些扫描类型（如SYN, FIN, NULL, XMAS, ACK, UDP）需要直接访问网络接口，因此需要更高的系统权限。如果您无法获得管理员权限，请使用TCP扫描类型代替。</p>
        </div>
    </div>`
	} else if needsRoot {
		// 如果是需要root权限的扫描类型但没有错误发生，添加提示信息
		htmlTemplate += `
    <div class="info-section warning-section">
        <h2>ℹ️ 扫描权限提示</h2>
        <div class="warning-message">
            <p>您选择的扫描类型 <strong>` + scanType + `</strong> 通常需要管理员/root权限才能获得最佳结果。</p>
            <p>如果扫描结果不完整或出现以下情况，请考虑使用管理员权限重新运行扫描：</p>
            <ul>
                <li>程序异常退出，显示 "root privileges required" 错误</li>
                <li>所有端口都显示为过滤状态</li>
                <li>扫描速度异常缓慢</li>
            </ul>
            <div class="solution-box">
                <h3>在没有管理员权限的情况下运行扫描:</h3>
                <p>如果无法获取管理员权限，建议使用TCP扫描类型代替:</p>
                <pre>go-port-rocket scan -t ` + target + ` -p ... -s tcp</pre>
            </div>
        </div>
    </div>`
	}

	htmlTemplate += `
    <div class="info-section">
        <h2>端口扫描结果</h2>
        
        <div class="stats-section">
            <div class="stat-box open-stat">
                <div>开放端口</div>
                <div class="stat-number">` + fmt.Sprintf("%d", openCount) + `</div>
            </div>
            <div class="stat-box closed-stat">
                <div>关闭端口</div>
                <div class="stat-number">` + fmt.Sprintf("%d", closedCount) + `</div>
            </div>
            <div class="stat-box filtered-stat">
                <div>过滤端口</div>
                <div class="stat-number">` + fmt.Sprintf("%d", filteredCount) + `</div>
            </div>
            <div class="stat-box">
                <div>总计端口</div>
                <div class="stat-number">` + fmt.Sprintf("%d", len(results)) + `</div>
            </div>
        </div>
        
        <div class="tab-container">
            <div class="tabs">
                <div class="tab active" onclick="switchTab('overview')">扫描概览</div>
                <div class="tab" onclick="switchTab('distribution')">端口分布</div>
                <div class="tab" onclick="switchTab('timeline')">时间轴对比</div>
            </div>
            
            <div id="overview" class="tab-content active">
                <div class="charts-container">
                    <div class="chart-container">
                        <div class="chart-title">端口状态分布</div>
                        <canvas id="portStatusChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <div class="chart-title">服务类型分布</div>
                        <canvas id="serviceTypeChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div id="distribution" class="tab-content">
                <div class="chart-container">
                    <div class="chart-title">端口分布热图</div>
                    <div class="heatmap-container" id="portHeatmap"></div>
                    <div class="port-legend">
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #27ae60;"></div>
                            <span>开放</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #e74c3c;"></div>
                            <span>关闭</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #f39c12;"></div>
                            <span>过滤</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="timeline" class="tab-content">
                <div class="chart-container">
                    <div class="chart-title">历史扫描对比</div>
                    <p class="note" style="text-align:center;">保存此报告后，未来的扫描将在此处显示历史对比。</p>
                    <div class="timeline-controls">
                        <select class="scan-selector" id="scanSelector" disabled>
                            <option value="current">当前扫描 - ` + startTime.Format("2006-01-02 15:04:05") + `</option>
                        </select>
                        <button class="filter-btn" disabled>加载对比</button>
                    </div>
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="tooltip-container" id="portTooltip"></div>
        
        <div class="filter-container">
            <span class="filter-label">状态筛选:</span>
            <button class="filter-btn all-btn active" onclick="filterPorts('all')">全部</button>
            <button class="filter-btn open-btn" onclick="filterPorts('open')">开放</button>
            <button class="filter-btn closed-btn" onclick="filterPorts('closed')">关闭</button>
            <button class="filter-btn filtered-btn" onclick="filterPorts('filtered')">过滤</button>
            
            <div class="search-container">
                <input type="text" class="search-input" id="portSearch" onkeyup="searchPort()" placeholder="搜索端口...">
            </div>
        </div>
        
        <table id="portTable">
            <thead>
                <tr>
                    <th>端口</th>
                    <th>状态</th>
                    <th>服务</th>
                    <th>版本</th>
                    <th>TTL</th>
                </tr>
            </thead>
            <tbody>`

	// 添加端口信息
	for _, result := range results {
		// 根据端口状态设置CSS类和数据属性
		stateClass := ""
		stateText := ""
		stateAttr := ""

		switch result.State {
		case scanner.PortStateOpen:
			stateClass = "open"
			stateText = "开放"
			stateAttr = "open"
		case scanner.PortStateClosed:
			stateClass = "closed"
			stateText = "关闭"
			stateAttr = "closed"
		case scanner.PortStateFiltered:
			stateClass = "filtered"
			stateText = "过滤"
			stateAttr = "filtered"
		default:
			stateClass = ""
			stateText = string(result.State)
			stateAttr = "unknown"
		}

		// 添加行，注意添加data-state属性用于筛选
		htmlTemplate += fmt.Sprintf(`                <tr class="port-row" data-state="%s" data-port="%d">
                    <td>%d</td>
                    <td class="%s">%s</td>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%d</td>
                </tr>`, stateAttr, result.Port, result.Port, stateClass, stateText, result.ServiceName, result.Version, result.TTL)

		// 如果有Banner，添加banner行
		if result.Banner != "" {
			// 检查Banner是否为十六进制格式（通常是UDP响应）
			bannerDisplay := result.Banner
			bannerExplanation := ""

			// 检测是否是十六进制格式
			if strings.HasPrefix(strings.TrimSpace(result.Banner), "0x") ||
				(len(strings.TrimSpace(result.Banner)) > 0 && isHexString(strings.TrimSpace(result.Banner))) {
				// 增强显示，突出显示十六进制数据
				bannerDisplay = fmt.Sprintf(`<span class="hex-data">%s</span>`, result.Banner)

				// 添加特定服务的解释
				serviceName := strings.ToLower(result.ServiceName)
				if serviceName == "ntp" {
					bannerExplanation = "这是NTP服务的原始响应数据包。NTP(网络时间协议)用于时间同步，响应包含以下信息：" +
						"<ul>" +
						"<li>前2字节(LI, VN, Mode): 包含认证和模式标识</li>" +
						"<li>后续字节: 系统时间戳、参考时间戳、精度和轮询间隔</li>" +
						"</ul>" +
						"红色标记的十六进制数据是原始数据包内容。"
				} else if serviceName == "dns" {
					bannerExplanation = "这是DNS服务的原始响应数据包。DNS查询/响应数据包结构包含：" +
						"<ul>" +
						"<li>包头(前12字节): 包含交易ID、标志、计数器</li>" +
						"<li>查询部分: 包含请求的域名和查询类型</li>" +
						"<li>应答部分: 包含资源记录(RR)信息</li>" +
						"</ul>" +
						"红色标记的十六进制数据是原始数据包内容。"
				} else if serviceName == "snmp" {
					bannerExplanation = "这是SNMP服务的原始响应数据包。SNMP协议用于网络管理，数据包包含：" +
						"<ul>" +
						"<li>版本信息: 指示SNMP版本(v1/v2c/v3)</li>" +
						"<li>社区名: 用于身份验证</li>" +
						"<li>SNMP PDU: 包含操作类型和OID值</li>" +
						"</ul>" +
						"红色标记的十六进制数据是原始数据包内容。"
				} else {
					bannerExplanation = "这是服务的原始二进制响应，以十六进制格式显示。十六进制数据表示网络数据包的原始内容，通常需要特定的协议分析器才能完全解码。红色标记表示这是原始数据。"
				}
			}

			// 输出Banner行
			htmlTemplate += fmt.Sprintf(`
                <tr class="port-row banner-row" data-state="%s" data-port="%d">
                    <td colspan="5">
                        <div class="banner">%s</div>`, stateAttr, result.Port, bannerDisplay)

			// 如果有解释，添加解释
			if bannerExplanation != "" {
				htmlTemplate += fmt.Sprintf(`
                    <div class="banner-explanation">🔍 <strong>数据解析:</strong> %s</div>`, bannerExplanation)
			}

			// 添加协议解析器 - 开始
			if strings.HasPrefix(strings.TrimSpace(result.Banner), "0x") ||
				(len(strings.TrimSpace(result.Banner)) > 0 && isHexString(strings.TrimSpace(result.Banner))) {

				// 获取干净的十六进制字符串(去除0x前缀和空格)
				hexData := strings.TrimSpace(result.Banner)
				if strings.HasPrefix(hexData, "0x") {
					hexData = hexData[2:]
				}
				hexData = strings.Replace(hexData, " ", "", -1)

				htmlTemplate += fmt.Sprintf(`
                <div class="protocol-analyzer" id="analyzer-%d">
                    <div class="analyzer-header">
                        <h2>%s 协议分析 (端口 %d)</h2>
                        <div class="tabs">
                            <div class="tab active" data-tab="parsed-%d">结构化视图</div>
                            <div class="tab" data-tab="raw-%d">原始数据</div>
                        </div>
                    </div>
                    <div class="analyzer-content active" id="analyzer-%d-parsed">
                        <div class="protocol-fields"></div>
                    </div>
                    <div class="analyzer-content" id="analyzer-%d-raw">
                        <pre>%s</pre>
                    </div>
                </div>
                <div class="hex-tooltip" id="hex-tooltip-%d"></div>`,
					result.Port,
					strings.ToUpper(result.ServiceName),
					result.Port,
					result.Port,
					result.Port,
					result.Port,
					hexData,
					result.Port)
			}
			// 协议解析器 - 结束

			htmlTemplate += fmt.Sprintf(`
                    </td>
                </tr>`)
		}
	}

	// 添加页脚
	htmlTemplate += fmt.Sprintf(`
            </tbody>
        </table>
    </div>

    <footer>
        <p>报告生成时间: %s | Go-Port-Rocket 端口扫描工具</p>
    </footer>

    <script>
        // 端口筛选功能
        function filterPorts(state) {
            // 更新按钮状态
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector('.filter-btn.' + state + '-btn').classList.add('active');
            
            // 筛选表格行
            const rows = document.querySelectorAll('.port-row');
            rows.forEach(row => {
                if (state === 'all') {
                    row.classList.remove('hidden');
                } else {
                    if (row.getAttribute('data-state') === state) {
                        row.classList.remove('hidden');
                    } else {
                        row.classList.add('hidden');
                    }
                }
            });
        }
        
        // 端口搜索功能
        function searchPort() {
            const input = document.getElementById('portSearch');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('portTable');
            const rows = table.getElementsByTagName('tr');
            
            // 从索引1开始跳过表头
            for (let i = 1; i < rows.length; i++) {
                const port = rows[i].getAttribute('data-port');
                if (port) {
                    if (port.includes(filter)) {
                        rows[i].style.display = "";
                    } else {
                        rows[i].style.display = "none";
                    }
                }
            }
        }
        
        // 选项卡切换功能
        function switchTab(tabId) {
            // 隐藏所有标签内容
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // 取消所有标签激活状态
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // 激活选中的标签和内容
            document.getElementById(tabId).classList.add('active');
            document.querySelector('.tab[onclick="switchTab(\'' + tabId + '\')"]').classList.add('active');
        }
        
        // 初始化端口状态分布图表
        function initPortStatusChart() {
            const ctx = document.getElementById('portStatusChart').getContext('2d');
            
            const data = {
                labels: ['开放', '关闭', '过滤'],
                datasets: [{
                    data: [`+fmt.Sprintf("%d, %d, %d", openCount, closedCount, filteredCount)+`],
                    backgroundColor: ['#27ae60', '#e74c3c', '#f39c12'],
                    borderWidth: 0
                }]
            };
            
            new Chart(ctx, {
                type: 'pie',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // 初始化服务类型分布图表
        function initServiceTypeChart() {
            const ctx = document.getElementById('serviceTypeChart').getContext('2d');
            
            // 从表格中提取服务信息
            const services = {};
            const rows = document.querySelectorAll('.port-row:not(.banner-row)');
            
            rows.forEach(row => {
                // 仅统计开放端口
                if (row.getAttribute('data-state') === 'open') {
                    const cells = row.getElementsByTagName('td');
                    if (cells.length >= 3) {
                        const service = cells[2].textContent.trim() || 'unknown';
                        services[service] = (services[service] || 0) + 1;
                    }
                }
            });
            
            const serviceLabels = Object.keys(services);
            const serviceData = Object.values(services);
            
            // 生成颜色
            const colors = generateColors(serviceLabels.length);
            
            const data = {
                labels: serviceLabels,
                datasets: [{
                    data: serviceData,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            };
            
            new Chart(ctx, {
                type: 'doughnut',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            display: serviceLabels.length > 0
                        }
                    }
                }
            });
        }
        
        // 初始化端口分布热图
        function initPortHeatmap() {
            const container = document.getElementById('portHeatmap');
            const tooltip = document.getElementById('portTooltip');
            
            // 清空容器
            container.innerHTML = '';
            
            // 获取端口数据
            const portData = [];
            const rows = document.querySelectorAll('.port-row:not(.banner-row)');
            
            rows.forEach(row => {
                const port = parseInt(row.getAttribute('data-port'));
                const state = row.getAttribute('data-state');
                if (!isNaN(port) && state) {
                    portData.push({ port, state });
                }
            });
            
            // 如果没有端口数据，显示提示信息
            if (portData.length === 0) {
                container.innerHTML = '<p style="text-align:center;color:#7f8c8d;">没有可用的端口数据</p>';
                return;
            }
            
            // 创建热图单元格
            portData.forEach(data => {
                const cell = document.createElement('div');
                cell.className = 'port-cell ' + data.state;
                cell.setAttribute('data-port', data.port);
                cell.textContent = '';
                
                // 添加鼠标悬停事件
                cell.addEventListener('mouseover', (e) => {
                    const rect = e.target.getBoundingClientRect();
                    tooltip.style.left = rect.left + window.scrollX + 'px';
                    tooltip.style.top = (rect.top - 30) + window.scrollY + 'px';
                    tooltip.textContent = '端口 ' + data.port + ': ' + getStateText(data.state);
                    tooltip.style.display = 'block';
                });
                
                cell.addEventListener('mouseout', () => {
                    tooltip.style.display = 'none';
                });
                
                // 点击跳转到表格对应行
                cell.addEventListener('click', () => {
                    const targetRow = document.querySelector('.port-row[data-port="' + data.port + '"]:not(.banner-row)');
                    if (targetRow) {
                        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        // 高亮显示
                        targetRow.style.backgroundColor = '#fffde7';
                        setTimeout(() => {
                            targetRow.style.backgroundColor = '';
                        }, 2000);
                    }
                });
                
                container.appendChild(cell);
            });
        }
        
        // 获取状态文本
        function getStateText(state) {
            switch(state) {
                case 'open': return '开放';
                case 'closed': return '关闭';
                case 'filtered': return '过滤';
                default: return '未知';
            }
        }
        
        // 生成颜色数组
        function generateColors(count) {
            const baseColors = [
                '#3498db', '#9b59b6', '#1abc9c', '#34495e', '#f1c40f', 
                '#e67e22', '#e74c3c', '#2ecc71', '#16a085', '#27ae60',
                '#2980b9', '#8e44ad', '#f39c12', '#d35400', '#c0392b'
            ];
            
            // 如果基础颜色足够，直接返回
            if (count <= baseColors.length) {
                return baseColors.slice(0, count);
            }
            
            // 否则生成更多颜色
            const colors = [...baseColors];
            while (colors.length < count) {
                const r = Math.floor(Math.random() * 200) + 50;
                const g = Math.floor(Math.random() * 200) + 50;
                const b = Math.floor(Math.random() * 200) + 50;
                colors.push('rgb(' + r + ', ' + g + ', ' + b + ')');
            }
            
            return colors;
        }
        
        // 初始化历史扫描时间轴
        function initTimelineChart() {
            const ctx = document.getElementById('timelineChart').getContext('2d');
            
            // 没有历史数据时显示提示信息
            const data = {
                labels: ['当前扫描'],
                datasets: [{
                    label: '开放端口',
                    data: [`+fmt.Sprintf("%d", openCount)+`],
                    backgroundColor: '#27ae60',
                    borderColor: '#27ae60',
                    borderWidth: 2,
                    tension: 0.1
                }, {
                    label: '关闭端口',
                    data: [`+fmt.Sprintf("%d", closedCount)+`],
                    backgroundColor: '#e74c3c',
                    borderColor: '#e74c3c',
                    borderWidth: 2,
                    tension: 0.1
                }, {
                    label: '过滤端口',
                    data: [`+fmt.Sprintf("%d", filteredCount)+`],
                    backgroundColor: '#f39c12',
                    borderColor: '#f39c12',
                    borderWidth: 2,
                    tension: 0.1
                }]
            };
            
            new Chart(ctx, {
                type: 'line',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: '端口数量'
                            }
                        }
                    }
                }
            });
        }
        
        // 协议解析器相关函数
        function switchAnalyzerTab(portId, tabName) {
            // 取消所有标签激活状态
            document.querySelectorAll('#analyzer-' + portId + ' .analyzer-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // 隐藏所有内容
            document.querySelectorAll('#analyzer-' + portId + ' .analyzer-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // 激活选中的标签和内容
            document.querySelector('#analyzer-' + portId + ' .analyzer-tab[onclick="switchAnalyzerTab(' + portId + ', \'' + tabName + '\')"]').classList.add('active');
            document.getElementById('analyzer-' + portId + '-' + tabName).classList.add('active');
        }
        
        // 初始化十六进制查看器
        function initHexViewer(portId, hexData) {
            const container = document.getElementById('hex-viewer-' + portId);
            const tooltip = document.getElementById('hex-tooltip-' + portId);
            
            if (!container || !hexData) return;
            
            // 确保hexData是偶数长度（每个字节两个十六进制字符）
            if (hexData.length % 2 !== 0) {
                hexData = '0' + hexData;
            }
            
            // 清空容器
            container.innerHTML = '';
            
            // 每行显示16个字节
            const bytesPerRow = 16;
            const rows = Math.ceil(hexData.length / 2 / bytesPerRow);
            
            for (let i = 0; i < rows; i++) {
                const rowDiv = document.createElement('div');
                rowDiv.className = 'bytes-row';
                
                // 添加偏移量
                const offsetDiv = document.createElement('div');
                offsetDiv.className = 'offset';
                offsetDiv.textContent = (i * bytesPerRow).toString(16).padStart(4, '0') + ':';
                rowDiv.appendChild(offsetDiv);
                
                // 添加十六进制部分
                const hexDiv = document.createElement('div');
                hexDiv.className = 'hex-bytes';
                
                // 添加ASCII部分
                const asciiDiv = document.createElement('div');
                asciiDiv.className = 'ascii-bytes';
                
                for (let j = 0; j < bytesPerRow; j++) {
                    const byteIndex = i * bytesPerRow + j;
                    if (byteIndex * 2 >= hexData.length) break;
                    
                    const byteValue = hexData.substr(byteIndex * 2, 2);
                    
                    // 创建十六进制字节元素
                    const hexByte = document.createElement('span');
                    hexByte.className = 'hex-byte';
                    hexByte.textContent = byteValue;
                    hexByte.setAttribute('data-offset', byteIndex);
                    hexByte.setAttribute('data-value', byteValue);
                    
                    // 添加鼠标悬停事件
                    hexByte.addEventListener('mouseover', (e) => {
                        const byte = e.target;
                        const rect = byte.getBoundingClientRect();
                        const offset = byte.getAttribute('data-offset');
                        const value = byte.getAttribute('data-value');
                        
                        tooltip.style.left = (rect.left + window.scrollX) + 'px';
                        tooltip.style.top = (rect.top - 30 + window.scrollY) + 'px';
                        tooltip.innerHTML = '偏移量: 0x' + parseInt(offset).toString(16) + '<br>值: 0x' + value + ' (' + parseInt(value, 16) + ')';
                        tooltip.style.display = 'block';
                    });
                    
                    hexByte.addEventListener('mouseout', () => {
                        tooltip.style.display = 'none';
                    });
                    
                    hexDiv.appendChild(hexByte);
                    
                    // 添加ASCII字符
                    const charCode = parseInt(byteValue, 16);
                    const asciiChar = (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
                    
                    const asciiByte = document.createElement('span');
                    asciiByte.className = 'ascii-byte';
                    asciiByte.textContent = asciiChar;
                    asciiDiv.appendChild(asciiByte);
                }
                
                rowDiv.appendChild(hexDiv);
                rowDiv.appendChild(asciiDiv);
                container.appendChild(rowDiv);
            }
            
            // 根据协议类型应用字段高亮
            const serviceName = document.querySelector('#analyzer-' + portId + ' .protocol-title').textContent.split(' ')[0].toLowerCase();
            applyProtocolHighlighting(portId, serviceName, hexData);
        }
        
        // 应用协议字段高亮
        function applyProtocolHighlighting(portId, protocol, hexData) {
            const hexViewer = document.getElementById('hex-viewer-' + portId);
            const detailsContainer = document.getElementById('protocol-details-' + portId);
            
            if (!hexViewer || !detailsContainer) return;
            
            // 清空字段容器
            detailsContainer.innerHTML = '';
            
            // 根据不同协议类型定义字段
            let fields = [];
            
            switch (protocol.toLowerCase()) {
                case 'ntp':
                    fields = parseNTP(hexData);
                    break;
                case 'dns':
                    fields = parseDNS(hexData);
                    break;
                case 'snmp':
                    fields = parseSNMP(hexData);
                    break;
                default:
                    // 通用解析，仅显示数据块
                    fields = [
                        { name: '数据', offset: 0, length: hexData.length / 2, type: 'payload', value: hexData, description: '原始协议数据' }
                    ];
            }
            
            // 为每个字段创建详情区域
            fields.forEach((field, index) => {
                const fieldDiv = document.createElement('div');
                fieldDiv.className = 'protocol-field';
                fieldDiv.setAttribute('data-offset-start', field.offset);
                fieldDiv.setAttribute('data-offset-end', field.offset + field.length - 1);
                
                const fieldHTML = 
                    '<div>' +
                        '<span class="field-name">' + field.name + '</span>' +
                        '<span class="field-value" style="background-color: ' + getFieldColor(field.type) + '; color: white;">' + field.value + '</span>' +
                    '</div>' +
                    '<div class="field-description">' + field.description + '</div>';
                
                fieldDiv.innerHTML = fieldHTML;
                
                // 添加鼠标悬停事件，高亮相应的十六进制字节
                fieldDiv.addEventListener('mouseover', () => {
                    const startOffset = parseInt(fieldDiv.getAttribute('data-offset-start'));
                    const endOffset = parseInt(fieldDiv.getAttribute('data-offset-end'));
                    
                    // 高亮相应的十六进制字节
                    const hexBytes = hexViewer.querySelectorAll('.hex-byte');
                    hexBytes.forEach(byte => {
                        const offset = parseInt(byte.getAttribute('data-offset'));
                        if (offset >= startOffset && offset <= endOffset) {
                            byte.style.backgroundColor = getFieldColor(field.type);
                            byte.style.color = 'white';
                        }
                    });
                });
                
                fieldDiv.addEventListener('mouseout', () => {
                    // 移除高亮
                    const hexBytes = hexViewer.querySelectorAll('.hex-byte');
                    hexBytes.forEach(byte => {
                        byte.style.backgroundColor = '';
                        byte.style.color = '';
                    });
                });
                
                detailsContainer.appendChild(fieldDiv);
            });
            
            // 初始高亮字段，这里我们可以将默认的颜色应用到十六进制查看器中
            fields.forEach(field => {
                const startOffset = field.offset;
                const endOffset = field.offset + field.length - 1;
                
                // 添加字段类
                const hexBytes = hexViewer.querySelectorAll('.hex-byte');
                hexBytes.forEach(byte => {
                    const offset = parseInt(byte.getAttribute('data-offset'));
                    if (offset >= startOffset && offset <= endOffset) {
                        byte.classList.add('hex-field');
                        byte.classList.add('field-' + field.type);
                    }
                });
            });
        }
        
        // 获取字段颜色
        function getFieldColor(type) {
            switch(type) {
                case 'header': return '#3498db';   // 蓝色
                case 'data': return '#2ecc71';     // 绿色
                case 'timestamp': return '#9b59b6'; // 紫色
                case 'identifier': return '#f39c12'; // 橙色
                case 'payload': return '#e74c3c';  // 红色
                default: return '#7f8c8d';         // 灰色
            }
        }
        
        // 解析NTP协议
        function parseNTP(hexData) {
            // NTP包结构解析
            if (hexData.length < 8) return [];
            
            // 获取第一个字节的二进制表示，用于解析各个标志位
            const firstByte = parseInt(hexData.substr(0, 2), 16);
            const leapIndicator = (firstByte >> 6) & 0x03;
            const version = (firstByte >> 3) & 0x07;
            const mode = firstByte & 0x07;
            
            // 获取NTP模式的文本描述
            let modeText;
            switch(mode) {
                case 1: modeText = "活跃对等体"; break;
                case 2: modeText = "被动对等体"; break;
                case 3: modeText = "客户端"; break;
                case 4: modeText = "服务器"; break;
                case 5: modeText = "广播"; break;
                case 6: modeText = "NTP控制消息"; break;
                case 7: modeText = "预留（内部使用）"; break;
                default: modeText = "未定义"; break;
            }
            
            // 获取闰秒指示器的文本描述
            let leapText;
            switch(leapIndicator) {
                case 0: leapText = "无警告"; break;
                case 1: leapText = "最后一分钟有61秒"; break;
                case 2: leapText = "最后一分钟有59秒"; break;
                case 3: leapText = "警告（时钟未同步）"; break;
            }
            
            const fields = [
                {
                    offset: 0,
                    length: 1,
                    name: "LI, VN, Mode",
                    value: hexData.substr(0, 2),
                    type: "header",
                    description: "闰秒指示器: " + leapIndicator + " (" + leapText + "), 版本: " + version + ", 模式: " + mode + " (" + modeText + ")"
                },
                {
                    offset: 1,
                    length: 1,
                    name: "Stratum",
                    value: hexData.substr(2, 2),
                    type: "header",
                    description: "层级: " + parseInt(hexData.substr(2, 2), 16) + " (" + getStratumDescription(parseInt(hexData.substr(2, 2), 16)) + ")"
                },
                {
                    offset: 2,
                    length: 1,
                    name: "Poll",
                    value: hexData.substr(4, 2),
                    type: "header",
                    description: "轮询间隔: " + Math.pow(2, parseInt(hexData.substr(4, 2), 16)) + " 秒"
                },
                {
                    offset: 3,
                    length: 1,
                    name: "Precision",
                    value: hexData.substr(6, 2),
                    type: "header",
                    description: "精度: " + Math.pow(2, parseInt(hexData.substr(6, 2), 16)) + " 秒"
                },
                {
                    offset: 4,
                    length: 4,
                    name: "Root Delay",
                    value: hexData.substr(8, 8),
                    type: "data",
                    description: "根延迟: " + parseInt(hexData.substr(8, 8), 16) / 65536 + " 秒"
                },
                {
                    offset: 8,
                    length: 4,
                    name: "Root Dispersion",
                    value: hexData.substr(16, 8),
                    type: "data",
                    description: "根离散度: " + parseInt(hexData.substr(16, 8), 16) / 65536 + " 秒"
                },
                {
                    offset: 12,
                    length: 4,
                    name: "Reference ID",
                    value: hexData.substr(24, 8),
                    type: "identifier",
                    description: "参考标识符: " + getRefIdText(hexData.substr(24, 8))
                }
            ];
            
            // 添加各种时间戳
            if (hexData.length >= 48) {
                fields.push({
                    offset: 16,
                    length: 8,
                    name: "Reference Timestamp",
                    value: hexData.substr(32, 16),
                    type: "data",
                    description: "参考时间戳: " + getNtpTimestamp(hexData.substr(32, 16))
                });
            }
            
            if (hexData.length >= 56) {
                fields.push({
                    offset: 24,
                    length: 8,
                    name: "Origin Timestamp",
                    value: hexData.substr(48, 16),
                    type: "data",
                    description: "起始时间戳: " + getNtpTimestamp(hexData.substr(48, 16))
                });
            }
            
            if (hexData.length >= 64) {
                fields.push({
                    offset: 32,
                    length: 8,
                    name: "Receive Timestamp",
                    value: hexData.substr(64, 16),
                    type: "data",
                    description: "接收时间戳: " + getNtpTimestamp(hexData.substr(64, 16))
                });
            }
            
            if (hexData.length >= 72) {
                fields.push({
                    offset: 40,
                    length: 8,
                    name: "Transmit Timestamp",
                    value: hexData.substr(80, 16),
                    type: "data",
                    description: "发送时间戳: " + getNtpTimestamp(hexData.substr(80, 16))
                });
            }
            
            return fields;
        }
        
        // 获取NTP分层描述
        function getStratumDescription(stratum) {
            if (stratum === 0) return "未指定或无效";
            if (stratum === 1) return "主参考源（原子钟、GPS等）";
            if (stratum >= 2 && stratum <= 15) return "次级参考源（通过NTP同步）";
            return "未使用";
        }
        
        // 获取参考标识符的文本表示
        function getRefIdText(hexRefId) {
            if (hexRefId === "00000000") return "未指定";
            
            // 尝试将其作为ASCII字符解释
            let refText = "";
            for (let i = 0; i < 8; i += 2) {
                const charCode = parseInt(hexRefId.substr(i, 2), 16);
                if (charCode >= 32 && charCode <= 126) { // 可打印ASCII
                    refText += String.fromCharCode(charCode);
                }
            }
            
            // 如果能解析为有效文本，返回文本形式
            if (refText.length > 0 && refText.trim().length > 0) {
                return hexRefId + " ('" + refText + "')";
            }
            
            // 否则返回原始十六进制
            return hexRefId;
        }
        
        // 解析NTP时间戳（从1900年1月1日开始的秒数）
        function getNtpTimestamp(hexTimestamp) {
            if (hexTimestamp.length < 16) return "无效时间戳";
            
            // NTP时间戳的前32位是从1900年1月1日至今的秒数
            const seconds = parseInt(hexTimestamp.substr(0, 8), 16);
            
            // 后32位是秒的小数部分
            const fraction = parseInt(hexTimestamp.substr(8, 8), 16) / Math.pow(2, 32);
            
            // 计算自1900年1月1日以来的总秒数
            const totalSeconds = seconds + fraction;
            
            // 1900年1月1日到1970年1月1日（Unix时间戳起点）的秒数
            const offsetToUnixEpoch = 2208988800;
            
            // 转换为Unix时间戳
            const unixTimestamp = (totalSeconds - offsetToUnixEpoch) * 1000;
            
            // 创建Date对象并格式化
            try {
                const date = new Date(unixTimestamp);
                return date.toISOString().replace('T', ' ').replace('Z', '') + " UTC";
            } catch (e) {
                return "解析错误 (" + hexTimestamp + ")";
            }
        }
        
        // 解析DNS协议
        function parseDNS(hexData) {
            if (hexData.length < 24) return [];
            
            // 提取DNS头部的各个字段
            const transactionId = hexData.substr(0, 4);
            const flags = parseInt(hexData.substr(4, 4), 16);
            const qdcount = parseInt(hexData.substr(8, 4), 16); // 问题记录数
            const ancount = parseInt(hexData.substr(12, 4), 16); // 回答记录数
            const nscount = parseInt(hexData.substr(16, 4), 16); // 权威名称服务器记录数
            const arcount = parseInt(hexData.substr(20, 4), 16); // 附加资源记录数
            
            // 解析标志位
            const qr = (flags >> 15) & 0x01; // 查询/响应标志
            const opcode = (flags >> 11) & 0x0F; // 操作码
            const aa = (flags >> 10) & 0x01; // 权威回答
            const tc = (flags >> 9) & 0x01; // 截断
            const rd = (flags >> 8) & 0x01; // 期望递归
            const ra = (flags >> 7) & 0x01; // 递归可用
            const z = (flags >> 4) & 0x07; // 保留
            const rcode = flags & 0x0F; // 响应码
            
            // 获取操作码的文本描述
            let opcodeText;
            switch(opcode) {
                case 0: opcodeText = "标准查询"; break;
                case 1: opcodeText = "反向查询"; break;
                case 2: opcodeText = "服务器状态请求"; break;
                default: opcodeText = "未知(" + opcode + ")"; break;
            }
            
            // 获取响应码的文本描述
            let rcodeText;
            switch(rcode) {
                case 0: rcodeText = "无错误"; break;
                case 1: rcodeText = "格式错误"; break;
                case 2: rcodeText = "服务器错误"; break;
                case 3: rcodeText = "名称错误"; break;
                case 4: rcodeText = "未实现"; break;
                case 5: rcodeText = "拒绝"; break;
                default: rcodeText = "未知(" + rcode + ")"; break;
            }
            
            // 解析查询部分（如果有）
            let queryLen = 0;
            let queryName = "";
            
            if (qdcount > 0) {
                // DNS查询名称使用特殊的压缩格式
                let pos = 24; // 查询部分开始的位置（十六进制字符位置）
                let labelLen = parseInt(hexData.substr(pos, 2), 16);
                
                while (labelLen > 0) {
                    pos += 2; // 移到标签内容的开始位置
                    
                    // 提取标签（域名的一部分）
                    let label = "";
                    for (let i = 0; i < labelLen; i++) {
                        const charCode = parseInt(hexData.substr(pos + i*2, 2), 16);
                        label += String.fromCharCode(charCode);
                    }
                    
                    queryName += label + ".";
                    pos += labelLen * 2; // 移到下一个长度字节
                    
                    labelLen = parseInt(hexData.substr(pos, 2), 16);
                }
                
                // 移除末尾的点并计算长度
                if (queryName.endsWith(".")) {
                    queryName = queryName.slice(0, -1);
                }
                
                queryLen = (pos + 2 - 24) / 2 + 4; // +4用于类型和类
            }
            
            // 构建DNS字段数组
            const fields = [
                {
                    offset: 0,
                    length: 2,
                    name: "Transaction ID",
                    value: transactionId,
                    type: "header",
                    description: "交易ID: 0x" + transactionId
                },
                {
                    offset: 2,
                    length: 2,
                    name: "Flags",
                    value: hexData.substr(4, 4),
                    type: "header",
                    description: "标志: " + 
                                (qr === 1 ? "响应" : "查询") + ", " + 
                                "操作码: " + opcodeText + ", " + 
                                (aa === 1 ? "权威应答, " : "") + 
                                (tc === 1 ? "截断, " : "") + 
                                (rd === 1 ? "期望递归, " : "") + 
                                (ra === 1 ? "递归可用, " : "") + 
                                "响应码: " + rcodeText
                },
                {
                    offset: 4,
                    length: 2,
                    name: "Questions",
                    value: hexData.substr(8, 4),
                    type: "header",
                    description: "问题记录数: " + qdcount
                },
                {
                    offset: 6,
                    length: 2,
                    name: "Answer RRs",
                    value: hexData.substr(12, 4),
                    type: "header",
                    description: "回答记录数: " + ancount
                },
                {
                    offset: 8,
                    length: 2,
                    name: "Authority RRs",
                    value: hexData.substr(16, 4),
                    type: "header",
                    description: "权威名称服务器记录数: " + nscount
                },
                {
                    offset: 10,
                    length: 2,
                    name: "Additional RRs",
                    value: hexData.substr(20, 4),
                    type: "header",
                    description: "附加资源记录数: " + arcount
                }
            ];
            
            // 添加查询部分（如果有）
            if (qdcount > 0) {
                fields.push({
                    offset: 12,
                    length: queryLen,
                    name: "Query",
                    value: hexData.substr(24, queryLen * 2),
                    type: "data",
                    description: "查询名称: " + queryName
                });
                
                fields.push({
                    offset: 12 + queryLen,
                    length: hexData.length / 2 - (12 + queryLen),
                    name: "Records",
                    value: hexData.substr(24 + queryLen * 2),
                    type: "payload",
                    description: "包含回答(" + ancount + "个)、权威(" + nscount + "个)和附加(" + arcount + "个)资源记录"
                });
            }
            
            return fields;
        }
        
        // 解析SNMP协议
        function parseSNMP(hexData) {
            if (hexData.length < 10) return [];
            
            // SNMP使用ASN.1 BER编码
            const fields = [];
            let offset = 0;
            
            // 检查SNMP消息开始(SEQUENCE)
            const sequenceType = hexData.substr(0, 2);
            const sequenceLenBytes = parseInt(hexData.substr(2, 2), 16);
            let sequenceLen = 0;
            
            if (sequenceType === "30") { // SEQUENCE
                if (sequenceLenBytes & 0x80) { // 长格式
                    const numLenBytes = sequenceLenBytes & 0x7F;
                    if (numLenBytes > 0 && hexData.length >= 4 + numLenBytes * 2) {
                        sequenceLen = parseInt(hexData.substr(4, numLenBytes * 2), 16);
                        offset = 2 + 2 + numLenBytes * 2;
                    }
                } else { // 短格式
                    sequenceLen = sequenceLenBytes;
                    offset = 4;
                }
                
                fields.push({
                    offset: 0,
                    length: offset / 2,
                    name: "SNMP Message",
                    value: hexData.substr(0, offset),
                    type: "header",
                    description: "SNMP消息开始，总长度: " + sequenceLen + " 字节"
                });
            }
            
            // 尝试解析版本
            if (offset + 4 <= hexData.length) {
                const versionType = hexData.substr(offset, 2);
                const versionLen = parseInt(hexData.substr(offset + 2, 2), 16);
                
                if (versionType === "02" && versionLen === 1) { // INTEGER，长度为1
                    const version = parseInt(hexData.substr(offset + 4, 2), 16);
                    let versionText = "未知";
                    
                    switch(version) {
                        case 0: versionText = "v1"; break;
                        case 1: versionText = "v2c"; break;
                        case 3: versionText = "v3"; break;
                    }
                    
                    fields.push({
                        offset: offset / 2,
                        length: 3,
                        name: "Version",
                        value: hexData.substr(offset, 6),
                        type: "data",
                        description: "SNMP版本: " + versionText + " (" + version + ")"
                    });
                    
                    offset += 6;
                }
            }
            
            // 尝试解析社区字符串
            if (offset + 4 <= hexData.length) {
                const communityType = hexData.substr(offset, 2);
                const communityLen = parseInt(hexData.substr(offset + 2, 2), 16);
                
                if (communityType === "04" && offset + 4 + communityLen * 2 <= hexData.length) { // OCTET STRING
                    let communityStr = "";
                    for (let i = 0; i < communityLen; i++) {
                        const charCode = parseInt(hexData.substr(offset + 4 + i * 2, 2), 16);
                        communityStr += String.fromCharCode(charCode);
                    }
                    
                    fields.push({
                        offset: offset / 2,
                        length: 2 + communityLen,
                        name: "Community",
                        value: hexData.substr(offset, 4 + communityLen * 2),
                        type: "data",
                        description: "社区字符串: '" + communityStr + "'"
                    });
                    
                    offset += 4 + communityLen * 2;
                }
            }
            
            // 如果还有剩余数据，作为PDU添加
            if (offset < hexData.length) {
                fields.push({
                    offset: offset / 2,
                    length: (hexData.length - offset) / 2,
                    name: "PDU",
                    value: hexData.substr(offset),
                    type: "payload",
                    description: "协议数据单元"
                });
            }
            
            return fields;
        }

        // 在页面加载完成后初始化图表
        document.addEventListener('DOMContentLoaded', function() {
            initPortStatusChart();
            initServiceTypeChart();
            initPortHeatmap();
            initTimelineChart();
            
            // 初始化所有协议解析器
            document.querySelectorAll('.protocol-analyzer').forEach(analyzer => {
                const portId = analyzer.id.split('-')[1];
                const contentElement = document.getElementById('analyzer-' + portId + '-raw');
                if (contentElement) {
                    const hexData = contentElement.querySelector('pre').textContent;
                    if (hexData) {
                        initHexViewer(portId, hexData);
                    }
                }
            });
        });

        // 在document.ready处添加初始化代码
        document.addEventListener('DOMContentLoaded', function() {
            // 查找所有的协议分析器
            const analyzers = document.querySelectorAll('.protocol-analyzer');
            analyzers.forEach(analyzer => {
                // 获取端口号和协议类型
                const id = analyzer.id.replace('analyzer-', '');
                const protocol = analyzer.querySelector('h2').textContent.split(' ')[0].toLowerCase();
                
                // 获取原始数据
                const rawData = analyzer.querySelector('.analyzer-content[id$="-raw"] pre').textContent.trim();
                
                // 移除非十六进制字符
                const hexData = rawData.replace(/[^0-9A-Fa-f]/g, '');
                
                // 解析协议数据
                const fields = parseProtocolData(hexData, parseInt(id), protocol);
                
                // 填充字段容器
                const fieldsContainer = analyzer.querySelector('.protocol-fields');
                fields.forEach(field => {
                    const fieldDiv = document.createElement('div');
                    fieldDiv.className = 'protocol-field';
                    fieldDiv.setAttribute('data-offset-start', field.offset);
                    fieldDiv.setAttribute('data-offset-end', field.offset + field.length - 1);
                    
                    const fieldHTML = 
                        '<div>' +
                            '<span class="field-name">' + field.name + '</span>' +
                            '<span class="field-value" style="background-color: ' + getFieldColor(field.type) + '; color: white;">' + field.value + '</span>' +
                        '</div>' +
                        '<div class="field-description">' + field.description + '</div>';
                    
                    fieldDiv.innerHTML = fieldHTML;
                    fieldsContainer.appendChild(fieldDiv);
                    
                    // 添加鼠标悬停事件
                    fieldDiv.addEventListener('mouseover', function() {
                        const tooltip = document.getElementById('hex-tooltip-' + id);
                        tooltip.textContent = field.description;
                        tooltip.style.display = 'block';
                        tooltip.style.top = (event.pageY + 10) + 'px';
                        tooltip.style.left = (event.pageX + 10) + 'px';
                    });
                    
                    fieldDiv.addEventListener('mouseout', function() {
                        const tooltip = document.getElementById('hex-tooltip-' + id);
                        tooltip.style.display = 'none';
                    });
                });
                
                // 设置标签切换
                const tabs = analyzer.querySelectorAll('.tab');
                tabs.forEach(tab => {
                    tab.addEventListener('click', function() {
                        // 移除所有标签的活动状态
                        analyzer.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        // 添加当前标签的活动状态
                        this.classList.add('active');
                        
                        // 隐藏所有内容
                        analyzer.querySelectorAll('.analyzer-content').forEach(content => {
                            content.classList.remove('active');
                        });
                        
                        // 显示当前标签对应的内容
                        const tabId = this.getAttribute('data-tab');
                        document.getElementById('analyzer-' + id + '-' + tabId.split('-')[0]).classList.add('active');
                    });
                });
            });
        });

        // 根据端口和协议解析十六进制数据
        function parseProtocolData(hexData, port, protocol) {
            // 去掉空格等非十六进制字符
            hexData = hexData.replace(/[^0-9A-Fa-f]/g, '');
            
            if (protocol.toLowerCase() === 'dns' || port === 53) {
                return parseDNS(hexData);
            } else if (protocol.toLowerCase() === 'ntp' || port === 123) {
                return parseNTP(hexData);
            } else if (protocol.toLowerCase() === 'snmp' || port === 161) {
                return parseSNMP(hexData);
            } else {
                // 通用十六进制数据解析器
                return parseGenericHex(hexData);
            }
        }

        // 添加通用十六进制数据解析器函数
        // 通用十六进制数据解析器
        function parseGenericHex(hexData) {
            const fields = [];
            const bytesPerRow = 16;
            
            // 如果数据太长，分块显示
            for (let offset = 0; offset < hexData.length; offset += bytesPerRow * 2) {
                const remainingBytes = Math.min(bytesPerRow, (hexData.length - offset) / 2);
                const rowData = hexData.substr(offset, remainingBytes * 2);
                
                // 创建ASCII表示
                let asciiText = '';
                for (let i = 0; i < rowData.length; i += 2) {
                    const byte = parseInt(rowData.substr(i, 2), 16);
                    asciiText += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                }
                
                fields.push({
                    offset: offset / 2,
                    length: remainingBytes,
                    name: 'Offset ' + (offset/2).toString(16).padStart(4, '0'),
                    value: rowData,
                    type: 'data',
                    description: 'ASCII: ' + asciiText
                });
            }
            
            return fields;
        }
    </script>
</body>
</html>`, time.Now().Format("2006-01-02 15:04:05"))

	// 写入HTML文件
	if _, err := file.WriteString(htmlTemplate); err != nil {
		return fmt.Errorf("写入HTML内容失败: %v", err)
	}

	return nil
}

// 辅助函数：检测字符串是否为十六进制格式
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ' ') {
			return false
		}
	}
	return true
}
