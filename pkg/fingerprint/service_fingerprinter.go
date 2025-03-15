package fingerprint

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ServiceFingerprinter 服务指纹识别器
type ServiceFingerprinter struct {
	opts *FingerprintOptions
	db   FingerprintDB
}

// NewServiceFingerprinter 创建新的服务指纹识别器
func NewServiceFingerprinter(db FingerprintDB) *ServiceFingerprinter {
	return &ServiceFingerprinter{
		opts: DefaultFingerprintOptions(),
		db:   db,
	}
}

// SetOptions 设置指纹识别选项
func (f *ServiceFingerprinter) SetOptions(opts *FingerprintOptions) {
	f.opts = opts
}

// GetOptions 获取指纹识别选项
func (f *ServiceFingerprinter) GetOptions() *FingerprintOptions {
	return f.opts
}

// FingerprintService 执行服务指纹识别
func (f *ServiceFingerprinter) FingerprintService(target string, port int) (*ServiceFingerprint, error) {
	if !f.opts.EnableServiceDetection {
		return nil, fmt.Errorf("service detection is disabled")
	}

	// 1. 收集探测结果
	probes, err := f.probeService(target, port)
	if err != nil {
		return nil, fmt.Errorf("service probing failed: %v", err)
	}

	// 2. 生成指纹
	fp := &ServiceFingerprint{
		Features:    make(map[string]string),
		Probes:      probes,
		LastUpdated: time.Now(),
	}

	// 3. 提取特征
	f.extractFeatures(fp)

	// 4. 匹配指纹
	matches, err := f.db.MatchServiceFingerprint(fp)
	if err != nil {
		return nil, fmt.Errorf("fingerprint matching failed: %v", err)
	}

	// 5. 选择最佳匹配
	if len(matches) > 0 {
		bestMatch := matches[0]
		fp.Name = bestMatch.Name
		fp.Version = bestMatch.Version
		fp.Product = bestMatch.Product
		fp.Confidence = bestMatch.Confidence
	}

	return fp, nil
}

// probeService 探测服务
func (f *ServiceFingerprinter) probeService(target string, port int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 根据端口选择探测方法
	switch port {
	case 21:
		probes, err := f.probeFTP(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 22:
		probes, err := f.probeSSH(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 23:
		probes, err := f.probeTelnet(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 25:
		probes, err := f.probeSMTP(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 80, 443, 8080:
		probes, err := f.probeHTTP(target, port)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 3306:
		probes, err := f.probeMySQL(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 5432:
		probes, err := f.probePostgreSQL(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 6379:
		probes, err := f.probeRedis(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 27017:
		probes, err := f.probeMongoDB(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	case 9200:
		probes, err := f.probeElasticsearch(target)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	default:
		// 对于未知服务类型，使用通用探测方法
		probes, err := f.probeFTP(target) // 先用 FTP 协议探测
		if err == nil && len(probes) > 0 {
			return probes, nil
		}

		probes, err = f.probeHTTP(target, port) // 尝试 HTTP 协议
		if err == nil && len(probes) > 0 {
			return probes, nil
		}

		// 如果都失败，返回空结果
		return []ProbeResult{}, nil
	}

	return results, nil
}

// probeFTP 探测FTP服务
func (f *ServiceFingerprinter) probeFTP(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接FTP服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:21", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 读取欢迎信息
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "FTP",
		Target:    target,
		Port:      21,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probeSSH 探测SSH服务
func (f *ServiceFingerprinter) probeSSH(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接SSH服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 读取SSH版本信息
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "SSH",
		Target:    target,
		Port:      22,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probeTelnet 探测Telnet服务
func (f *ServiceFingerprinter) probeTelnet(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接Telnet服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:23", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 读取欢迎信息
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "Telnet",
		Target:    target,
		Port:      23,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probeSMTP 探测SMTP服务
func (f *ServiceFingerprinter) probeSMTP(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接SMTP服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:25", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 读取欢迎信息
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "SMTP",
		Target:    target,
		Port:      25,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probeHTTP 探测HTTP服务
func (f *ServiceFingerprinter) probeHTTP(target string, port int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 构建HTTP请求
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-Port-Rocket\r\nAccept: */*\r\n\r\n", target)

	// 连接HTTP服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送HTTP请求
	_, err = conn.Write([]byte(req))
	if err != nil {
		return nil, err
	}

	// 读取响应
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "HTTP",
		Target:    target,
		Port:      port,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probeMySQL 探测MySQL服务
func (f *ServiceFingerprinter) probeMySQL(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接MySQL服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3306", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送MySQL握手包
	handshake := []byte{0x0a} // 简单的握手包
	_, err = conn.Write(handshake)
	if err != nil {
		return nil, err
	}

	// 读取响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "MySQL",
		Target:    target,
		Port:      3306,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probePostgreSQL 探测PostgreSQL服务
func (f *ServiceFingerprinter) probePostgreSQL(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接PostgreSQL服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:5432", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送PostgreSQL握手包
	handshake := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f} // 简单的握手包
	_, err = conn.Write(handshake)
	if err != nil {
		return nil, err
	}

	// 读取响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// 记录探测结果
	results = append(results, ProbeResult{
		Type:      "PostgreSQL",
		Target:    target,
		Port:      5432,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	})

	return results, nil
}

// probeRedis 探测Redis服务
func (f *ServiceFingerprinter) probeRedis(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:6379", target), f.opts.Timeout)
	if err != nil {
		return results, err
	}
	defer conn.Close()

	// 发送PING命令
	conn.SetDeadline(time.Now().Add(f.opts.Timeout))
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		return results, err
	}

	// 读取响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return results, err
	}

	response := string(buf[:n])
	result := ProbeResult{
		Type:      "redis",
		Target:    target,
		Port:      6379,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	}

	// 解析版本信息
	if strings.Contains(response, "REDIS") {
		version := extractRedisVersion(response)
		result.Features["version"] = version
	}

	results = append(results, result)
	return results, nil
}

// probeMongoDB 探测MongoDB服务
func (f *ServiceFingerprinter) probeMongoDB(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:27017", target), f.opts.Timeout)
	if err != nil {
		return results, err
	}
	defer conn.Close()

	// 发送MongoDB握手消息
	handshake := []byte{
		0x3a, 0x00, 0x00, 0x00, // Message length
		0x01, 0x00, 0x00, 0x00, // Request ID
		0x00, 0x00, 0x00, 0x00, // Response to
		0xdd, 0x07, 0x00, 0x00, // Op code: OP_QUERY
		0x00, 0x00, 0x00, 0x00, // Flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // Collection name
		0x00, 0x00, 0x00, 0x00, // Number to skip
		0x01, 0x00, 0x00, 0x00, // Number to return
		0x13, 0x00, 0x00, 0x00, // Document length
		0x01, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00, // Field name
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Value
	}

	conn.SetDeadline(time.Now().Add(f.opts.Timeout))
	_, err = conn.Write(handshake)
	if err != nil {
		return results, err
	}

	// 读取响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return results, err
	}

	result := ProbeResult{
		Type:      "mongodb",
		Target:    target,
		Port:      27017,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	}

	// 解析版本信息
	if len(buf) >= 4 {
		version := extractMongoDBVersion(buf[:n])
		result.Features["version"] = version
	}

	results = append(results, result)
	return results, nil
}

// probeElasticsearch 探测Elasticsearch服务
func (f *ServiceFingerprinter) probeElasticsearch(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:9200", target), f.opts.Timeout)
	if err != nil {
		return results, err
	}
	defer conn.Close()

	// 发送HTTP GET请求
	request := "GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	conn.SetDeadline(time.Now().Add(f.opts.Timeout))
	_, err = conn.Write([]byte(request))
	if err != nil {
		return results, err
	}

	// 读取响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return results, err
	}

	result := ProbeResult{
		Type:      "elasticsearch",
		Target:    target,
		Port:      9200,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features:  make(map[string]string),
	}

	// 解析版本信息
	response := string(buf[:n])
	if strings.Contains(response, "number") {
		version := extractElasticsearchVersion(response)
		result.Features["version"] = version
	}

	results = append(results, result)
	return results, nil
}

// extractRedisVersion 从Redis响应中提取版本信息
func extractRedisVersion(response string) string {
	// 示例响应: "+PONG\r\n$6\r\nREDIS\r\n$6\r\n6.2.6\r\n"
	lines := strings.Split(response, "\r\n")
	for i, line := range lines {
		if line == "REDIS" && i+2 < len(lines) {
			return strings.TrimPrefix(lines[i+2], "$")
		}
	}
	return "unknown"
}

// extractMongoDBVersion 从MongoDB响应中提取版本信息
func extractMongoDBVersion(data []byte) string {
	// MongoDB响应格式解析
	if len(data) < 36 {
		return "unknown"
	}

	// 解析版本信息
	version := fmt.Sprintf("%d.%d.%d", data[32], data[33], data[34])
	return version
}

// extractElasticsearchVersion 从Elasticsearch响应中提取版本信息
func extractElasticsearchVersion(response string) string {
	// 示例响应: {"name":"node-1","cluster_name":"elasticsearch","version":{"number":"7.17.0"}}
	if strings.Contains(response, "version") {
		start := strings.Index(response, "\"number\":\"")
		if start != -1 {
			start += 9
			end := strings.Index(response[start:], "\"")
			if end != -1 {
				return response[start : start+end]
			}
		}
	}
	return "unknown"
}

// extractFeatures 从探测结果中提取特征
func (f *ServiceFingerprinter) extractFeatures(fp *ServiceFingerprint) {
	for _, probe := range fp.Probes {
		// 提取服务特征
		switch probe.Type {
		case "FTP":
			f.extractFTPFeatures(probe, fp)
		case "SSH":
			f.extractSSHFeatures(probe, fp)
		case "Telnet":
			f.extractTelnetFeatures(probe, fp)
		case "SMTP":
			f.extractSMTPFeatures(probe, fp)
		case "HTTP":
			f.extractHTTPFeatures(probe, fp)
		case "MySQL":
			f.extractMySQLFeatures(probe, fp)
		case "PostgreSQL":
			f.extractPostgreSQLFeatures(probe, fp)
		case "redis":
			f.extractRedisFeatures(probe, fp)
		case "mongodb":
			f.extractMongoDBFeatures(probe, fp)
		case "elasticsearch":
			f.extractElasticsearchFeatures(probe, fp)
		}
	}
}

// extractFTPFeatures 提取FTP服务特征
func (f *ServiceFingerprinter) extractFTPFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取FTP服务器信息
	if strings.Contains(response, "220") {
		fp.Features["ftp_server"] = strings.TrimSpace(strings.Split(response, "\r\n")[0])
	}

	// 提取FTP版本信息
	if strings.Contains(response, "Version") {
		version := strings.Split(response, "Version")[1]
		version = strings.Split(version, "\r\n")[0]
		fp.Features["ftp_version"] = strings.TrimSpace(version)
	}
}

// extractSSHFeatures 提取SSH服务特征
func (f *ServiceFingerprinter) extractSSHFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取SSH版本信息
	if strings.HasPrefix(response, "SSH-") {
		fp.Features["ssh_version"] = strings.TrimSpace(strings.Split(response, "\r\n")[0])
	}
}

// extractTelnetFeatures 提取Telnet服务特征
func (f *ServiceFingerprinter) extractTelnetFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取Telnet服务器信息
	if strings.Contains(response, "Welcome") {
		fp.Features["telnet_server"] = strings.TrimSpace(strings.Split(response, "\r\n")[0])
	}
}

// extractSMTPFeatures 提取SMTP服务特征
func (f *ServiceFingerprinter) extractSMTPFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取SMTP服务器信息
	if strings.Contains(response, "220") {
		fp.Features["smtp_server"] = strings.TrimSpace(strings.Split(response, "\r\n")[0])
	}
}

// extractHTTPFeatures 提取HTTP服务特征
func (f *ServiceFingerprinter) extractHTTPFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取HTTP服务器信息
	if strings.Contains(response, "Server:") {
		server := strings.Split(response, "Server:")[1]
		server = strings.Split(server, "\r\n")[0]
		fp.Features["http_server"] = strings.TrimSpace(server)
	}

	// 提取HTTP版本信息
	if strings.Contains(response, "HTTP/") {
		version := strings.Split(response, "HTTP/")[1]
		version = strings.Split(version, "\r\n")[0]
		fp.Features["http_version"] = strings.TrimSpace(version)
	}
}

// extractMySQLFeatures 提取MySQL服务特征
func (f *ServiceFingerprinter) extractMySQLFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := probe.Response

	// 提取MySQL版本信息
	if len(response) >= 5 && response[0] == 0x0a {
		version := string(response[1:])
		fp.Features["mysql_version"] = strings.TrimSpace(version)
	}
}

// extractPostgreSQLFeatures 提取PostgreSQL服务特征
func (f *ServiceFingerprinter) extractPostgreSQLFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := probe.Response

	// 提取PostgreSQL版本信息
	if len(response) >= 8 && response[0] == 0x4e {
		version := string(response[8:])
		fp.Features["postgresql_version"] = strings.TrimSpace(version)
	}
}

// extractRedisFeatures 提取Redis服务特征
func (f *ServiceFingerprinter) extractRedisFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取Redis版本信息
	if strings.Contains(response, "REDIS") {
		version := strings.Split(response, "REDIS")[1]
		version = strings.Split(version, "\r\n")[0]
		fp.Features["redis_version"] = strings.TrimSpace(version)
	}
}

// extractMongoDBFeatures 提取MongoDB服务特征
func (f *ServiceFingerprinter) extractMongoDBFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取MongoDB版本信息
	if strings.Contains(response, "version") {
		version := strings.Split(response, "version")[1]
		version = strings.Split(version, "\r\n")[0]
		fp.Features["mongodb_version"] = strings.TrimSpace(version)
	}
}

// extractElasticsearchFeatures 提取Elasticsearch服务特征
func (f *ServiceFingerprinter) extractElasticsearchFeatures(probe ProbeResult, fp *ServiceFingerprint) {
	response := string(probe.Response)

	// 提取Elasticsearch版本信息
	if strings.Contains(response, "number") {
		version := strings.Split(response, "number")[1]
		version = strings.Split(version, "\r\n")[0]
		fp.Features["elasticsearch_version"] = strings.TrimSpace(version)
	}
}
