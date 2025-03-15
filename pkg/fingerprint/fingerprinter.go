package fingerprint

import (
	"fmt"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/fingerprint/nmap"
)

// Fingerprinter 指纹识别器
type Fingerprinter struct {
	opts *FingerprintOptions
	db   *nmap.NmapDB
}

// NewFingerprinter 创建新的指纹识别器
func NewFingerprinter(nmapSharePath string) (*Fingerprinter, error) {
	var db *nmap.NmapDB
	var err error

	// 如果用户没有提供Nmap共享目录路径，则使用嵌入的指纹数据
	if nmapSharePath == "" {
		tempDir, err := GetEmbeddedFingerprintPath()
		if err != nil {
			return nil, fmt.Errorf("提取嵌入的指纹数据失败: %v", err)
		}

		// 使用临时目录中的嵌入指纹数据
		db, err = nmap.LoadNmapDB(tempDir)
		if err != nil {
			return nil, fmt.Errorf("加载嵌入的指纹数据库失败: %v", err)
		}
	} else {
		// 用户提供了Nmap路径，尝试加载
		db, err = nmap.LoadNmapDB(nmapSharePath)
		if err != nil {
			// 如果加载失败，回退到嵌入的指纹数据
			tempDir, tempErr := GetEmbeddedFingerprintPath()
			if tempErr != nil {
				return nil, fmt.Errorf("加载Nmap指纹数据库失败: %v, 同时无法提取嵌入的指纹数据: %v", err, tempErr)
			}

			db, err = nmap.LoadNmapDB(tempDir)
			if err != nil {
				return nil, fmt.Errorf("加载Nmap指纹数据库失败: %v", err)
			}
		}
	}

	return &Fingerprinter{
		opts: DefaultFingerprintOptions(),
		db:   db,
	}, nil
}

// SetOptions 设置指纹识别选项
func (f *Fingerprinter) SetOptions(opts *FingerprintOptions) {
	f.opts = opts
}

// GetOptions 获取指纹识别选项
func (f *Fingerprinter) GetOptions() *FingerprintOptions {
	return f.opts
}

// FingerprintOS 执行操作系统指纹识别
func (f *Fingerprinter) FingerprintOS(target string, ports []int) (*OSFingerprint, error) {
	if !f.opts.EnableOSDetection {
		return nil, fmt.Errorf("操作系统检测已禁用")
	}

	// 1. 收集探测结果
	probes, err := f.probeOS(target, ports)
	if err != nil {
		return nil, fmt.Errorf("操作系统探测失败: %v", err)
	}

	// 2. 生成指纹
	fp := &OSFingerprint{
		Features:    make(map[string]string),
		Probes:      probes,
		LastUpdated: time.Now(),
	}

	// 3. 提取特征
	f.extractFeatures(fp)

	// 4. 匹配指纹
	matches, err := f.db.MatchOS(fp.Features)
	if err != nil {
		return nil, fmt.Errorf("指纹匹配失败: %v", err)
	}

	// 5. 选择最佳匹配
	if len(matches) > 0 {
		bestMatch := matches[0]
		fp.Name = bestMatch.Name
		fp.Version = bestMatch.Features["version"]
		fp.Confidence = 0.9 // TODO: 根据匹配规则计算置信度
	}

	return fp, nil
}

// FingerprintService 执行服务指纹识别
func (f *Fingerprinter) FingerprintService(target string, port int) (*ServiceFingerprint, error) {
	if !f.opts.EnableServiceDetection {
		return nil, fmt.Errorf("服务检测已禁用")
	}

	// 1. 收集探测结果
	probes, err := f.probeService(target, port)
	if err != nil {
		return nil, fmt.Errorf("服务探测失败: %v", err)
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
	matches, err := f.db.MatchService(fp.Features)
	if err != nil {
		return nil, fmt.Errorf("指纹匹配失败: %v", err)
	}

	// 5. 选择最佳匹配
	if len(matches) > 0 {
		bestMatch := matches[0]
		fp.Name = bestMatch.Name
		fp.Version = bestMatch.Features["version"]
		fp.Product = bestMatch.Features["product"]
		fp.Confidence = 0.9 // TODO: 根据匹配规则计算置信度
	}

	return fp, nil
}

// probeOS 探测操作系统
func (f *Fingerprinter) probeOS(target string, ports []int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 1. TCP序列号探测
	seqProbes, err := f.seqProbe(target, ports)
	if err != nil {
		return nil, err
	}
	results = append(results, seqProbes...)

	// 2. ICMP探测
	icmpProbes, err := f.icmpProbe(target)
	if err != nil {
		return nil, err
	}
	results = append(results, icmpProbes...)

	// 3. ECN探测
	ecnProbes, err := f.ecnProbe(target, ports)
	if err != nil {
		return nil, err
	}
	results = append(results, ecnProbes...)

	// 4. TCP选项探测
	tcpOptProbes, err := f.tcpOptionsProbe(target, ports)
	if err != nil {
		return nil, err
	}
	results = append(results, tcpOptProbes...)

	// 5. UDP探测
	udpProbes, err := f.udpProbe(target, ports)
	if err != nil {
		return nil, err
	}
	results = append(results, udpProbes...)

	return results, nil
}

// probeService 探测服务
func (f *Fingerprinter) probeService(target string, port int) ([]ProbeResult, error) {
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
		probes, err := f.probeGeneric(target, port)
		if err != nil {
			return nil, err
		}
		results = append(results, probes...)
	}

	return results, nil
}

// extractFeatures 从探测结果中提取特征
func (f *Fingerprinter) extractFeatures(fp interface{}) {
	switch v := fp.(type) {
	case *OSFingerprint:
		f.extractOSFeatures(v)
	case *ServiceFingerprint:
		f.extractServiceFeatures(v)
	}
}

// extractOSFeatures 提取操作系统特征
func (f *Fingerprinter) extractOSFeatures(fp *OSFingerprint) {
	for _, probe := range fp.Probes {
		// 提取TCP序列号特征
		if probe.Type == "SEQ" {
			fp.Features["seq"] = probe.Features["seq"]
		}

		// 提取ICMP特征
		if probe.Type == "ICMP" {
			fp.Features["icmp"] = probe.Features["icmp"]
		}

		// 提取ECN特征
		if probe.Type == "ECN" {
			fp.Features["ecn"] = probe.Features["ecn"]
		}

		// 提取TCP选项特征
		if probe.Type == "TCP_OPTIONS" {
			fp.Features["tcp_options"] = probe.Features["tcp_options"]
		}

		// 提取UDP特征
		if probe.Type == "UDP" {
			fp.Features["udp"] = probe.Features["udp"]
		}
	}
}

// extractServiceFeatures 提取服务特征
func (f *Fingerprinter) extractServiceFeatures(fp *ServiceFingerprint) {
	for _, probe := range fp.Probes {
		// 提取服务特征
		switch probe.Type {
		case "FTP":
			fp.Features["ftp"] = probe.Features["ftp"]
		case "SSH":
			fp.Features["ssh"] = probe.Features["ssh"]
		case "Telnet":
			fp.Features["telnet"] = probe.Features["telnet"]
		case "SMTP":
			fp.Features["smtp"] = probe.Features["smtp"]
		case "HTTP":
			fp.Features["http"] = probe.Features["http"]
		case "MySQL":
			fp.Features["mysql"] = probe.Features["mysql"]
		case "PostgreSQL":
			fp.Features["postgresql"] = probe.Features["postgresql"]
		case "Redis":
			fp.Features["redis"] = probe.Features["redis"]
		case "MongoDB":
			fp.Features["mongodb"] = probe.Features["mongodb"]
		case "Elasticsearch":
			fp.Features["elasticsearch"] = probe.Features["elasticsearch"]
		}
	}
}
