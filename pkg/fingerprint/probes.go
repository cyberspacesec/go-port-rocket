package fingerprint

import (
	"fmt"
	"net"
	"time"
)

// seqProbe TCP序列号探测
func (f *Fingerprinter) seqProbe(target string, ports []int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	for _, port := range ports {
		// 连接目标端口
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
		if err != nil {
			continue
		}
		defer conn.Close()

		// 发送探测数据
		probe := []byte{0x00}
		_, err = conn.Write(probe)
		if err != nil {
			continue
		}

		// 读取响应
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		// 记录探测结果
		results = append(results, ProbeResult{
			Type:      "SEQ",
			Target:    target,
			Port:      port,
			Protocol:  "tcp",
			Response:  buf[:n],
			Timestamp: time.Now(),
			Features: map[string]string{
				"seq": fmt.Sprintf("%x", buf[:n]),
			},
		})
	}

	return results, nil
}

// icmpProbe ICMP探测
func (f *Fingerprinter) icmpProbe(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 发送ICMP Echo请求
	conn, err := net.DialTimeout("ip4:icmp", target, f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 构造ICMP Echo请求
	msg := []byte{
		0x08,       // Type: Echo Request
		0x00,       // Code: 0
		0x00, 0x00, // Checksum
		0x00, 0x00, // Identifier
		0x00, 0x00, // Sequence Number
	}

	// 发送请求
	_, err = conn.Write(msg)
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
		Type:      "ICMP",
		Target:    target,
		Protocol:  "icmp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features: map[string]string{
			"icmp": fmt.Sprintf("%x", buf[:n]),
		},
	})

	return results, nil
}

// ecnProbe ECN探测
func (f *Fingerprinter) ecnProbe(target string, ports []int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	for _, port := range ports {
		// 连接目标端口
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
		if err != nil {
			continue
		}
		defer conn.Close()

		// 设置ECN标志
		tcpConn := conn.(*net.TCPConn)
		err = tcpConn.SetReadBuffer(1024)
		if err != nil {
			continue
		}

		// 发送探测数据
		probe := []byte{0x00}
		_, err = conn.Write(probe)
		if err != nil {
			continue
		}

		// 读取响应
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		// 记录探测结果
		results = append(results, ProbeResult{
			Type:      "ECN",
			Target:    target,
			Port:      port,
			Protocol:  "tcp",
			Response:  buf[:n],
			Timestamp: time.Now(),
			Features: map[string]string{
				"ecn": fmt.Sprintf("%x", buf[:n]),
			},
		})
	}

	return results, nil
}

// tcpOptionsProbe TCP选项探测
func (f *Fingerprinter) tcpOptionsProbe(target string, ports []int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	for _, port := range ports {
		// 连接目标端口
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
		if err != nil {
			continue
		}
		defer conn.Close()

		// 发送探测数据
		probe := []byte{0x00}
		_, err = conn.Write(probe)
		if err != nil {
			continue
		}

		// 读取响应
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		// 记录探测结果
		results = append(results, ProbeResult{
			Type:      "TCP_OPTIONS",
			Target:    target,
			Port:      port,
			Protocol:  "tcp",
			Response:  buf[:n],
			Timestamp: time.Now(),
			Features: map[string]string{
				"tcp_options": fmt.Sprintf("%x", buf[:n]),
			},
		})
	}

	return results, nil
}

// udpProbe UDP探测
func (f *Fingerprinter) udpProbe(target string, ports []int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	for _, port := range ports {
		// 连接目标端口
		conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
		if err != nil {
			continue
		}
		defer conn.Close()

		// 发送探测数据
		probe := []byte{0x00}
		_, err = conn.Write(probe)
		if err != nil {
			continue
		}

		// 读取响应
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		// 记录探测结果
		results = append(results, ProbeResult{
			Type:      "UDP",
			Target:    target,
			Port:      port,
			Protocol:  "udp",
			Response:  buf[:n],
			Timestamp: time.Now(),
			Features: map[string]string{
				"udp": fmt.Sprintf("%x", buf[:n]),
			},
		})
	}

	return results, nil
}

// probeFTP 探测FTP服务
func (f *Fingerprinter) probeFTP(target string) ([]ProbeResult, error) {
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
		Features: map[string]string{
			"ftp": string(buf[:n]),
		},
	})

	return results, nil
}

// probeSSH 探测SSH服务
func (f *Fingerprinter) probeSSH(target string) ([]ProbeResult, error) {
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
		Features: map[string]string{
			"ssh": string(buf[:n]),
		},
	})

	return results, nil
}

// probeTelnet 探测Telnet服务
func (f *Fingerprinter) probeTelnet(target string) ([]ProbeResult, error) {
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
		Features: map[string]string{
			"telnet": string(buf[:n]),
		},
	})

	return results, nil
}

// probeSMTP 探测SMTP服务
func (f *Fingerprinter) probeSMTP(target string) ([]ProbeResult, error) {
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
		Features: map[string]string{
			"smtp": string(buf[:n]),
		},
	})

	return results, nil
}

// probeHTTP 探测HTTP服务
func (f *Fingerprinter) probeHTTP(target string, port int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接HTTP服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送HTTP请求
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	_, err = conn.Write([]byte(request))
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
		Type:      "HTTP",
		Target:    target,
		Port:      port,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features: map[string]string{
			"http": string(buf[:n]),
		},
	})

	return results, nil
}

// probeMySQL 探测MySQL服务
func (f *Fingerprinter) probeMySQL(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接MySQL服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3306", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送MySQL握手包
	handshake := []byte{
		0x0a,                         // Protocol version
		0x35, 0x2e, 0x35, 0x2e, 0x35, // Server version
		0x00,                   // Server status
		0x00, 0x00, 0x00, 0x00, // Connection ID
		0x00, // Auth plugin data
		0x00, // Filler
	}

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
		Features: map[string]string{
			"mysql": string(buf[:n]),
		},
	})

	return results, nil
}

// probePostgreSQL 探测PostgreSQL服务
func (f *Fingerprinter) probePostgreSQL(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接PostgreSQL服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:5432", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送PostgreSQL握手包
	handshake := []byte{
		0x00, 0x00, 0x00, 0x08, // Message length
		0x04, 0xd2, 0x16, 0x2f, // Protocol version
	}

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
		Features: map[string]string{
			"postgresql": string(buf[:n]),
		},
	})

	return results, nil
}

// probeRedis 探测Redis服务
func (f *Fingerprinter) probeRedis(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接Redis服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:6379", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送PING命令
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
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
		Type:      "Redis",
		Target:    target,
		Port:      6379,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features: map[string]string{
			"redis": string(buf[:n]),
		},
	})

	return results, nil
}

// probeMongoDB 探测MongoDB服务
func (f *Fingerprinter) probeMongoDB(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接MongoDB服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:27017", target), f.opts.Timeout)
	if err != nil {
		return nil, err
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
		Type:      "MongoDB",
		Target:    target,
		Port:      27017,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features: map[string]string{
			"mongodb": string(buf[:n]),
		},
	})

	return results, nil
}

// probeElasticsearch 探测Elasticsearch服务
func (f *Fingerprinter) probeElasticsearch(target string) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接Elasticsearch服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:9200", target), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送HTTP GET请求
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	_, err = conn.Write([]byte(request))
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
		Type:      "Elasticsearch",
		Target:    target,
		Port:      9200,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features: map[string]string{
			"elasticsearch": string(buf[:n]),
		},
	})

	return results, nil
}

// probeGeneric 通用探测方法
func (f *Fingerprinter) probeGeneric(target string, port int) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0)

	// 连接目标端口
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), f.opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送探测数据
	probe := []byte{0x00}
	_, err = conn.Write(probe)
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
		Type:      "Generic",
		Target:    target,
		Port:      port,
		Protocol:  "tcp",
		Response:  buf[:n],
		Timestamp: time.Now(),
		Features: map[string]string{
			"generic": string(buf[:n]),
		},
	})

	return results, nil
}
