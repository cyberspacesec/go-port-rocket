package scanner

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTCPScan(t *testing.T) {
	// 创建一个本地TCP服务器用于测试
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// 启动服务器
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
	}()

	tests := []struct {
		name     string
		target   string
		ports    []int
		timeout  time.Duration
		workers  int
		wantErr  bool
		wantOpen bool
	}{
		{
			name:     "valid scan open port",
			target:   "127.0.0.1",
			ports:    []int{port},
			timeout:  time.Second,
			workers:  1,
			wantErr:  false,
			wantOpen: true,
		},
		{
			name:     "valid scan closed port",
			target:   "127.0.0.1",
			ports:    []int{port + 1},
			timeout:  time.Second,
			workers:  1,
			wantErr:  false,
			wantOpen: false,
		},
		{
			name:    "invalid target",
			target:  "invalid-host",
			ports:   []int{80},
			timeout: time.Second,
			workers: 1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := TCPScan(tt.target, tt.ports, tt.timeout, tt.workers)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, results, len(tt.ports))

			if tt.wantOpen {
				assert.Equal(t, PortStateOpen, results[0].State)
			} else {
				assert.Equal(t, PortStateClosed, results[0].State)
			}
		})
	}
}

func TestScanPorts(t *testing.T) {
	// 创建一个本地TCP服务器用于测试
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// 启动服务器
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
	}()

	config := &ScanConfig{
		Target:  "127.0.0.1",
		Timeout: time.Second,
		Workers: 1,
		Verbose: true,
	}

	tests := []struct {
		name     string
		ports    []int
		wantOpen bool
	}{
		{
			name:     "scan open port",
			ports:    []int{port},
			wantOpen: true,
		},
		{
			name:     "scan closed port",
			ports:    []int{port + 1},
			wantOpen: false,
		},
		{
			name:     "scan multiple ports",
			ports:    []int{port, port + 1},
			wantOpen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ScanPorts(config, tt.ports)
			assert.Len(t, results, len(tt.ports))

			if tt.wantOpen {
				found := false
				for _, result := range results {
					if result.State == PortStateOpen {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected to find an open port")
			}
		})
	}
}

func TestScanPort(t *testing.T) {
	// 创建一个本地TCP服务器用于测试
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// 启动服务器
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
	}()

	tests := []struct {
		name     string
		target   string
		port     int
		timeout  time.Duration
		wantOpen bool
	}{
		{
			name:     "scan open port",
			target:   "127.0.0.1",
			port:     port,
			timeout:  time.Second,
			wantOpen: true,
		},
		{
			name:     "scan closed port",
			target:   "127.0.0.1",
			port:     port + 1,
			timeout:  time.Second,
			wantOpen: false,
		},
		{
			name:     "scan with short timeout",
			target:   "127.0.0.1",
			port:     port,
			timeout:  time.Nanosecond,
			wantOpen: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanPort(tt.target, tt.port, tt.timeout)
			if tt.wantOpen {
				assert.Equal(t, PortStateOpen, result.State)
				assert.True(t, result.Open)
				assert.NotEmpty(t, result.ServiceName)
			} else {
				assert.Equal(t, PortStateClosed, result.State)
				assert.False(t, result.Open)
			}
		})
	}
}

func TestCommonServices(t *testing.T) {
	tests := []struct {
		port    int
		service string
	}{
		{80, "HTTP"},
		{443, "HTTPS"},
		{22, "SSH"},
		{21, "FTP"},
		{25, "SMTP"},
		{53, "DNS"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{9999, ""}, // 不存在的端口
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("port_%d", tt.port), func(t *testing.T) {
			service, exists := CommonServices[tt.port]
			if tt.service == "" {
				assert.False(t, exists)
			} else {
				assert.True(t, exists)
				assert.Equal(t, tt.service, service)
			}
		})
	}
}
