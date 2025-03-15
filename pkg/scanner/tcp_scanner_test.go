package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewTCPScanner(t *testing.T) {
	scanner := NewTCPScanner()
	assert.NotNil(t, scanner)
	assert.NotNil(t, scanner.baseScanner)
	assert.Equal(t, ScanTypeTCP, scanner.baseScanner.scanType)
}

func TestTCPScanner_RequiresRoot(t *testing.T) {
	scanner := NewTCPScanner()
	assert.False(t, scanner.RequiresRoot())
}

func TestTCPScanner_ValidateOptions(t *testing.T) {
	scanner := NewTCPScanner()

	tests := []struct {
		name    string
		opts    *ScanOptions
		wantErr bool
	}{
		{
			name:    "nil options",
			opts:    nil,
			wantErr: true,
		},
		{
			name: "empty target",
			opts: &ScanOptions{
				Target:  "",
				Ports:   []int{80},
				Timeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "empty ports",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   []int{},
				Timeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "valid options",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   []int{80},
				Timeout: time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.ValidateOptions(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTCPScanner_scanPort(t *testing.T) {
	scanner := NewTCPScanner()
	scanner.opts = &ScanOptions{
		Target:  "127.0.0.1",
		Timeout: time.Second,
	}

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
		port     int
		wantOpen bool
	}{
		{
			name:     "open port",
			port:     port,
			wantOpen: true,
		},
		{
			name:     "closed port",
			port:     port + 1,
			wantOpen: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := scanner.scanPort(context.Background(), tt.port)
			if tt.wantOpen {
				assert.NoError(t, err)
				assert.Equal(t, PortStateOpen, result.State)
				assert.True(t, result.Open)
				if serviceName, ok := CommonServices[tt.port]; ok {
					assert.Equal(t, serviceName, result.ServiceName)
				}
			} else {
				if err == nil {
					assert.Equal(t, PortStateClosed, result.State)
					assert.False(t, result.Open)
				}
			}
		})
	}
}

func TestTCPScanner_Scan(t *testing.T) {
	scanner := NewTCPScanner()

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
		opts     *ScanOptions
		wantErr  bool
		wantOpen bool
	}{
		{
			name: "valid scan open port",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   []int{port},
				Timeout: time.Second,
				Workers: 1,
			},
			wantErr:  false,
			wantOpen: true,
		},
		{
			name: "valid scan closed port",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   []int{port + 1},
				Timeout: time.Second,
				Workers: 1,
			},
			wantErr:  false,
			wantOpen: false,
		},
		{
			name: "invalid target",
			opts: &ScanOptions{
				Target:  "invalid-host",
				Ports:   []int{80},
				Timeout: time.Second,
				Workers: 1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := scanner.Scan(context.Background(), tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, results, len(tt.opts.Ports))

			if tt.wantOpen {
				assert.Equal(t, PortStateOpen, results[0].State)
				assert.True(t, results[0].Open)
			} else {
				assert.Equal(t, PortStateClosed, results[0].State)
				assert.False(t, results[0].Open)
			}
		})
	}
}
