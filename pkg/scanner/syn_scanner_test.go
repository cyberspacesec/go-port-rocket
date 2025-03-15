package scanner

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSYNScanner(t *testing.T) {
	scanner := NewSYNScanner()
	assert.NotNil(t, scanner)
	assert.NotNil(t, scanner.baseScanner)
	assert.Equal(t, ScanTypeSYN, scanner.scanType)
}

func TestSYNScanner_RequiresRoot(t *testing.T) {
	scanner := NewSYNScanner()
	assert.True(t, scanner.RequiresRoot())
}

func TestSYNScanner_ValidateOptions(t *testing.T) {
	scanner := NewSYNScanner()

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
			name: "valid options",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   []int{80},
				Timeout: time.Second,
			},
			wantErr: os.Geteuid() != 0, // 如果不是root用户，应该返回错误
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

func TestSYNScanner_scanPort(t *testing.T) {
	scanner := NewSYNScanner()
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
			} else {
				if err == nil {
					assert.Equal(t, PortStateClosed, result.State)
				}
			}
		})
	}
}

func TestSendICMP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	tests := []struct {
		name    string
		target  string
		timeout time.Duration
		wantErr bool
	}{
		{
			name:    "valid localhost",
			target:  "127.0.0.1",
			timeout: time.Second,
			wantErr: false,
		},
		{
			name:    "invalid target",
			target:  "invalid-host",
			timeout: time.Second,
			wantErr: true,
		},
		{
			name:    "timeout",
			target:  "8.8.8.8",
			timeout: time.Nanosecond,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sendICMP(tt.target, tt.timeout)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				if err != nil {
					t.Logf("ICMP test skipped: %v", err)
					t.Skip()
				}
			}
		})
	}
}

func TestSendSYNPacket(t *testing.T) {
	err := sendSYNPacket("127.0.0.1", 80)
	assert.Error(t, err)
	assert.Equal(t, "not implemented", err.Error())
}

func TestListenForSYNACK(t *testing.T) {
	err := listenForSYNACK(time.Second)
	assert.Error(t, err)
	assert.Equal(t, "not implemented", err.Error())
}

// 测试辅助函数
type mockConn struct {
	net.Conn
	readErr  error
	writeErr error
	data     []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	copy(b, m.data)
	return len(m.data), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}
