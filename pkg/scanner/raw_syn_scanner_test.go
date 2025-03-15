package scanner

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRawSYNScan(t *testing.T) {
	if !isRoot() {
		t.Skip("Skipping test that requires root privileges")
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
			results, err := RawSYNScan(tt.target, tt.ports, tt.timeout, tt.workers)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, results, len(tt.ports))

			if tt.wantOpen {
				assert.Equal(t, "open", results[0].State)
			} else {
				assert.Equal(t, "closed", results[0].State)
			}
		})
	}
}

func TestCalculateTCPChecksum(t *testing.T) {
	tests := []struct {
		name      string
		tcpHeader []byte
		srcIP     net.IP
		dstIP     net.IP
		tcpLength uint16
		want      uint16
	}{
		{
			name:      "empty header",
			tcpHeader: make([]byte, 20),
			srcIP:     net.ParseIP("127.0.0.1"),
			dstIP:     net.ParseIP("127.0.0.1"),
			tcpLength: 20,
			want:      0xffff,
		},
		{
			name: "SYN packet",
			tcpHeader: []byte{
				0x00, 0x50, // Source port (80)
				0x00, 0x50, // Destination port (80)
				0x00, 0x00, 0x00, 0x00, // Sequence number
				0x00, 0x00, 0x00, 0x00, // Acknowledgment number
				0x50, 0x02, // Data offset, reserved, flags (SYN)
				0xff, 0xff, // Window size
				0x00, 0x00, // Checksum
				0x00, 0x00, // Urgent pointer
			},
			srcIP:     net.ParseIP("192.168.1.1"),
			dstIP:     net.ParseIP("192.168.1.2"),
			tcpLength: 20,
			want:      0x442e,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateTCPChecksum(tt.tcpHeader, tt.srcIP, tt.dstIP, tt.tcpLength)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildSYNPacket(t *testing.T) {
	srcPort := uint16(12345)
	dstPort := uint16(80)
	dstIP := net.ParseIP("192.168.1.1")

	packet := buildSYNPacket(srcPort, dstPort, dstIP)

	// 验证包长度
	assert.Equal(t, 40, len(packet))

	// 验证IP头部
	assert.Equal(t, byte(0x45), packet[0]) // 版本(4) + 头部长度(5)
	assert.Equal(t, byte(0x00), packet[1]) // 服务类型
	assert.Equal(t, byte(0x00), packet[2]) // 总长度高字节
	assert.Equal(t, byte(0x28), packet[3]) // 总长度低字节 (40)
	assert.Equal(t, byte(0x40), packet[6]) // 不分片标志
	assert.Equal(t, byte(0x40), packet[8]) // TTL
	assert.Equal(t, byte(0x06), packet[9]) // 协议 (TCP)

	// 验证TCP头部
	assert.Equal(t, byte(0x50), packet[32]) // 数据偏移
	assert.Equal(t, byte(0x02), packet[33]) // SYN标志
	assert.Equal(t, byte(0xff), packet[34]) // 窗口大小高字节
	assert.Equal(t, byte(0xff), packet[35]) // 窗口大小低字节
}

func TestGetSrcIP(t *testing.T) {
	tests := []struct {
		name    string
		dstIP   net.IP
		wantLen int
	}{
		{
			name:    "valid IPv4",
			dstIP:   net.ParseIP("8.8.8.8"),
			wantLen: net.IPv4len,
		},
		{
			name:    "localhost",
			dstIP:   net.ParseIP("127.0.0.1"),
			wantLen: net.IPv4len,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getSrcIP(tt.dstIP)
			assert.NotNil(t, got)
			assert.Equal(t, tt.wantLen, len(got.To4()))
		})
	}
}

// 辅助函数
func isRoot() bool {
	return os.Geteuid() == 0
}
