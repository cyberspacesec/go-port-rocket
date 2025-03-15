package scanner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScanType_String(t *testing.T) {
	tests := []struct {
		name string
		st   ScanType
		want string
	}{
		{"TCP", ScanTypeTCP, "tcp"},
		{"SYN", ScanTypeSYN, "syn"},
		{"FIN", ScanTypeFIN, "fin"},
		{"NULL", ScanTypeNULL, "null"},
		{"XMAS", ScanTypeXMAS, "xmas"},
		{"ACK", ScanTypeACK, "ack"},
		{"UDP", ScanTypeUDP, "udp"},
		{"MAIMON", ScanTypeMAIMON, "maimon"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.st))
		})
	}
}

func TestPortState_String(t *testing.T) {
	tests := []struct {
		name string
		ps   PortState
		want string
	}{
		{"Open", PortStateOpen, "open"},
		{"Closed", PortStateClosed, "closed"},
		{"Filtered", PortStateFiltered, "filtered"},
		{"Unknown", PortStateUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.ps))
		})
	}
}

func TestConvertRawToScanResult(t *testing.T) {
	raw := RawScanResult{
		Port:    80,
		State:   PortStateOpen,
		TTL:     64,
		OS:      "Linux",
		Banner:  "Apache",
		Service: "HTTP",
		Version: "2.4.41",
		TCPSeq:  12345,
		TCPAck:  67890,
		Flags:   0x02,
		Type:    ScanTypeSYN,
	}

	result := ConvertRawToScanResult(raw)

	assert.Equal(t, raw.Port, result.Port)
	assert.Equal(t, raw.State, result.State)
	assert.Equal(t, raw.Service, result.Service)
	assert.Equal(t, raw.Version, result.Version)
	assert.Equal(t, raw.Banner, result.Banner)
	assert.Equal(t, raw.TTL, result.TTL)
	assert.Equal(t, raw.OS, result.OS)
}

func TestConvertRawToScanResults(t *testing.T) {
	raws := []RawScanResult{
		{
			Port:    80,
			State:   PortStateOpen,
			Service: "HTTP",
		},
		{
			Port:    443,
			State:   PortStateClosed,
			Service: "HTTPS",
		},
	}

	results := ConvertRawToScanResults(raws)

	assert.Len(t, results, len(raws))
	for i, result := range results {
		assert.Equal(t, raws[i].Port, result.Port)
		assert.Equal(t, raws[i].State, result.State)
		assert.Equal(t, raws[i].Service, result.Service)
	}
}

func TestNewScanOptions(t *testing.T) {
	target := "example.com"
	ports := []int{80, 443}
	scanType := ScanTypeTCP

	opts := NewScanOptions(target, ports, scanType)

	assert.NotNil(t, opts)
	assert.Equal(t, target, opts.Target)
	assert.Equal(t, ports, opts.Ports)
	assert.Equal(t, scanType, opts.ScanType)
	assert.Equal(t, time.Second*5, opts.Timeout)
	assert.Equal(t, 100, opts.Workers)
	assert.Equal(t, 1000, opts.RateLimit)
	assert.Equal(t, 3, opts.Retries)
	assert.False(t, opts.Verbose)
	assert.True(t, opts.ServiceProbe)
	assert.True(t, opts.OSProbe)
	assert.True(t, opts.BannerProbe)
}

func TestNewScanStats(t *testing.T) {
	stats := NewScanStats()

	assert.NotNil(t, stats)
	assert.False(t, stats.StartTime.IsZero())
	assert.True(t, stats.EndTime.IsZero())
	assert.Equal(t, 0, stats.TotalPorts)
	assert.Equal(t, 0, stats.OpenPorts)
	assert.Equal(t, 0, stats.ClosedPorts)
	assert.Equal(t, 0, stats.FilteredPorts)
	assert.Equal(t, 0, stats.Errors)
	assert.Equal(t, float64(0), stats.ScanRate)
}

func TestScanStats_UpdateStats(t *testing.T) {
	stats := &ScanStats{
		StartTime:  time.Now().Add(-time.Second),
		TotalPorts: 100,
	}

	stats.UpdateStats()

	assert.False(t, stats.EndTime.IsZero())
	assert.Greater(t, stats.ScanRate, float64(0))
}

func TestServiceInfo(t *testing.T) {
	info := &ServiceInfo{
		Name:        "HTTP",
		Version:     "2.4.41",
		Product:     "Apache",
		ExtraInfo:   "Unix",
		FullBanner:  "Apache/2.4.41 (Unix)",
		Fingerprint: "apache24",
		Port:        80,
	}

	assert.Equal(t, "HTTP", info.Name)
	assert.Equal(t, "2.4.41", info.Version)
	assert.Equal(t, "Apache", info.Product)
	assert.Equal(t, "Unix", info.ExtraInfo)
	assert.Equal(t, "Apache/2.4.41 (Unix)", info.FullBanner)
	assert.Equal(t, "apache24", info.Fingerprint)
	assert.Equal(t, 80, info.Port)
}

func TestOSInfo(t *testing.T) {
	info := &OSInfo{
		Name:    "Linux",
		Version: "5.4.0",
		TTL:     64,
	}

	assert.Equal(t, "Linux", info.Name)
	assert.Equal(t, "5.4.0", info.Version)
	assert.Equal(t, 64, info.TTL)
}

func TestScanError(t *testing.T) {
	port := 80
	err := assert.AnError
	scanErr := &ScanError{
		Port:  port,
		Error: err,
	}

	assert.Equal(t, port, scanErr.Port)
	assert.Equal(t, err, scanErr.Error)
}
