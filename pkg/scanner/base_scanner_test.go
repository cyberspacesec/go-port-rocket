package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockScanner struct {
	*baseScanner
	scanPortFunc func(ctx context.Context, port int) (ScanResult, error)
}

func newMockScanner() *mockScanner {
	return &mockScanner{
		baseScanner: newBaseScanner(ScanTypeTCP),
	}
}

func (s *mockScanner) scanPort(ctx context.Context, port int) (ScanResult, error) {
	if s.scanPortFunc != nil {
		return s.scanPortFunc(ctx, port)
	}
	return ScanResult{}, nil
}

func TestNewBaseScanner(t *testing.T) {
	scanner := newBaseScanner(ScanTypeTCP)
	assert.NotNil(t, scanner)
	assert.Equal(t, ScanTypeTCP, scanner.scanType)
	assert.NotNil(t, scanner.stats)
}

func TestBaseScanner_ValidateOptions(t *testing.T) {
	scanner := newBaseScanner(ScanTypeTCP)

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
				Ports:   "80",
				Timeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "empty ports",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   "",
				Timeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   "80",
				Timeout: 0,
			},
			wantErr: false, // Should set default timeout
		},
		{
			name: "zero workers",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   "80",
				Timeout: time.Second,
				Workers: 0,
			},
			wantErr: false, // Should set default workers
		},
		{
			name: "valid options",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   "80",
				Timeout: time.Second,
				Workers: 10,
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
				if tt.opts.Timeout == 0 {
					assert.Equal(t, time.Second*5, tt.opts.Timeout)
				}
				if tt.opts.Workers == 0 {
					assert.Equal(t, 100, tt.opts.Workers)
				}
			}
		})
	}
}

func TestBaseScanner_Scan(t *testing.T) {
	scanner := newMockScanner()

	tests := []struct {
		name      string
		opts      *ScanOptions
		mockFunc  func(ctx context.Context, port int) (ScanResult, error)
		wantState PortState
		wantErr   bool
	}{
		{
			name: "successful scan",
			opts: &ScanOptions{
				Target:  "127.0.0.1",
				Ports:   "80",
				Timeout: time.Second,
				Workers: 1,
			},
			mockFunc: func(ctx context.Context, port int) (ScanResult, error) {
				return ScanResult{
					Port:  port,
					State: PortStateOpen,
					Open:  true,
				}, nil
			},
			wantState: PortStateOpen,
			wantErr:   false,
		},
		{
			name: "scan with invalid options",
			opts: nil,
			mockFunc: func(ctx context.Context, port int) (ScanResult, error) {
				return ScanResult{}, nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner.scanPortFunc = tt.mockFunc
			results, err := scanner.Scan(context.Background(), tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, results, len(tt.opts.Ports))
			assert.Equal(t, tt.wantState, results[0].State)
		})
	}
}

func TestBaseScanner_RequiresRoot(t *testing.T) {
	scanner := newBaseScanner(ScanTypeTCP)
	assert.False(t, scanner.RequiresRoot())
}

func TestBaseScanner_GetStats(t *testing.T) {
	scanner := newBaseScanner(ScanTypeTCP)
	stats := scanner.GetStats()
	assert.NotNil(t, stats)
	assert.False(t, stats.StartTime.IsZero())
}

func TestBaseScanner_updateStats(t *testing.T) {
	scanner := newBaseScanner(ScanTypeTCP)
	scanner.opts = &ScanOptions{
		Target: "127.0.0.1",
	}

	tests := []struct {
		name     string
		result   ScanResult
		wantOpen int
	}{
		{
			name: "open port",
			result: ScanResult{
				Port:  80,
				State: PortStateOpen,
			},
			wantOpen: 1,
		},
		{
			name: "closed port",
			result: ScanResult{
				Port:  81,
				State: PortStateClosed,
			},
			wantOpen: 0,
		},
		{
			name: "filtered port",
			result: ScanResult{
				Port:  82,
				State: PortStateFiltered,
			},
			wantOpen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner.updateStats(tt.result)
			stats := scanner.GetStats()
			assert.Equal(t, tt.wantOpen, stats.OpenPorts)
		})
	}
}
