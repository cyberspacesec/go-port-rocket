package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:    "single port",
			input:   "80",
			want:    []int{80},
			wantErr: false,
		},
		{
			name:    "port range",
			input:   "80-82",
			want:    []int{80, 81, 82},
			wantErr: false,
		},
		{
			name:    "multiple ports",
			input:   "80,443,8080",
			want:    []int{80, 443, 8080},
			wantErr: false,
		},
		{
			name:    "mixed format",
			input:   "80-82,443,8080-8081",
			want:    []int{80, 81, 82, 443, 8080, 8081},
			wantErr: false,
		},
		{
			name:    "invalid port",
			input:   "abc",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range format",
			input:   "80-",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range order",
			input:   "82-80",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "port out of range",
			input:   "0",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "port too large",
			input:   "65536",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "range with spaces",
			input:   "80 - 82",
			want:    []int{80, 81, 82},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRange(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantIP  bool
		wantErr bool
	}{
		{
			name:    "valid IP",
			host:    "127.0.0.1",
			wantIP:  true,
			wantErr: false,
		},
		{
			name:    "localhost",
			host:    "localhost",
			wantIP:  true,
			wantErr: false,
		},
		{
			name:    "invalid host",
			host:    "invalid.host.name",
			wantIP:  false,
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    "",
			wantIP:  false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveHost(tt.host)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tt.wantIP {
				assert.NotEmpty(t, got)
			}
		})
	}
}
