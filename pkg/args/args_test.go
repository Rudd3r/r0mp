package args

import (
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIngressProxyPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    domain.IngressProxyPort
		wantErr bool
	}{
		{
			name:  "full specification with policy and https",
			input: "mypolicy@https://0.0.0.0:8080-80",
			want: domain.IngressProxyPort{
				PolicyName: "mypolicy",
				Scheme:     "https",
				HostIP:     "0.0.0.0",
				HostPort:   8080,
				GuestPort:  80,
			},
			wantErr: false,
		},
		{
			name:  "https without policy",
			input: "https://localhost:8443-443",
			want: domain.IngressProxyPort{
				PolicyName: "allow_all",
				Scheme:     "https",
				HostIP:     "127.0.0.1",
				HostPort:   8443,
				GuestPort:  443,
			},
			wantErr: false,
		},
		{
			name:  "explicit host IP",
			input: "0.0.0.0:8080-80",
			want: domain.IngressProxyPort{
				PolicyName: "allow_all",
				Scheme:     "http",
				HostIP:     "0.0.0.0",
				HostPort:   8080,
				GuestPort:  80,
			},
			wantErr: false,
		},
		{
			name:  "simple localhost mapping",
			input: "127.0.0.1:3000-3000",
			want: domain.IngressProxyPort{
				PolicyName: "allow_all",
				Scheme:     "http",
				HostIP:     "127.0.0.1",
				HostPort:   3000,
				GuestPort:  3000,
			},
			wantErr: false,
		},
		{
			name:  "policy without scheme",
			input: "custom@192.168.1.1:9000-8000",
			want: domain.IngressProxyPort{
				PolicyName: "custom",
				Scheme:     "http",
				HostIP:     "192.168.1.1",
				HostPort:   9000,
				GuestPort:  8000,
			},
			wantErr: false,
		},
		{
			name:  "minimal - just ports (defaults to 0.0.0.0)",
			input: "8080-80",
			want: domain.IngressProxyPort{
				PolicyName: "allow_all",
				Scheme:     "http",
				HostIP:     "0.0.0.0",
				HostPort:   8080,
				GuestPort:  80,
			},
			wantErr: false,
		},
		{
			name:  "https without host IP",
			input: "https://8443-443",
			want: domain.IngressProxyPort{
				PolicyName: "allow_all",
				Scheme:     "https",
				HostIP:     "0.0.0.0",
				HostPort:   8443,
				GuestPort:  443,
			},
			wantErr: false,
		},
		{
			name:  "policy without host IP",
			input: "strict@9000-8000",
			want: domain.IngressProxyPort{
				PolicyName: "strict",
				Scheme:     "http",
				HostIP:     "0.0.0.0",
				HostPort:   9000,
				GuestPort:  8000,
			},
			wantErr: false,
		},
		{
			name:  "policy and https without host IP",
			input: "api@https://443-3000",
			want: domain.IngressProxyPort{
				PolicyName: "api",
				Scheme:     "https",
				HostIP:     "0.0.0.0",
				HostPort:   443,
				GuestPort:  3000,
			},
			wantErr: false,
		},
		{
			name:    "invalid - missing dash separator",
			input:   "0.0.0.0:8080:80",
			wantErr: true,
		},
		{
			name:    "invalid - bad scheme",
			input:   "ftp://0.0.0.0:8080-80",
			wantErr: true,
		},
		{
			name:    "invalid - bad host IP",
			input:   "999.999.999.999:8080-80",
			wantErr: true,
		},
		{
			name:    "invalid - bad host port with IP",
			input:   "0.0.0.0:99999-80",
			wantErr: true,
		},
		{
			name:    "invalid - bad host port without IP",
			input:   "99999-80",
			wantErr: true,
		},
		{
			name:    "invalid - bad guest port",
			input:   "0.0.0.0:8080-99999",
			wantErr: true,
		},
		{
			name:    "invalid - only one number",
			input:   "8080",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIngressProxyPort(tt.input)
			
			if tt.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				return
			}
			
			require.NoError(t, err, "Unexpected error")
			assert.Equal(t, tt.want.PolicyName, got.PolicyName, "PolicyName mismatch")
			assert.Equal(t, tt.want.Scheme, got.Scheme, "Scheme mismatch")
			assert.Equal(t, tt.want.HostIP, got.HostIP, "HostIP mismatch")
			assert.Equal(t, tt.want.HostPort, got.HostPort, "HostPort mismatch")
			assert.Equal(t, tt.want.GuestPort, got.GuestPort, "GuestPort mismatch")
		})
	}
}
