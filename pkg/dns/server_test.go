package dns

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_WildcardMatching(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tests := []struct {
		name     string
		mappings []domain.DNSMapping
		query    string
		expected net.IP
	}{
		{
			name: "exact match",
			mappings: []domain.DNSMapping{
				{Pattern: "example.com", IP: net.ParseIP("1.2.3.4")},
			},
			query:    "example.com",
			expected: net.ParseIP("1.2.3.4"),
		},
		{
			name: "wildcard subdomain match",
			mappings: []domain.DNSMapping{
				{Pattern: "*.google.com", IP: net.ParseIP("8.8.8.8")},
			},
			query:    "mail.google.com",
			expected: net.ParseIP("8.8.8.8"),
		},
		{
			name: "wildcard subdomain no match for nested",
			mappings: []domain.DNSMapping{
				{Pattern: "*.google.com", IP: net.ParseIP("8.8.8.8")},
			},
			query:    "deep.mail.google.com",
			expected: nil,
		},
		{
			name: "wildcard TLD match",
			mappings: []domain.DNSMapping{
				{Pattern: "*.com", IP: net.ParseIP("10.0.0.1")},
			},
			query:    "example.com",
			expected: net.ParseIP("10.0.0.1"),
		},
		{
			name: "wildcard all domains",
			mappings: []domain.DNSMapping{
				{Pattern: "*", IP: net.ParseIP("127.0.0.1")},
			},
			query:    "anything.example.com",
			expected: net.ParseIP("127.0.0.1"),
		},
		{
			name: "priority: exact over wildcard",
			mappings: []domain.DNSMapping{
				{Pattern: "*.google.com", IP: net.ParseIP("8.8.8.8")},
				{Pattern: "mail.google.com", IP: net.ParseIP("1.1.1.1")},
			},
			query:    "mail.google.com",
			expected: net.ParseIP("1.1.1.1"),
		},
		{
			name: "no match",
			mappings: []domain.DNSMapping{
				{Pattern: "example.com", IP: net.ParseIP("1.2.3.4")},
			},
			query:    "other.com",
			expected: nil,
		},
		{
			name: "case insensitive match",
			mappings: []domain.DNSMapping{
				{Pattern: "Example.Com", IP: net.ParseIP("1.2.3.4")},
			},
			query:    "example.com",
			expected: net.ParseIP("1.2.3.4"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(ctx, log, "127.0.0.1:0", tt.mappings)
			result := server.matchDomain(tt.query)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected.String(), result.String())
			}
		})
	}
}

func TestServer_QueryResponse(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mappings := []domain.DNSMapping{
		{Pattern: "example.com", IP: net.ParseIP("1.2.3.4")},
		{Pattern: "*.google.com", IP: net.ParseIP("8.8.8.8")},
		{Pattern: "ipv6.test", IP: net.ParseIP("2001:db8::1")},
		{Pattern: "*", IP: net.ParseIP("127.0.0.1")},
	}

	server := NewServer(ctx, log, "127.0.0.1:0", mappings)

	go func() {
		err := server.Start()
		if err != nil && ctx.Err() == nil {
			t.Logf("DNS server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	localAddr := server.server.PacketConn.LocalAddr().(*net.UDPAddr).String()
	t.Logf("DNS server listening on %s", localAddr)

	tests := []struct {
		name       string
		domain     string
		qType      uint16
		expectIP   net.IP
		expectCode int
	}{
		{
			name:       "A record for exact match",
			domain:     "example.com",
			qType:      dns.TypeA,
			expectIP:   net.ParseIP("1.2.3.4"),
			expectCode: dns.RcodeSuccess,
		},
		{
			name:       "A record for wildcard match",
			domain:     "mail.google.com",
			qType:      dns.TypeA,
			expectIP:   net.ParseIP("8.8.8.8"),
			expectCode: dns.RcodeSuccess,
		},
		{
			name:       "A record for catch-all wildcard",
			domain:     "unknown.domain",
			qType:      dns.TypeA,
			expectIP:   net.ParseIP("127.0.0.1"),
			expectCode: dns.RcodeSuccess,
		},
		{
			name:       "AAAA record for IPv6",
			domain:     "ipv6.test",
			qType:      dns.TypeAAAA,
			expectIP:   net.ParseIP("2001:db8::1"),
			expectCode: dns.RcodeSuccess,
		},
	}

	c := new(dns.Client)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(tt.domain), tt.qType)

			r, _, err := c.Exchange(m, localAddr)
			require.NoError(t, err)
			require.NotNil(t, r)

			assert.Equal(t, tt.expectCode, r.Rcode, "response code mismatch")

			if r.Rcode == dns.RcodeSuccess && tt.expectIP != nil {
				require.Len(t, r.Answer, 1, "expected 1 answer")

				var gotIP net.IP
				switch rr := r.Answer[0].(type) {
				case *dns.A:
					gotIP = rr.A
				case *dns.AAAA:
					gotIP = rr.AAAA
				default:
					t.Fatalf("unexpected answer type: %T", rr)
				}

				assert.Equal(t, tt.expectIP.String(), gotIP.String(), "IP address mismatch")
			}
		})
	}
}

func TestServer_StartStop(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	mappings := []domain.DNSMapping{
		{Pattern: "test.com", IP: net.ParseIP("1.2.3.4")},
	}

	server := NewServer(ctx, log, "127.0.0.1:0", mappings)

	done := make(chan error, 1)
	go func() {
		done <- server.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	server.Stop()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not stop in time")
	}
}
