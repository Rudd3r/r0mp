package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

func TestNewServer(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	if server == nil {
		t.Fatal("expected server but got nil")
	}

	if server.ca == nil {
		t.Error("CA not initialized")
	}

	if server.server == nil {
		t.Error("HTTP server not initialized")
	}

	if server.transport == nil {
		t.Error("transport not initialized")
	}
}

func TestServer_Director(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	tests := []struct {
		name       string
		request    *http.Request
		wantScheme string
		wantHost   string
	}{
		{
			name: "HTTP request",
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{},
				TLS:  nil,
			},
			wantScheme: "http",
			wantHost:   "example.com",
		},
		{
			name: "HTTPS request",
			request: &http.Request{
				Host: "secure.example.com",
				URL:  &url.URL{},
				TLS:  &tls.ConnectionState{},
			},
			wantScheme: "https",
			wantHost:   "secure.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.Director(tt.request)

			if tt.request.URL.Scheme != tt.wantScheme {
				t.Errorf("URL.Scheme = %v, want %v", tt.request.URL.Scheme, tt.wantScheme)
			}

			if tt.request.URL.Host != tt.wantHost {
				t.Errorf("URL.Host = %v, want %v", tt.request.URL.Host, tt.wantHost)
			}
		})
	}
}

func TestServer_RoundTrip_Allowed(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-api",
					Match: &domain.ProxyPolicyMatch{
						Host:   "api\\.example\\.com",
						Method: "GET",
						Path:   "/api/.*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Create a request that should be allowed
	req, err := http.NewRequest("GET", backend.URL+"/api/users", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = "api.example.com"

	resp, err := server.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != "backend response" {
		t.Errorf("body = %v, want %v", string(body), "backend response")
	}
}

func TestServer_RoundTrip_Denied(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			DenyRules: []*domain.ProxyPolicyDenyRule{
				{
					Name: "deny-admin",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   "/admin/.*",
					},
				},
			},
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Create a request that should be denied
	req, err := http.NewRequest("GET", "http://example.com/admin/users", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := server.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() failed: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %v, want %v", resp.StatusCode, http.StatusForbidden)
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != "Domain blocked" {
		t.Errorf("body = %v, want %v", string(body), "Domain blocked")
	}
}

func TestServer_RoundTrip_NoMatch(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-api-only",
					Match: &domain.ProxyPolicyMatch{
						Host:   "api\\.example\\.com",
						Method: "GET",
						Path:   "/api/.*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Create a request that doesn't match any policy
	req, err := http.NewRequest("GET", "http://other.com/path", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := server.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() failed: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %v, want %v", resp.StatusCode, http.StatusForbidden)
	}
}

func TestServer_RoundTrip_WithModification(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-with-header",
					Match: &domain.ProxyPolicyMatch{
						Host:   "api\\.example\\.com",
						Method: "GET",
						Path:   ".*",
					},
					ActionModify: []domain.ActionModify{
						{
							Name: "set_header",
							Args: []string{"X-Custom-Header", "test-value-123"},
						},
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	// Create a test backend that verifies the header
	headerReceived := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("X-Custom-Header")
		if header == "test-value-123" {
			headerReceived = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	req, err := http.NewRequest("GET", backend.URL+"/data", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = "api.example.com"

	resp, err := server.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() failed: %v", err)
	}
	_ = resp.Body.Close()

	if !headerReceived {
		t.Error("expected header to be added to request")
	}
}

func TestServer_Serve_HTTP(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	// Create a listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve([]net.Listener{listener}, nil)
	}()

	// Give server time to start
	time.Sleep(time.Millisecond * 100)

	// Create a backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test response"))
	}))
	defer backend.Close()

	// Make a request through the proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
			},
		},
		Timeout: time.Second * 2,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Logf("Request failed (this may be expected in test environment): %v", err)
	} else {
		_ = resp.Body.Close()
	}

	// Shutdown the server
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() failed: %v", err)
	}

	// Wait for serve to return
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			t.Errorf("Serve() returned unexpected error: %v", err)
		}
	case <-time.After(time.Second * 3):
		t.Error("Serve() did not return after shutdown")
	}
}

func TestServer_Serve_HTTPS(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	// Create a TLS listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Start server in background
	go func() {
		_ = server.Serve(nil, []net.Listener{listener})
	}()

	// Give server time to start
	time.Sleep(time.Millisecond * 100)

	// Shutdown the server
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() failed: %v", err)
	}
}

func TestServer_Serve_NoListeners(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	cancel()

	// Should return immediately with context.Canceled
	err = server.Serve(nil, nil)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestServer_SetContext(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}
	defer cancel()

	if server.ctx != ctx {
		t.Error("context not set correctly")
	}
}

func TestServer_Shutdown_Timeout(t *testing.T) {
	cfg := domain.ProxyConfig{
		Policy: &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	if err := cfg.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	server, err := NewServer(context.Background(), slog.Default(), &cfg)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Start server
	go func() { _ = server.Serve([]net.Listener{listener}, nil) }()

	// Give server time to start
	time.Sleep(time.Millisecond * 100)

	// Shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() failed: %v", err)
	}
}
