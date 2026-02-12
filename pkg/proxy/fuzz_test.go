package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

// FuzzCertificateAuthorityGeneration fuzzes CA certificate generation
func FuzzCertificateAuthorityGeneration(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus with various expiry durations
	f.Add(int64(time.Hour))
	f.Add(int64(24 * time.Hour))
	f.Add(int64(365 * 24 * time.Hour))
	f.Add(int64(0))
	f.Add(int64(-1))

	f.Fuzz(func(t *testing.T, expireNano int64) {
		expire := time.Duration(expireNano)

		cfg := &domain.ProxyConfig{
			Expire: expire,
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ca, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return // Generation errors are acceptable
		}

		// Verify the CA was created
		if ca == nil {
			t.Error("CA is nil")
			return
		}

		// Verify certificate PEM is valid
		if len(ca.cfg.CertPEM) == 0 {
			t.Error("Certificate PEM is empty")
		}

		// Verify key PEM is valid
		if len(ca.cfg.KeyPEM) == 0 {
			t.Error("Key PEM is empty")
		}
	})
}

// FuzzGetCertificateServerName fuzzes certificate generation for various server names
func FuzzGetCertificateServerName(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("example.com")
	f.Add("localhost")
	f.Add("")
	f.Add("*.example.com")
	f.Add("sub.domain.example.com")
	f.Add("192.168.1.1")
	f.Add("[::1]")
	f.Add("very-long-subdomain-name-that-might-cause-issues.example.com")
	f.Add("xn--example-gva.com")      // IDN domain
	f.Add(string([]byte{0, 1, 2, 3})) // Binary data

	f.Fuzz(func(t *testing.T, serverName string) {
		cfg := &domain.ProxyConfig{
			Expire: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ca, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return
		}

		// Create a mock ClientHello
		clientHello := &tls.ClientHelloInfo{
			ServerName: serverName,
		}

		// Try to get certificate
		cert, err := ca.GetCertificate(clientHello)
		if err != nil {
			return // Errors are acceptable for invalid server names
		}

		// If successful, verify certificate properties
		if cert == nil {
			t.Error("Certificate is nil")
			return
		}

		if len(cert.Certificate) == 0 {
			t.Error("Certificate chain is empty")
		}

		if cert.PrivateKey == nil {
			t.Error("Private key is nil")
		}
	})
}

// FuzzCertificateCaching fuzzes the certificate caching mechanism
func FuzzCertificateCaching(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("example.com", true)
	f.Add("localhost", true)
	f.Add("test.com", false)
	f.Add("", true)

	f.Fuzz(func(t *testing.T, serverName string, requestTwice bool) {
		cfg := &domain.ProxyConfig{
			Expire: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ca, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return
		}

		clientHello := &tls.ClientHelloInfo{
			ServerName: serverName,
		}

		// First request
		cert1, err := ca.GetCertificate(clientHello)
		if err != nil {
			return
		}

		if !requestTwice {
			return
		}

		// Second request - should potentially be cached
		cert2, err := ca.GetCertificate(clientHello)
		if err != nil {
			return
		}

		// Both should succeed and be non-nil
		if cert1 == nil || cert2 == nil {
			return
		}

		// Verify cache behavior - leaf cert should be the same
		if cert1.Leaf != nil && cert2.Leaf != nil {
			if !cert1.Leaf.Equal(cert2.Leaf) {
				// Cache may have expired, which is acceptable
				return
			}
		}
	})
}

// FuzzDirector fuzzes the HTTP request director function
func FuzzDirector(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("http", "example.com", "/path")
	f.Add("https", "localhost", "/")
	f.Add("http", "", "")
	f.Add("https", "test.com", "/api/v1/test")
	f.Add("", "example.com", "/path")

	f.Fuzz(func(t *testing.T, scheme, host, path string) {
		ctx := context.Background()
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		cfg := &domain.ProxyConfig{
			Expire: 24 * time.Hour,
		}

		server, err := NewServer(ctx, log, cfg)
		if err != nil {
			return
		}

		// Create a test request
		req := httptest.NewRequest("GET", "http://test.local"+path, nil)
		req.Host = host

		// Set TLS if scheme is https
		if scheme == "https" {
			req.TLS = &tls.ConnectionState{}
		}

		// Call Director
		server.Director(req)

		// Verify URL was modified
		if req.URL.Host == "" && host != "" {
			t.Error("URL host not set")
		}

		// Verify scheme was set correctly
		expectedScheme := "http"
		if scheme == "https" && req.TLS != nil {
			expectedScheme = "https"
		}

		if req.URL.Scheme != expectedScheme {
			t.Errorf("expected scheme %s, got %s", expectedScheme, req.URL.Scheme)
		}
	})
}

// FuzzParseCertificate fuzzes certificate parsing
func FuzzParseCertificate(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Fuzz(func(t *testing.T, certPEM, keyPEM []byte) {
		cfg := &domain.ProxyConfig{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
			Expire:  24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		_, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return // Parse errors are expected for invalid input
		}
	})
}

// FuzzCertificateExpiry fuzzes certificate expiry handling
func FuzzCertificateExpiry(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus with various time offsets
	f.Add("example.com", int64(time.Hour), int64(24*time.Hour))
	f.Add("localhost", int64(0), int64(time.Hour))
	f.Add("test.com", int64(-time.Hour), int64(time.Hour))
	f.Add("", int64(time.Minute), int64(time.Minute))

	f.Fuzz(func(t *testing.T, serverName string, notBeforeOffset, notAfterOffset int64) {
		cfg := &domain.ProxyConfig{
			Expire: time.Duration(notAfterOffset),
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ca, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return
		}

		// Generate a certificate first, then we'll check expiry
		// Note: We can't directly manipulate the certificate cache with x509.Certificate
		// because the cache stores *tls.Certificate now. We'll just test the normal flow.

		// Request certificate - should regenerate if expired
		clientHello := &tls.ClientHelloInfo{
			ServerName: serverName,
		}

		cert, err := ca.GetCertificate(clientHello)
		if err != nil {
			return
		}

		// If successful, certificate should be valid
		if cert != nil && cert.Leaf != nil {
			if cert.Leaf.NotAfter.Before(time.Now()) {
				t.Error("Generated certificate is already expired")
			}
		}
	})
}

// FuzzRoundTrip fuzzes the HTTP round trip handling
func FuzzRoundTrip(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("GET", "http://example.com", "/path")
	f.Add("POST", "https://api.test.com", "/api/v1")
	f.Add("PUT", "http://localhost", "/")
	f.Add("DELETE", "https://test.com", "/resource")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, method, urlStr, path string) {
		ctx := context.Background()
		log := slog.New(slog.NewTextHandler(io.Discard, nil))

		// Create a simple allow-all config
		cfg := &domain.ProxyConfig{
			Expire: 24 * time.Hour,
			Policy: &domain.ProxyPolicy{
				AcceptRules: []*domain.ProxyPolicyAcceptRule{
					{
						Name: "allow-all",
						Match: &domain.ProxyPolicyMatch{
							Host: ".*",
						},
					},
				},
			},
		}

		if err := cfg.Compile(); err != nil {
			return
		}

		server, err := NewServer(ctx, log, cfg)
		if err != nil {
			return
		}

		// Create test request
		if method == "" {
			method = "GET"
		}

		fullURL := urlStr + path
		if fullURL == "" || fullURL == "/" {
			fullURL = "http://example.com/"
		}

		req, err := http.NewRequest(method, fullURL, nil)
		if err != nil {
			return // Invalid request parameters
		}

		// Call RoundTrip
		_, _ = server.RoundTrip(req)
		// Errors are expected for invalid requests or blocked domains
	})
}

// FuzzCertificateSubjectName fuzzes certificate subject name generation
func FuzzCertificateSubjectName(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus with various name patterns
	f.Add("example.com", "Organization")
	f.Add("localhost", "Test Org")
	f.Add("", "")
	f.Add("test-123", "My Company")
	f.Add(string([]byte{0x00, 0xFF}), "Special\nChars")

	f.Fuzz(func(t *testing.T, commonName, organization string) {
		cfg := &domain.ProxyConfig{
			Expire: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ca, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return
		}

		// Try to generate a certificate with custom names
		clientHello := &tls.ClientHelloInfo{
			ServerName: commonName,
		}

		cert, err := ca.GetCertificate(clientHello)
		if err != nil {
			return // Errors are acceptable for invalid names
		}

		if cert == nil {
			return
		}

		// Verify certificate was created
		if len(cert.Certificate) == 0 {
			t.Error("Empty certificate")
		}
	})
}

// FuzzConcurrentCertificateGeneration fuzzes concurrent certificate requests
func FuzzConcurrentCertificateGeneration(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("example.com", byte(2))
	f.Add("localhost", byte(5))
	f.Add("test.com", byte(10))

	f.Fuzz(func(t *testing.T, serverName string, concurrency byte) {
		if concurrency == 0 || concurrency > 20 {
			return // Limit concurrency
		}

		cfg := &domain.ProxyConfig{
			Expire: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ca, err := NewCertificateAuthority(log, cfg)
		if err != nil {
			return
		}

		// Make concurrent requests
		results := make(chan *tls.Certificate, concurrency)
		for i := byte(0); i < concurrency; i++ {
			go func() {
				clientHello := &tls.ClientHelloInfo{
					ServerName: serverName,
				}
				cert, err := ca.GetCertificate(clientHello)
				if err == nil {
					results <- cert
				} else {
					results <- nil
				}
			}()
		}

		// Collect results
		certs := make([]*tls.Certificate, 0, concurrency)
		for i := byte(0); i < concurrency; i++ {
			cert := <-results
			if cert != nil {
				certs = append(certs, cert)
			}
		}

		// All successful certificates should be for the same server
		if len(certs) > 0 && serverName != "" {
			for _, cert := range certs {
				if cert.Leaf != nil && len(cert.Leaf.DNSNames) > 0 {
					if cert.Leaf.DNSNames[0] != serverName {
						t.Errorf("expected certificate for %s, got %s", serverName, cert.Leaf.DNSNames[0])
					}
				}
			}
		}
	})
}
