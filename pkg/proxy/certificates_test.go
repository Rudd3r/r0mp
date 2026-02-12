package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

func TestNewCertificateAuthority(t *testing.T) {
	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
		expire  time.Duration
		wantErr bool
	}{
		{
			name:    "generate new CA",
			certPEM: nil,
			keyPEM:  nil,
			expire:  time.Hour * 24,
			wantErr: false,
		},
		{
			name:    "with existing cert and key",
			certPEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			keyPEM:  []byte("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"),
			expire:  time.Hour * 24,
			wantErr: true, // Will fail to parse invalid cert
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(os.Stderr, nil))
			ca, err := NewCertificateAuthority(log, &domain.ProxyConfig{CertPEM: tt.certPEM, KeyPEM: tt.keyPEM, Expire: tt.expire})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificateAuthority() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if ca == nil {
					t.Error("expected CA but got nil")
					return
				}
				if len(ca.cfg.CertPEM) == 0 {
					t.Error("CA certificate not generated")
				}
				if len(ca.cfg.KeyPEM) == 0 {
					t.Error("CA key not generated")
				}
				if ca.certs == nil {
					t.Error("certificate cache not initialized")
				}
			}
		})
	}
}

func TestGenerateCA(t *testing.T) {
	ca := &CertificateAuthority{
		cfg: &domain.ProxyConfig{
			Expire: time.Hour * 24,
		},
		certs: make(map[string]*tls.Certificate),
	}

	err := ca.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	if len(ca.cfg.CertPEM) == 0 {
		t.Error("CertPEM not generated")
	}
	if len(ca.cfg.KeyPEM) == 0 {
		t.Error("KeyPEM not generated")
	}

	// Verify the generated certificate can be parsed
	cert, err := tls.X509KeyPair(ca.cfg.CertPEM, ca.cfg.KeyPEM)
	if err != nil {
		t.Errorf("failed to parse generated certificate: %v", err)
	}

	// Verify it's a CA certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Errorf("failed to parse x509 certificate: %v", err)
	}

	if !x509Cert.IsCA {
		t.Error("generated certificate is not marked as CA")
	}

	if x509Cert.Subject.CommonName != "r0mp" {
		t.Errorf("expected CommonName 'r0mp', got %s", x509Cert.Subject.CommonName)
	}
}

func TestGetCertificate(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, &domain.ProxyConfig{Expire: time.Hour * 24})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	tests := []struct {
		name       string
		serverName string
		wantErr    bool
	}{
		{
			name:       "generate certificate for example.com",
			serverName: "example.com",
			wantErr:    false,
		},
		{
			name:       "generate certificate for subdomain",
			serverName: "api.example.com",
			wantErr:    false,
		},
		{
			name:       "generate certificate for localhost",
			serverName: "localhost",
			wantErr:    false,
		},
		{
			name:       "empty server name defaults to localhost",
			serverName: "",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &tls.ClientHelloInfo{
				ServerName: tt.serverName,
			}

			cert, err := ca.GetCertificate(info)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cert == nil {
					t.Error("expected certificate but got nil")
					return
				}

				if cert.Leaf == nil {
					t.Error("certificate Leaf is nil")
					return
				}

				expectedName := tt.serverName
				if expectedName == "" {
					expectedName = "localhost"
				}

				if cert.Leaf.Subject.CommonName != expectedName {
					t.Errorf("expected CommonName %s, got %s", expectedName, cert.Leaf.Subject.CommonName)
				}

				if len(cert.Leaf.DNSNames) == 0 {
					t.Error("certificate has no DNSNames")
				} else if cert.Leaf.DNSNames[0] != expectedName {
					t.Errorf("expected DNSName %s, got %s", expectedName, cert.Leaf.DNSNames[0])
				}
			}
		})
	}
}

func TestGetCertificate_Caching(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, &domain.ProxyConfig{Expire: time.Hour * 24})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	info := &tls.ClientHelloInfo{
		ServerName: "cache-test.example.com",
	}

	// First call should generate a new certificate
	cert1, err := ca.GetCertificate(info)
	if err != nil {
		t.Fatalf("first GetCertificate() failed: %v", err)
	}

	// Second call should return cached certificate
	cert2, err := ca.GetCertificate(info)
	if err != nil {
		t.Fatalf("second GetCertificate() failed: %v", err)
	}

	// Compare serial numbers to ensure it's the same certificate
	if cert1.Leaf.SerialNumber.Cmp(cert2.Leaf.SerialNumber) != 0 {
		t.Error("expected cached certificate but got different serial number")
	}
}

func TestGetCertificate_Concurrent(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, &domain.ProxyConfig{Expire: time.Hour * 24})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	const goroutines = 10
	const serverName = "concurrent-test.example.com"

	errChan := make(chan error, goroutines)
	certChan := make(chan *tls.Certificate, goroutines)

	// Launch concurrent certificate requests
	for i := 0; i < goroutines; i++ {
		go func() {
			info := &tls.ClientHelloInfo{
				ServerName: serverName,
			}
			cert, err := ca.GetCertificate(info)
			if err != nil {
				errChan <- err
				return
			}
			certChan <- cert
		}()
	}

	// Collect results
	certs := make([]*tls.Certificate, 0, goroutines)
	for i := 0; i < goroutines; i++ {
		select {
		case err := <-errChan:
			t.Fatalf("concurrent GetCertificate() failed: %v", err)
		case cert := <-certChan:
			certs = append(certs, cert)
		}
	}

	// Verify all certificates have the same serial number (from cache)
	firstSerial := certs[0].Leaf.SerialNumber
	for i, cert := range certs {
		if cert.Leaf.SerialNumber.Cmp(firstSerial) != 0 {
			t.Errorf("certificate %d has different serial number", i)
		}
	}
}

func TestGetCertificate_ExpiredCert(t *testing.T) {
	// Create a CA with very short expiration
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, &domain.ProxyConfig{Expire: time.Millisecond * 100})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	info := &tls.ClientHelloInfo{
		ServerName: "expiry-test.example.com",
	}

	// Generate first certificate
	cert1, err := ca.GetCertificate(info)
	if err != nil {
		t.Fatalf("first GetCertificate() failed: %v", err)
	}

	// Wait for certificate to expire
	time.Sleep(time.Millisecond * 150)

	// Request again should generate a new certificate
	cert2, err := ca.GetCertificate(info)
	if err != nil {
		t.Fatalf("second GetCertificate() failed: %v", err)
	}

	// Should have different serial numbers
	if cert1.Leaf.SerialNumber.Cmp(cert2.Leaf.SerialNumber) == 0 {
		t.Error("expected new certificate after expiration but got same serial number")
	}
}

func TestGenerateCertificate(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, &domain.ProxyConfig{Expire: time.Hour * 24})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	serverName := "direct-gen.example.com"
	cert, err := ca.generateCertificate(serverName)
	if err != nil {
		t.Fatalf("generateCertificate() failed: %v", err)
	}

	if cert == nil {
		t.Fatal("expected certificate but got nil")
	}

	if cert.Leaf == nil {
		t.Fatal("certificate Leaf is nil")
	}

	if cert.Leaf.Subject.CommonName != serverName {
		t.Errorf("expected CommonName %s, got %s", serverName, cert.Leaf.Subject.CommonName)
	}

	// Verify the certificate is signed by our CA
	caCert, err := x509.ParseCertificate(ca.authority.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     pool,
		DNSName:   serverName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}
}

func TestParseCert(t *testing.T) {
	// Generate a valid certificate first
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	tempCA, err := NewCertificateAuthority(log, &domain.ProxyConfig{Expire: time.Hour * 24})
	if err != nil {
		t.Fatalf("failed to create temporary CA: %v", err)
	}

	ca := &CertificateAuthority{
		certs: make(map[string]*tls.Certificate),
		cfg: &domain.ProxyConfig{
			CertPEM: tempCA.cfg.CertPEM,
			KeyPEM:  tempCA.cfg.KeyPEM,
		},
	}

	err = ca.parseCert()
	if err != nil {
		t.Errorf("parseCert() failed: %v", err)
	}

	if len(ca.authority.Certificate) == 0 {
		t.Error("authority certificate not parsed")
	}
}

func TestParseCert_InvalidData(t *testing.T) {
	ca := &CertificateAuthority{
		cfg: &domain.ProxyConfig{
			CertPEM: []byte("invalid certificate"),
			KeyPEM:  []byte("invalid key"),
			Expire:  time.Hour * 24,
		},
		certs: make(map[string]*tls.Certificate),
	}

	err := ca.parseCert()
	if err == nil {
		t.Error("expected error for invalid certificate data")
	}
}
