package proxy

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCACertPEM_ReturnsCopy(t *testing.T) {
	// Create a certificate authority with automatic generation
	cfg := &domain.ProxyConfig{
		Expire: 24 * time.Hour,
		Policy: &domain.ProxyPolicy{},
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, cfg)
	require.NoError(t, err)

	// Get the CA cert
	certPEM := ca.GetCACertPEM()
	require.NotNil(t, certPEM)
	require.Greater(t, len(certPEM), 0)

	// Modify the returned cert
	originalByte := certPEM[0]
	certPEM[0] = 'X'

	// Get the cert again
	certPEM2 := ca.GetCACertPEM()
	require.NotNil(t, certPEM2)

	// The new cert should not be affected by our modification
	assert.Equal(t, originalByte, certPEM2[0], "GetCACertPEM should return a copy, not the original")

	// Verify the original cert in the CA is not modified
	assert.Equal(t, originalByte, ca.cfg.CertPEM[0], "Original CA cert should not be modified")
}

func TestServer_GetCACertPEM(t *testing.T) {
	// Create a proxy config with automatic CA generation
	proxyCfg := &domain.ProxyConfig{
		Expire: 24 * time.Hour,
		Policy: &domain.ProxyPolicy{},
	}

	err := proxyCfg.Compile()
	require.NoError(t, err)

	// Create a server (without listeners for simplicity)
	server := &Server{
		cfg: proxyCfg,
	}

	// Initialize the CA
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	server.ca, err = NewCertificateAuthority(log, proxyCfg)
	require.NoError(t, err)

	// Get the CA cert from the server
	certPEM := server.GetCACertPEM()
	require.NotNil(t, certPEM)
	require.Greater(t, len(certPEM), 0)

	// Verify it's a valid PEM certificate
	assert.Contains(t, string(certPEM), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(certPEM), "-----END CERTIFICATE-----")
}

func TestGetCACertPEM_ConsistentResults(t *testing.T) {
	// Create a certificate authority
	cfg := &domain.ProxyConfig{
		Expire: 24 * time.Hour,
		Policy: &domain.ProxyPolicy{},
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := NewCertificateAuthority(log, cfg)
	require.NoError(t, err)

	// Get the cert multiple times
	cert1 := ca.GetCACertPEM()
	cert2 := ca.GetCACertPEM()
	cert3 := ca.GetCACertPEM()

	// All should have the same content (but be different slices)
	assert.Equal(t, cert1, cert2)
	assert.Equal(t, cert2, cert3)

	// Verify they are different slices (modifying one doesn't affect others)
	cert1[0] = 'A'
	cert2[0] = 'B'
	cert3[0] = 'C'

	assert.NotEqual(t, cert1[0], cert2[0])
	assert.NotEqual(t, cert2[0], cert3[0])
}
