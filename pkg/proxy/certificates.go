package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

type CertificateAuthority struct {
	cfg       *domain.ProxyConfig
	authority tls.Certificate
	mtx       sync.RWMutex
	log       *slog.Logger
	certs     map[string]*tls.Certificate
}

func NewCertificateAuthority(log *slog.Logger, cfg *domain.ProxyConfig) (*CertificateAuthority, error) {
	ca := &CertificateAuthority{
		cfg:   cfg,
		log:   log,
		mtx:   sync.RWMutex{},
		certs: make(map[string]*tls.Certificate),
	}
	return ca, ca.GenerateCA()
}

func (ca *CertificateAuthority) GenerateCA() error {
	if len(ca.cfg.CertPEM) == 0 || len(ca.cfg.KeyPEM) == 0 {
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{domain.AppName + " proxy"},
				CommonName:   domain.AppName,
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(ca.cfg.Expire),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
		if err != nil {
			return err
		}

		ca.cfg.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		ca.cfg.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	}

	return ca.parseCert()
}

func (ca *CertificateAuthority) parseCert() (err error) {
	ca.authority, err = tls.X509KeyPair(ca.cfg.CertPEM, ca.cfg.KeyPEM)
	return err
}

func (ca *CertificateAuthority) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := info.ServerName
	if serverName == "" {
		serverName = "localhost"
	}

	ca.mtx.RLock()
	cert, exists := ca.certs[serverName]
	ca.mtx.RUnlock()

	if exists && cert.Leaf.NotAfter.After(time.Now()) {
		ca.log.Debug("certificate found", "serverName", serverName)
		return cert, nil
	}

	return ca.generateCertificate(serverName)
}

func (ca *CertificateAuthority) generateCertificate(serverName string) (*tls.Certificate, error) {
	ca.mtx.Lock()
	defer ca.mtx.Unlock()

	ca.log.Debug("generating certificate", "serverName", serverName)

	// Double-check pattern: another goroutine might have generated it
	if cert, exists := ca.certs[serverName]; exists && cert.Leaf.NotAfter.After(time.Now()) {
		return cert, nil
	}

	caCert, err := x509.ParseCertificate(ca.authority.Certificate[0])
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"r0mp proxy"},
			CommonName:   serverName,
		},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(ca.cfg.Expire),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, ca.authority.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	ca.certs[serverName] = &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return ca.certs[serverName], nil
}

// GetCACertPEM returns a copy of the CA certificate in PEM format
func (ca *CertificateAuthority) GetCACertPEM() []byte {
	cert := make([]byte, len(ca.cfg.CertPEM))
	copy(cert, ca.cfg.CertPEM)
	return cert
}
