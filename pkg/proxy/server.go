package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

type Server struct {
	cfg          *domain.ProxyConfig
	ca           *CertificateAuthority
	server       *http.Server
	transport    http.RoundTripper
	ctx          context.Context
	log          *slog.Logger
	tlsListeners []net.Listener
	listeners    []net.Listener
}

func NewServer(ctx context.Context, log *slog.Logger, cfg *domain.ProxyConfig) (*Server, error) {

	if err := cfg.Compile(); err != nil {
		return nil, fmt.Errorf("compile proxy config: %v", err)
	}

	ca, err := NewCertificateAuthority(log, cfg)
	if err != nil {
		return nil, fmt.Errorf("create certificate authority: %v", err)
	}

	server := &Server{
		cfg:       cfg,
		ca:        ca,
		ctx:       ctx,
		transport: DefaultTransport(),
		log:       log,
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(false)
	server.server = &http.Server{
		Handler: &httputil.ReverseProxy{
			Director:      server.Director,
			Transport:     server,
			FlushInterval: -1,
			ErrorLog:      slog.NewLogLogger(server.log.Handler(), slog.LevelDebug),
		},
		TLSConfig: &tls.Config{
			GetCertificate: server.ca.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			MaxVersion:     tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		ErrorLog: slog.NewLogLogger(server.log.Handler(), slog.LevelDebug),
		ConnState: func(conn net.Conn, state http.ConnState) {
			log.Info("New connection", "addr", conn.RemoteAddr(), "state", state)
		},
		Protocols: protocols,
	}
	return server, nil
}

func (t *Server) Director(request *http.Request) {
	request.URL.Host = request.Host
	request.URL.Scheme = "http"
	if request.TLS != nil {
		request.URL.Scheme = "https"
	}
	t.log.Debug("Proxy Director",
		"url", request.URL.String(),
		"method", request.Method,
		"user-agent", request.Header.Get("User-Agent"),
	)
}

func (t *Server) RoundTrip(request *http.Request) (*http.Response, error) {

	allow, deny := t.cfg.Find(request)
	l := t.log.With(
		"url", request.URL.String(),
		"method", request.Method,
		"user-agent", request.Header.Get("User-Agent"),
		"match_allow", allow != nil,
		"deny_allow", deny != nil,
	)

	if deny != nil || allow == nil {
		l.Info("proxy request rejected")
		body := []byte("Domain blocked")
		return &http.Response{
			Status:        "403 Forbidden",
			StatusCode:    http.StatusForbidden,
			Proto:         request.Proto,
			ProtoMajor:    request.ProtoMajor,
			ProtoMinor:    request.ProtoMinor,
			Header:        http.Header{},
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       request,
		}, nil
	}
	allow.Modify(request)
	allow.Wait(request.Context())
	l.Info("proxy request accepted")
	return t.transport.RoundTrip(request)
}

func (t *Server) Serve(listeners []net.Listener, tlsListeners []net.Listener) error {
	errChan := make(chan error, len(t.listeners)+len(t.tlsListeners))
	t.listeners = listeners
	t.tlsListeners = tlsListeners

	// Start HTTP listeners
	for _, listener := range t.listeners {
		go func(l net.Listener) {
			t.log.Info("starting HTTP listener", "addr", l.Addr().String())
			if err := t.server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("HTTP listener error: %w", err)
			}
		}(listener)
	}

	// Start HTTPS listeners
	for _, listener := range t.tlsListeners {
		go func(l net.Listener) {
			t.log.Info("starting HTTPS listener", "addr", l.Addr().String())
			if err := t.server.ServeTLS(l, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("HTTPS listener error: %w", err)
			}
		}(listener)
	}

	// Wait for first error or context cancellation
	select {
	case err := <-errChan:
		return err
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Server) Shutdown(ctx context.Context) error {
	t.log.Info("shutting down proxy server")
	return t.server.Shutdown(ctx)
}

func (t *Server) SetTransport(transport *http.Transport) {
	t.transport = transport
}

func (t *Server) GetCACertPEM() []byte {
	return t.ca.GetCACertPEM()
}
