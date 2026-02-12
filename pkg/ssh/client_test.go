package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"golang.org/x/crypto/ssh"
)

// TestClientConnect tests basic client connection
func TestClientConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping client integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start test server
	server, port := startTestServer(t, ctx, log)
	_ = server

	// Configure client
	var stdout, stderr bytes.Buffer
	cfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            port,
		Command:         "echo hello",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Stdin:           nil,
	}

	// Connect and run command
	err := Client(ctx, log, cfg)
	if err != nil {
		t.Fatalf("client failed: %v", err)
	}

	// Check output
	output := strings.TrimSpace(stdout.String())
	if output != "hello" {
		t.Errorf("expected output 'hello', got %q", output)
	}
}

// TestClientAuthenticationFailure tests authentication failure
func TestClientAuthenticationFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping client integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start test server
	server, port := startTestServer(t, ctx, log)
	_ = server

	// Configure client with wrong password
	var stdout, stderr bytes.Buffer
	cfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            port,
		Command:         "echo hello",
		Auth:            []ssh.AuthMethod{ssh.Password("wrongpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Stdin:           nil,
	}

	// Try to connect
	err := Client(ctx, log, cfg)
	if err == nil {
		t.Error("expected authentication to fail, but it succeeded")
	}

	// Check error message contains authentication-related text
	if !strings.Contains(err.Error(), "unable to authenticate") && !strings.Contains(err.Error(), "ssh: handshake failed") {
		t.Errorf("expected authentication error, got: %v", err)
	}
}

// TestClientCommandExecution tests executing different commands
func TestClientCommandExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping client integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start test server
	server, port := startTestServer(t, ctx, log)
	_ = server

	tests := []struct {
		name           string
		command        string
		expectedOutput string
	}{
		{
			name:           "echo command",
			command:        "echo test123",
			expectedOutput: "test123",
		},
		{
			name:           "multiple words",
			command:        "echo hello world",
			expectedOutput: "hello world",
		},
		{
			name:           "pwd command",
			command:        "pwd",
			expectedOutput: "/", // Depends on server working directory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cfg := &domain.SSHClientConfig{
				User:            "testuser",
				Host:            "127.0.0.1",
				Port:            port,
				Command:         tt.command,
				Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Stdout:          &stdout,
				Stderr:          &stderr,
				Stdin:           nil,
			}

			err := Client(ctx, log, cfg)
			if err != nil {
				t.Fatalf("client failed: %v", err)
			}

			output := strings.TrimSpace(stdout.String())
			if tt.expectedOutput != "/" && output != tt.expectedOutput {
				t.Errorf("expected output %q, got %q", tt.expectedOutput, output)
			} else if tt.expectedOutput == "/" && !strings.HasPrefix(output, "/") {
				t.Errorf("expected output to start with '/', got %q", output)
			}
		})
	}
}

// TestClientStdin tests sending input via stdin
func TestClientStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping client integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start test server
	server, port := startTestServer(t, ctx, log)
	_ = server

	// Prepare stdin
	stdin := bytes.NewBufferString("test input\n")
	var stdout, stderr bytes.Buffer

	cfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            port,
		Command:         "cat",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Stdin:           stdin,
		Interactive:     true,
	}

	err := Client(ctx, log, cfg)
	if err != nil {
		t.Fatalf("client failed: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	expected := "test input"
	if output != expected {
		t.Errorf("expected output %q, got %q", expected, output)
	}
}

// TestClientConnectionRefused tests connection to non-existent server
func TestClientConnectionRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Try to connect to a port that's not listening
	var stdout, stderr bytes.Buffer
	cfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            9999, // Unlikely to be in use
		Command:         "echo hello",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Stdin:           nil,
	}

	err := Client(ctx, log, cfg)
	if err == nil {
		t.Error("expected connection to fail, but it succeeded")
	}

	// Check error is connection-related
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") {
		t.Logf("got error: %v", err)
	}
}

// TestClientContextCancellation tests that client respects context cancellation
func TestClientContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping client integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start test server
	server, port := startTestServer(t, ctx, log)
	_ = server

	// Create a short-lived context
	clientCtx, clientCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer clientCancel()

	var stdout, stderr bytes.Buffer
	cfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            port,
		Command:         "sleep 10", // Long-running command
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Stdin:           nil,
	}

	err := Client(clientCtx, log, cfg)
	if err == nil {
		t.Error("expected client to fail due to context cancellation")
	}

	if err != nil && err != context.DeadlineExceeded && !strings.Contains(err.Error(), "context") {
		t.Logf("got error: %v (expected context-related error)", err)
	}
}

// TestClientPublicKeyAuth tests public key authentication
func TestClientPublicKeyAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping client integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	// Start test server with public key auth
	server, port := startTestServerWithPublicKey(t, ctx, log, publicKey)
	_ = server

	// Configure client with public key
	var stdout, stderr bytes.Buffer
	cfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            port,
		Command:         "echo hello",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Stdin:           nil,
	}

	err = Client(ctx, log, cfg)
	if err != nil {
		t.Fatalf("client failed: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "hello" {
		t.Errorf("expected output 'hello', got %q", output)
	}
}

// Helper function to start a test server with password auth
func startTestServer(t *testing.T, ctx context.Context, log *slog.Logger) (*SSHServer, int) {
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"testuser": "testpass",
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, cfg)

	go func() {
		if err := server.Start(); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	return server, port
}

// Helper function to start a test server with public key auth
func startTestServerWithPublicKey(t *testing.T, ctx context.Context, log *slog.Logger, pubKey ssh.PublicKey) (*SSHServer, int) {
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		HostKeys: []ssh.Signer{hostKey},
		AuthorizedKeys: map[string][]ssh.PublicKey{
			"testuser": {pubKey},
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, cfg)

	go func() {
		if err := server.Start(); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	return server, port
}
