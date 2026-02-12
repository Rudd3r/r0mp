package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"golang.org/x/crypto/ssh"
)

// TestServerStartStop tests that the server can start and stop cleanly
func TestServerStartStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	cfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     0, // Use random available port
		HostKeys: []ssh.Signer{hostKey},
		Shell:    "/bin/sh",
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop server
	cancel()

	// Wait for server to exit
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("unexpected error from server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("server did not stop in time")
	}
}

// TestServerPasswordAuth tests password authentication
func TestServerPasswordAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
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
		Shell: "/bin/echo",
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Test correct password
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect with correct password: %v", err)
	}
	_ = client.Close()

	// Test incorrect password
	wrongCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("wrongpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err = ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), wrongCfg)
	if err == nil {
		_ = client.Close()
		t.Error("expected authentication to fail with wrong password")
	}
}

// TestServerPublicKeyAuth tests public key authentication
func TestServerPublicKeyAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	// Generate client key
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientSigner, err := ssh.NewSignerFromKey(clientPrivKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	clientPubKey, err := ssh.NewPublicKey(&clientPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
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
			"testuser": {clientPubKey},
		},
		Shell: "/bin/echo",
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Test correct key
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect with correct key: %v", err)
	}
	_ = client.Close()

	// Test wrong key
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongSigner, _ := ssh.NewSignerFromKey(wrongKey)

	wrongCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(wrongSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err = ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), wrongCfg)
	if err == nil {
		_ = client.Close()
		t.Error("expected authentication to fail with wrong key")
	}
}

// TestServerExecCommand tests executing a command
func TestServerExecCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping exec test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
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

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Connect
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Run command
	output, err := session.CombinedOutput("echo hello world")
	if err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	expectedOutput := "hello world"
	actualOutput := strings.TrimSpace(string(output))
	if actualOutput != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, actualOutput)
	}
}

// TestServerMultipleConnections tests multiple concurrent connections
func TestServerMultipleConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multiple connections test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
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

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Create multiple connections
	numConnections := 5
	errCh := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(id int) {
			clientCfg := &ssh.ClientConfig{
				User: "testuser",
				Auth: []ssh.AuthMethod{
					ssh.Password("testpass"),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
			if err != nil {
				errCh <- fmt.Errorf("connection %d: failed to connect: %w", id, err)
				return
			}
			defer func() { _ = client.Close() }()

			session, err := client.NewSession()
			if err != nil {
				errCh <- fmt.Errorf("connection %d: failed to create session: %w", id, err)
				return
			}
			defer func() { _ = session.Close() }()

			output, err := session.CombinedOutput(fmt.Sprintf("echo connection-%d", id))
			if err != nil {
				errCh <- fmt.Errorf("connection %d: failed to run command: %w", id, err)
				return
			}

			expected := fmt.Sprintf("connection-%d", id)
			actual := strings.TrimSpace(string(output))
			if actual != expected {
				errCh <- fmt.Errorf("connection %d: expected %q, got %q", id, expected, actual)
				return
			}

			errCh <- nil
		}(i)
	}

	// Wait for all connections to complete
	for i := 0; i < numConnections; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("connection %d timed out", i)
		}
	}
}

// TestServerEnvironmentVariables tests setting environment variables
func TestServerEnvironmentVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping environment test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
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
		Env: []string{
			"TEST_VAR=test_value",
			"ANOTHER_VAR=another_value",
		},
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Connect
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Check environment variable
	output, err := session.CombinedOutput("echo $TEST_VAR")
	if err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	expected := "test_value"
	actual := strings.TrimSpace(string(output))
	if actual != expected {
		t.Errorf("expected TEST_VAR=%q, got %q", expected, actual)
	}
}

// TestServerPTYAllocation tests PTY allocation
func TestServerPTYAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PTY test in short mode")
	}

	// Skip if not on a Unix-like system
	if _, err := os.Stat("/dev/ptmx"); os.IsNotExist(err) {
		t.Skip("PTY not available on this system")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
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

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Connect
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Request PTY
	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		t.Fatalf("failed to request PTY: %v", err)
	}

	// Run command with PTY
	output, err := session.CombinedOutput("echo hello")
	if err != nil {
		t.Fatalf("failed to run command with PTY: %v", err)
	}

	if !bytes.Contains(output, []byte("hello")) {
		t.Errorf("expected output to contain 'hello', got %q", string(output))
	}
}

// Helper function to generate a test host key
func generateTestHostKey() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	return signer, nil
}

// TestNewSSHServerFromInit tests creating a server from SSHServerInit config
func TestNewSSHServerFromInit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate client key pair for auth
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientPubKey, err := ssh.NewPublicKey(&clientPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create client public key: %v", err)
	}
	authorizedKey := string(ssh.MarshalAuthorizedKey(clientPubKey))

	// Test with default (generated) host key
	t.Run("GeneratedHostKey", func(t *testing.T) {
		initCfg := &domain.SSHServer{
			Enabled: true,
			Addr:    "127.0.0.1",
			Port:    0,
			AuthorizedKeys: map[string][]string{
				"testuser": {authorizedKey},
			},
			HostKey: MustGenerateHostKey(),
			Shell:   "/bin/sh",
		}

		server, err := NewSSHServerFromInit(ctx, log, initCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if server == nil {
			t.Fatal("server is nil")
		}

		if len(server.cfg.HostKeys) != 1 {
			t.Errorf("expected 1 host key, got %d", len(server.cfg.HostKeys))
		}

		if len(server.cfg.AuthorizedKeys["testuser"]) != 1 {
			t.Errorf("expected 1 authorized key for testuser, got %d", len(server.cfg.AuthorizedKeys["testuser"]))
		}
	})

	// Test with provided host key
	t.Run("ProvidedHostKey", func(t *testing.T) {
		hostPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate host key: %v", err)
		}
		hostKeyPEMBlock, err := ssh.MarshalPrivateKey(hostPrivKey, "")
		if err != nil {
			t.Fatalf("failed to marshal private key: %v", err)
		}
		hostKeyPEM := pem.EncodeToMemory(hostKeyPEMBlock)

		initCfg := &domain.SSHServer{
			Enabled: true,
			Addr:    "127.0.0.1",
			Port:    0,
			HostKey: hostKeyPEM,
			AuthorizedKeys: map[string][]string{
				"user1": {authorizedKey},
				"user2": {authorizedKey},
			},
			Shell: "/bin/sh",
		}

		server, err := NewSSHServerFromInit(ctx, log, initCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if server == nil {
			t.Fatal("server is nil")
		}

		if len(server.cfg.HostKeys) != 1 {
			t.Errorf("expected 1 host key, got %d", len(server.cfg.HostKeys))
		}

		if len(server.cfg.AuthorizedKeys) != 2 {
			t.Errorf("expected 2 users, got %d", len(server.cfg.AuthorizedKeys))
		}

		if len(server.cfg.AuthorizedKeys["user1"]) != 1 {
			t.Errorf("expected 1 authorized key for user1, got %d", len(server.cfg.AuthorizedKeys["user1"]))
		}

		if len(server.cfg.AuthorizedKeys["user2"]) != 1 {
			t.Errorf("expected 1 authorized key for user2, got %d", len(server.cfg.AuthorizedKeys["user2"]))
		}
	})

	// Test with disabled server
	t.Run("DisabledServer", func(t *testing.T) {
		initCfg := &domain.SSHServer{
			Enabled: false,
		}

		_, err := NewSSHServerFromInit(ctx, log, initCfg)
		if err == nil {
			t.Error("expected error when server is disabled")
		}
	})

	// Test with multiple keys per user
	t.Run("MultipleKeysPerUser", func(t *testing.T) {
		key2PrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate second key: %v", err)
		}
		key2PubKey, err := ssh.NewPublicKey(&key2PrivKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to create second public key: %v", err)
		}
		authorizedKey2 := string(ssh.MarshalAuthorizedKey(key2PubKey))

		initCfg := &domain.SSHServer{
			Enabled: true,
			Addr:    "127.0.0.1",
			Port:    0,
			AuthorizedKeys: map[string][]string{
				"testuser": {authorizedKey, authorizedKey2},
			},
			HostKey: MustGenerateHostKey(),
			Shell:   "/bin/sh",
		}

		server, err := NewSSHServerFromInit(ctx, log, initCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if len(server.cfg.AuthorizedKeys["testuser"]) != 2 {
			t.Errorf("expected 2 authorized keys for testuser, got %d", len(server.cfg.AuthorizedKeys["testuser"]))
		}
	})
}

// TestServerTCPIPForward tests the tcpip-forward functionality (port forwarding)
func TestServerTCPIPForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping tcpip-forward test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	// Find available port for SSH server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	sshPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     sshPort,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"testuser": "testpass",
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Connect SSH client
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Request remote port forwarding using ListenTCP
	// This will use the tcpip-forward request
	remoteListener, err := client.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0, // Use any available port
	})
	if err != nil {
		t.Fatalf("failed to create remote listener: %v", err)
	}
	defer func() { _ = remoteListener.Close() }()

	remotePort := remoteListener.Addr().(*net.TCPAddr).Port
	t.Logf("remote listener on port %d", remotePort)

	// Start a goroutine to accept connections on the remote listener
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := remoteListener.Accept()
		if err != nil {
			t.Logf("accept error: %v", err)
			return
		}
		accepted <- conn
	}()

	// Give the accept goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// Now connect to the forwarded port on the server side
	testData := "hello from forwarded connection"
	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer func() { _ = localConn.Close() }()

	// Send test data
	_, err = localConn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write to forwarded connection: %v", err)
	}

	// Wait for the connection to be accepted
	select {
	case remoteConn := <-accepted:
		defer func() { _ = remoteConn.Close() }()

		// Read the data on the remote side
		buf := make([]byte, 1024)
		n, err := remoteConn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read from remote connection: %v", err)
		}

		received := string(buf[:n])
		if received != testData {
			t.Errorf("expected to receive %q, got %q", testData, received)
		}

		// Send response back
		response := "response from client"
		_, err = remoteConn.Write([]byte(response))
		if err != nil {
			t.Fatalf("failed to write response: %v", err)
		}

		// Read response on local side
		n, err = localConn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}

		receivedResponse := string(buf[:n])
		if receivedResponse != response {
			t.Errorf("expected to receive %q, got %q", response, receivedResponse)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connection to be accepted")
	}
}

// TestServerTCPIPForwardMultipleConnections tests multiple connections through a forwarded port
func TestServerTCPIPForwardMultipleConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping tcpip-forward multiple connections test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate host key
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	// Find available port for SSH server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	sshPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     sshPort,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"testuser": "testpass",
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Connect SSH client
	clientCfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), clientCfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Request remote port forwarding
	remoteListener, err := client.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		t.Fatalf("failed to create remote listener: %v", err)
	}
	defer func() { _ = remoteListener.Close() }()

	remotePort := remoteListener.Addr().(*net.TCPAddr).Port
	t.Logf("remote listener on port %d", remotePort)

	// Accept connections in the background
	connChan := make(chan net.Conn, 5)
	go func() {
		for {
			conn, err := remoteListener.Accept()
			if err != nil {
				return
			}
			connChan <- conn
		}
	}()

	// Test multiple connections
	numConnections := 3
	for i := 0; i < numConnections; i++ {
		testData := fmt.Sprintf("message-%d", i)

		// Connect to forwarded port
		localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort), 2*time.Second)
		if err != nil {
			t.Fatalf("connection %d: failed to connect: %v", i, err)
		}

		// Send data
		_, err = localConn.Write([]byte(testData))
		if err != nil {
			_ = localConn.Close()
			t.Fatalf("connection %d: failed to write: %v", i, err)
		}

		// Wait for remote connection
		select {
		case remoteConn := <-connChan:
			// Read data
			buf := make([]byte, 1024)
			n, err := remoteConn.Read(buf)
			if err != nil {
				_ = remoteConn.Close()
				_ = localConn.Close()
				t.Fatalf("connection %d: failed to read: %v", i, err)
			}

			received := string(buf[:n])
			if received != testData {
				_ = remoteConn.Close()
				_ = localConn.Close()
				t.Errorf("connection %d: expected %q, got %q", i, testData, received)
			}

			_ = remoteConn.Close()
			_ = localConn.Close()

		case <-time.After(3 * time.Second):
			_ = localConn.Close()
			t.Fatalf("connection %d: timeout", i)
		}
	}
}

// TestParsePasswdFile tests the /etc/passwd parsing functionality
func TestParsePasswdFile(t *testing.T) {
	// Create a temporary passwd file
	tmpDir := t.TempDir()
	passwdPath := filepath.Join(tmpDir, "etc", "passwd")

	if err := os.MkdirAll(filepath.Dir(passwdPath), 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	passwdContent := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
testuser:x:1000:1000:Test User:/home/testuser:/bin/sh
# This is a comment
invalid_line_without_enough_fields:x:1001
appuser:x:2000:2001:App User:/app:/bin/bash
`
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd file: %v", err)
	}

	// Parse the passwd file
	users, err := parsePasswdFile(tmpDir)
	if err != nil {
		t.Fatalf("failed to parse passwd file: %v", err)
	}

	// Verify root user
	if root, ok := users["root"]; !ok {
		t.Error("root user not found")
	} else {
		if root.UID != 0 || root.GID != 0 {
			t.Errorf("root: expected UID=0, GID=0, got UID=%d, GID=%d", root.UID, root.GID)
		}
		if root.Home != "/root" {
			t.Errorf("root: expected home /root, got %s", root.Home)
		}
		if root.Shell != "/bin/bash" {
			t.Errorf("root: expected shell /bin/bash, got %s", root.Shell)
		}
	}

	// Verify testuser
	if testuser, ok := users["testuser"]; !ok {
		t.Error("testuser not found")
	} else {
		if testuser.UID != 1000 || testuser.GID != 1000 {
			t.Errorf("testuser: expected UID=1000, GID=1000, got UID=%d, GID=%d", testuser.UID, testuser.GID)
		}
	}

	// Verify appuser
	if appuser, ok := users["appuser"]; !ok {
		t.Error("appuser not found")
	} else {
		if appuser.UID != 2000 || appuser.GID != 2001 {
			t.Errorf("appuser: expected UID=2000, GID=2001, got UID=%d, GID=%d", appuser.UID, appuser.GID)
		}
	}

	// Verify invalid lines and comments are skipped
	if _, ok := users["#"]; ok {
		t.Error("comment line should not be parsed as user")
	}
	if _, ok := users["invalid_line_without_enough_fields"]; ok {
		t.Error("invalid line should not be parsed")
	}
}

// TestExtractSessionConfig tests extraction of session configuration from environment
func TestExtractSessionConfig(t *testing.T) {
	// Create a temporary passwd file
	tmpDir := t.TempDir()
	passwdPath := filepath.Join(tmpDir, "etc", "passwd")

	if err := os.MkdirAll(filepath.Dir(passwdPath), 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	passwdContent := `root:x:0:0:root:/root:/bin/bash
testuser:x:1000:1000:Test User:/home/testuser:/bin/sh
`
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd file: %v", err)
	}

	tests := []struct {
		name       string
		env        []string
		wantChroot string
		wantUser   string
		wantUID    uint32
		wantGID    uint32
		wantErr    bool
	}{
		{
			name:       "no chroot or user",
			env:        []string{"PATH=/usr/bin", "HOME=/root"},
			wantChroot: "",
			wantUser:   "",
			wantUID:    0,
			wantGID:    0,
			wantErr:    false,
		},
		{
			name:       "chroot only",
			env:        []string{"RAFT_CHROOT=/mnt/rootfs", "PATH=/usr/bin"},
			wantChroot: "/mnt/rootfs",
			wantUser:   "",
			wantUID:    0,
			wantGID:    0,
			wantErr:    false,
		},
		{
			name:       "chroot and user",
			env:        []string{fmt.Sprintf("RAFT_CHROOT=%s", tmpDir), "RAFT_USER=testuser"},
			wantChroot: tmpDir,
			wantUser:   "testuser",
			wantUID:    1000,
			wantGID:    1000,
			wantErr:    false,
		},
		{
			name:       "user without chroot",
			env:        []string{"RAFT_USER=testuser"},
			wantChroot: "",
			wantUser:   "testuser",
			wantErr:    true, // Should fail because testuser not in /etc/passwd
		},
		{
			name:       "non-existent user",
			env:        []string{fmt.Sprintf("RAFT_CHROOT=%s", tmpDir), "RAFT_USER=nonexistent"},
			wantChroot: tmpDir,
			wantUser:   "nonexistent",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := extractSessionConfig(tt.env)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg.Chroot != tt.wantChroot {
				t.Errorf("chroot: expected %q, got %q", tt.wantChroot, cfg.Chroot)
			}
			if cfg.TargetUser != tt.wantUser {
				t.Errorf("user: expected %q, got %q", tt.wantUser, cfg.TargetUser)
			}
			if cfg.UID != tt.wantUID {
				t.Errorf("UID: expected %d, got %d", tt.wantUID, cfg.UID)
			}
			if cfg.GID != tt.wantGID {
				t.Errorf("GID: expected %d, got %d", tt.wantGID, cfg.GID)
			}
		})
	}
}

// TestFilterSessionEnv tests that session environment variables are filtered out
func TestFilterSessionEnv(t *testing.T) {
	tests := []struct {
		name    string
		env     []string
		wantEnv []string
	}{
		{
			name: "filter both raft vars",
			env: []string{
				"PATH=/usr/bin",
				"RAFT_CHROOT=/mnt/rootfs",
				"HOME=/root",
				"RAFT_USER=appuser",
				"TERM=xterm",
			},
			wantEnv: []string{
				"PATH=/usr/bin",
				"HOME=/root",
				"TERM=xterm",
			},
		},
		{
			name: "filter only chroot",
			env: []string{
				"PATH=/usr/bin",
				"RAFT_CHROOT=/mnt/rootfs",
				"HOME=/root",
			},
			wantEnv: []string{
				"PATH=/usr/bin",
				"HOME=/root",
			},
		},
		{
			name: "filter only user",
			env: []string{
				"PATH=/usr/bin",
				"RAFT_USER=appuser",
				"HOME=/root",
			},
			wantEnv: []string{
				"PATH=/usr/bin",
				"HOME=/root",
			},
		},
		{
			name: "no raft vars to filter",
			env: []string{
				"PATH=/usr/bin",
				"HOME=/root",
				"TERM=xterm",
			},
			wantEnv: []string{
				"PATH=/usr/bin",
				"HOME=/root",
				"TERM=xterm",
			},
		},
		{
			name:    "empty env",
			env:     []string{},
			wantEnv: []string{},
		},
		{
			name: "similar but different var names",
			env: []string{
				"RAFT_CHROOT_BACKUP=/backup", // Should NOT be filtered
				"RAFT_USER_ID=1000",          // Should NOT be filtered
				"MY_RAFT_CHROOT=/other",      // Should NOT be filtered
				"RAFT_CHROOT=/mnt/rootfs",    // Should be filtered
				"RAFT_USER=appuser",          // Should be filtered
			},
			wantEnv: []string{
				"RAFT_CHROOT_BACKUP=/backup",
				"RAFT_USER_ID=1000",
				"MY_RAFT_CHROOT=/other",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterSessionEnv(tt.env)

			if len(filtered) != len(tt.wantEnv) {
				t.Errorf("length mismatch: expected %d, got %d", len(tt.wantEnv), len(filtered))
			}

			for i, want := range tt.wantEnv {
				if i >= len(filtered) {
					break
				}
				if filtered[i] != want {
					t.Errorf("env[%d]: expected %q, got %q", i, want, filtered[i])
				}
			}
		})
	}
}

// TestServerDirectTCPIP tests the direct-tcpip channel for remote forwarding
func TestServerDirectTCPIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Generate host key
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	// Create SSH server
	cfg := &sshServerConfig{
		Addr:         "127.0.0.1",
		Port:         0,
		HostKeys:     []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{"testuser": "testpass"},
		Shell:        "/bin/sh",
	}

	server := newSSHServer(ctx, log, cfg)

	// Start server
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Get the actual port the server is listening on
	serverPort := server.listener.Addr().(*net.TCPAddr).Port
	t.Logf("SSH server listening on port %d", serverPort)

	// Start a simple TCP echo server that we'll connect to through SSH
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer func() { _ = echoListener.Close() }()

	echoPort := echoListener.Addr().(*net.TCPAddr).Port
	t.Logf("Echo server listening on port %d", echoPort)

	// Handle echo connections
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	// Connect SSH client
	clientConfig := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), clientConfig)
	if err != nil {
		t.Fatalf("failed to connect SSH client: %v", err)
	}
	defer func() { _ = sshClient.Close() }()

	t.Log("SSH client connected successfully")

	// Use Dial to connect to the echo server through SSH (direct-tcpip)
	remoteConn, err := sshClient.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		t.Fatalf("failed to dial through SSH: %v", err)
	}
	defer func() { _ = remoteConn.Close() }()

	t.Log("Direct-TCPIP connection established")

	// Send test data
	testMsg := "Hello, direct-tcpip!"
	_, err = remoteConn.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("failed to write to remote connection: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := remoteConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from remote connection: %v", err)
	}

	response := string(buf[:n])
	if response != testMsg {
		t.Errorf("expected echo %q, got %q", testMsg, response)
	}

	t.Log("Direct-TCPIP test successful - data echoed correctly")

	// Clean shutdown
	_ = sshClient.Close()
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server shutdown timeout")
	}
}
