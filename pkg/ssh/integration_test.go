package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"golang.org/x/crypto/ssh"
)

// TestIntegrationClientServer tests full client-server interaction
func TestIntegrationClientServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	serverCfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"user1": "pass1",
			"user2": "pass2",
		},
		Shell: "/bin/sh",
		Env: []string{
			"TEST_VAR=integration_test",
			"PATH=/usr/bin:/bin",
		},
	}

	server := newSSHServer(ctx, log.With("component", "server"), serverCfg)

	go func() {
		if err := server.Start(); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Test scenarios
	t.Run("BasicCommand", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "user1",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "echo integration",
			Auth:            []ssh.AuthMethod{ssh.Password("pass1")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &stderr,
		}

		err := Client(ctx, log.With("test", "basic"), clientCfg)
		if err != nil {
			t.Fatalf("client failed: %v", err)
		}

		if !strings.Contains(stdout.String(), "integration") {
			t.Errorf("expected 'integration' in output, got: %q", stdout.String())
		}
	})

	t.Run("MultipleUsers", func(t *testing.T) {
		users := []struct {
			user string
			pass string
		}{
			{"user1", "pass1"},
			{"user2", "pass2"},
		}

		for _, u := range users {
			var stdout bytes.Buffer
			clientCfg := &domain.SSHClientConfig{
				User:            u.user,
				Host:            "127.0.0.1",
				Port:            port,
				Command:         fmt.Sprintf("echo %s", u.user),
				Auth:            []ssh.AuthMethod{ssh.Password(u.pass)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Stdout:          &stdout,
			}

			err := Client(ctx, log, clientCfg)
			if err != nil {
				t.Errorf("client failed for user %s: %v", u.user, err)
			}

			if !strings.Contains(stdout.String(), u.user) {
				t.Errorf("expected %q in output, got: %q", u.user, stdout.String())
			}
		}
	})

	t.Run("EnvironmentVariables", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "user1",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "echo $TEST_VAR",
			Auth:            []ssh.AuthMethod{ssh.Password("pass1")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
		}

		err := Client(ctx, log, clientCfg)
		if err != nil {
			t.Fatalf("client failed: %v", err)
		}

		if !strings.Contains(stdout.String(), "integration_test") {
			t.Errorf("expected 'integration_test' in output, got: %q", stdout.String())
		}
	})

	t.Run("StdinRedirection", func(t *testing.T) {
		input := "hello from stdin\n"
		stdin := bytes.NewBufferString(input)
		var stdout bytes.Buffer

		clientCfg := &domain.SSHClientConfig{
			User:            "user1",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "cat",
			Auth:            []ssh.AuthMethod{ssh.Password("pass1")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stdin:           stdin,
			Interactive:     true,
		}

		err := Client(ctx, log, clientCfg)
		if err != nil {
			t.Fatalf("client failed: %v", err)
		}

		if !strings.Contains(stdout.String(), "hello from stdin") {
			t.Errorf("expected 'hello from stdin' in output, got: %q", stdout.String())
		}
	})

	t.Run("ConcurrentConnections", func(t *testing.T) {
		numClients := 5
		errCh := make(chan error, numClients)

		for i := 0; i < numClients; i++ {
			go func(id int) {
				var stdout bytes.Buffer
				clientCfg := &domain.SSHClientConfig{
					User:            "user1",
					Host:            "127.0.0.1",
					Port:            port,
					Command:         fmt.Sprintf("echo client-%d", id),
					Auth:            []ssh.AuthMethod{ssh.Password("pass1")},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Stdout:          &stdout,
				}

				err := Client(ctx, log, clientCfg)
				if err != nil {
					errCh <- fmt.Errorf("client %d failed: %w", id, err)
					return
				}

				expected := fmt.Sprintf("client-%d", id)
				if !strings.Contains(stdout.String(), expected) {
					errCh <- fmt.Errorf("client %d: expected %q in output, got: %q", id, expected, stdout.String())
					return
				}

				errCh <- nil
			}(i)
		}

		for i := 0; i < numClients; i++ {
			select {
			case err := <-errCh:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("client %d timed out", i)
			}
		}
	})
}

// TestIntegrationPTY tests PTY functionality end-to-end
func TestIntegrationPTY(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PTY integration test in short mode")
	}

	// Skip if not on a Unix-like system
	if _, err := os.Stat("/dev/ptmx"); os.IsNotExist(err) {
		t.Skip("PTY not available on this system")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Setup server
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	serverCfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"testuser": "testpass",
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, serverCfg)

	go func() {
		if err := server.Start(); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect with SSH client and request PTY
	clientConfig := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientConfig)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Request PTY
	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		t.Fatalf("failed to request PTY: %v", err)
	}

	// Run command
	output, err := session.CombinedOutput("echo pty test")
	if err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	if !bytes.Contains(output, []byte("pty test")) {
		t.Errorf("expected 'pty test' in output, got: %q", string(output))
	}
}

// TestIntegrationAuthMethods tests different authentication methods
func TestIntegrationAuthMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping auth integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Generate key pair for public key auth
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

	// Setup server with both auth methods
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	serverCfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"passuser": "password123",
		},
		AuthorizedKeys: map[string][]ssh.PublicKey{
			"keyuser": {publicKey},
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, serverCfg)

	go func() {
		if err := server.Start(); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	t.Run("PasswordAuth", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "passuser",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "echo password auth works",
			Auth:            []ssh.AuthMethod{ssh.Password("password123")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
		}

		err := Client(ctx, log, clientCfg)
		if err != nil {
			t.Fatalf("password auth failed: %v", err)
		}

		if !strings.Contains(stdout.String(), "password auth works") {
			t.Errorf("unexpected output: %q", stdout.String())
		}
	})

	t.Run("PublicKeyAuth", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "keyuser",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "echo key auth works",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
		}

		err := Client(ctx, log, clientCfg)
		if err != nil {
			t.Fatalf("public key auth failed: %v", err)
		}

		if !strings.Contains(stdout.String(), "key auth works") {
			t.Errorf("unexpected output: %q", stdout.String())
		}
	})

	t.Run("WrongPassword", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "passuser",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "echo should not work",
			Auth:            []ssh.AuthMethod{ssh.Password("wrongpassword")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
		}

		err := Client(ctx, log, clientCfg)
		if err == nil {
			t.Error("expected authentication to fail with wrong password")
		}
	})

	t.Run("WrongUser", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "nonexistent",
			Host:            "127.0.0.1",
			Port:            port,
			Command:         "echo should not work",
			Auth:            []ssh.AuthMethod{ssh.Password("password123")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
		}

		err := Client(ctx, log, clientCfg)
		if err == nil {
			t.Error("expected authentication to fail for nonexistent user")
		}
	})
}

// TestIntegrationLongRunningCommand tests handling of long-running commands
func TestIntegrationLongRunningCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running command test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Setup server
	hostKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	serverCfg := &sshServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		HostKeys: []ssh.Signer{hostKey},
		PasswordAuth: map[string]string{
			"testuser": "testpass",
		},
		Shell: "/bin/sh",
	}

	server := newSSHServer(ctx, log, serverCfg)

	go func() {
		if err := server.Start(); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Run a command that takes some time
	var stdout bytes.Buffer
	clientCfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            port,
		Command:         "for i in 1 2 3; do echo line $i; sleep 0.1; done",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
	}

	err = Client(ctx, log, clientCfg)
	if err != nil {
		t.Fatalf("client failed: %v", err)
	}

	output := stdout.String()
	for i := 1; i <= 3; i++ {
		expected := fmt.Sprintf("line %d", i)
		if !strings.Contains(output, expected) {
			t.Errorf("expected %q in output, got: %q", expected, output)
		}
	}
}
