package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzPtyRequestUnmarshal fuzzes the unmarshaling of PTY request messages
func FuzzPtyRequestUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add([]byte("xterm-256color"), uint32(80), uint32(24), uint32(0), uint32(0), "")
	f.Add([]byte("xterm"), uint32(120), uint32(40), uint32(640), uint32(480), "modes")
	f.Add([]byte(""), uint32(0), uint32(0), uint32(0), uint32(0), "")
	f.Add([]byte("vt100"), uint32(1), uint32(1), uint32(1), uint32(1), "test")

	f.Fuzz(func(t *testing.T, term []byte, width, height, widthPx, heightPx uint32, modes string) {
		msg := &ptyRequestMsg{
			Term:     string(term),
			Width:    width,
			Height:   height,
			WidthPx:  widthPx,
			HeightPx: heightPx,
			Modes:    modes,
		}

		// Marshal and unmarshal
		data := ssh.Marshal(msg)

		var decoded ptyRequestMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return // Invalid data is expected
		}

		// Verify basic properties
		if decoded.Term != msg.Term {
			t.Errorf("Term mismatch: got %q, want %q", decoded.Term, msg.Term)
		}
	})
}

// FuzzWindowChangeUnmarshal fuzzes the unmarshaling of window change messages
func FuzzWindowChangeUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add(uint32(80), uint32(24), uint32(640), uint32(480))
	f.Add(uint32(0), uint32(0), uint32(0), uint32(0))
	f.Add(uint32(1), uint32(1), uint32(1), uint32(1))
	f.Add(uint32(65535), uint32(65535), uint32(65535), uint32(65535))

	f.Fuzz(func(t *testing.T, width, height, widthPx, heightPx uint32) {
		msg := &windowChangeMsg{
			Width:    width,
			Height:   height,
			WidthPx:  widthPx,
			HeightPx: heightPx,
		}

		data := ssh.Marshal(msg)

		var decoded windowChangeMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.Width != msg.Width || decoded.Height != msg.Height {
			t.Errorf("Dimension mismatch")
		}
	})
}

// FuzzEnvRequestUnmarshal fuzzes the unmarshaling of environment variable request messages
func FuzzEnvRequestUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("PATH", "/usr/bin:/bin")
	f.Add("HOME", "/home/user")
	f.Add("", "")
	f.Add("TERM", "xterm-256color")
	f.Add("LANG", "en_US.UTF-8")

	f.Fuzz(func(t *testing.T, name, value string) {
		msg := &envRequestMsg{
			Name:  name,
			Value: value,
		}

		data := ssh.Marshal(msg)

		var decoded envRequestMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.Name != msg.Name || decoded.Value != msg.Value {
			t.Errorf("Env mismatch: got %s=%s, want %s=%s",
				decoded.Name, decoded.Value, msg.Name, msg.Value)
		}
	})
}

// FuzzExecRequestUnmarshal fuzzes the unmarshaling of exec request messages
func FuzzExecRequestUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("ls -la")
	f.Add("echo hello")
	f.Add("")
	f.Add("cat /etc/passwd")
	f.Add("bash -c 'echo test'")
	f.Add(string([]byte{0, 1, 2, 3})) // Binary data

	f.Fuzz(func(t *testing.T, command string) {
		msg := &execRequestMsg{
			Command: command,
		}

		data := ssh.Marshal(msg)

		var decoded execRequestMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.Command != msg.Command {
			t.Errorf("Command mismatch: got %q, want %q", decoded.Command, msg.Command)
		}
	})
}

// FuzzSubsystemRequestUnmarshal fuzzes the unmarshaling of subsystem request messages
func FuzzSubsystemRequestUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("sftp")
	f.Add("layer-writer")
	f.Add("port-proxy")
	f.Add("")
	f.Add("unknown")

	f.Fuzz(func(t *testing.T, subsystem string) {
		msg := &subsystemRequestMsg{
			Subsystem: subsystem,
		}

		data := ssh.Marshal(msg)

		var decoded subsystemRequestMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.Subsystem != msg.Subsystem {
			t.Errorf("Subsystem mismatch: got %q, want %q", decoded.Subsystem, msg.Subsystem)
		}
	})
}

// FuzzTCPIPForwardUnmarshal fuzzes the unmarshaling of TCP/IP forward messages
func FuzzTCPIPForwardUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("127.0.0.1", uint32(8080))
	f.Add("0.0.0.0", uint32(80))
	f.Add("", uint32(0))
	f.Add("localhost", uint32(22))
	f.Add("192.168.1.1", uint32(65535))

	f.Fuzz(func(t *testing.T, bindAddr string, bindPort uint32) {
		msg := &tcpipForwardMsg{
			BindAddr: bindAddr,
			BindPort: bindPort,
		}

		data := ssh.Marshal(msg)

		var decoded tcpipForwardMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.BindAddr != msg.BindAddr || decoded.BindPort != msg.BindPort {
			t.Errorf("TCPIPForward mismatch")
		}
	})
}

// FuzzCancelTCPIPForwardUnmarshal fuzzes the unmarshaling of cancel TCP/IP forward messages
func FuzzCancelTCPIPForwardUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("127.0.0.1", uint32(8080))
	f.Add("0.0.0.0", uint32(80))
	f.Add("", uint32(0))

	f.Fuzz(func(t *testing.T, bindAddr string, bindPort uint32) {
		msg := &cancelTcpipForwardMsg{
			BindAddr: bindAddr,
			BindPort: bindPort,
		}

		data := ssh.Marshal(msg)

		var decoded cancelTcpipForwardMsg
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.BindAddr != msg.BindAddr || decoded.BindPort != msg.BindPort {
			t.Errorf("CancelTCPIPForward mismatch")
		}
	})
}

// FuzzForwardedTCPPayloadUnmarshal fuzzes the unmarshaling of forwarded TCP payload messages
func FuzzForwardedTCPPayloadUnmarshal(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("example.com", uint32(443), "192.168.1.1", uint32(54321))
	f.Add("localhost", uint32(8080), "127.0.0.1", uint32(12345))
	f.Add("", uint32(0), "", uint32(0))

	f.Fuzz(func(t *testing.T, destAddr string, destPort uint32, originAddr string, originPort uint32) {
		msg := &forwardedTCPPayload{
			DestAddr:   destAddr,
			DestPort:   destPort,
			OriginAddr: originAddr,
			OriginPort: originPort,
		}

		data := ssh.Marshal(msg)

		var decoded forwardedTCPPayload
		if err := ssh.Unmarshal(data, &decoded); err != nil {
			return
		}

		if decoded.DestAddr != msg.DestAddr || decoded.DestPort != msg.DestPort {
			t.Errorf("ForwardedTCPPayload mismatch")
		}
	})
}

// FuzzPublicKeyParsing fuzzes SSH public key parsing
func FuzzPublicKeyParsing(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Generate a valid key for seed corpus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}

	sshPublicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		f.Fatal(err)
	}

	authorizedKey := ssh.MarshalAuthorizedKey(sshPublicKey)

	// Add seed corpus
	f.Add(authorizedKey)
	f.Add([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTest test@example.com"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, keyData []byte) {
		// Try to parse as authorized key
		_, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
		if err != nil {
			return // Invalid keys are expected
		}
	})
}

// FuzzPasswordCallback fuzzes password authentication callback
func FuzzPasswordCallback(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Add seed corpus
	f.Add("user1", "password123")
	f.Add("admin", "admin")
	f.Add("", "")
	f.Add("root", "")
	f.Add("test", string([]byte{0, 1, 2, 3}))

	f.Fuzz(func(t *testing.T, username, password string) {
		// Create test server config
		cfg := &sshServerConfig{
			PasswordAuth: map[string]string{
				"testuser": "testpass",
				"admin":    "secret",
			},
		}

		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		server := newSSHServer(context.Background(), log, cfg)

		// Create mock connection metadata
		mockConn := &mockConnMetadata{user: username}

		// Test password callback
		_, err := server.passwordCallback(mockConn, []byte(password))

		// We expect errors for invalid credentials
		if username == "testuser" && password == "testpass" {
			if err != nil {
				t.Errorf("Valid credentials rejected: %v", err)
			}
		}
	})
}

// FuzzKeysEqual fuzzes the SSH key comparison function
func FuzzKeysEqual(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Generate test keys
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}

	pubKey1, err := ssh.NewPublicKey(&key1.PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	pubKey2, err := ssh.NewPublicKey(&key2.PublicKey)
	if err != nil {
		f.Fatal(err)
	}

	// Seed with marshaled key data
	f.Add(pubKey1.Marshal(), pubKey1.Marshal())
	f.Add(pubKey1.Marshal(), pubKey2.Marshal())

	f.Fuzz(func(t *testing.T, data1, data2 []byte) {
		// Try to parse both as public keys
		key1, err := ssh.ParsePublicKey(data1)
		if err != nil {
			return
		}

		key2, err := ssh.ParsePublicKey(data2)
		if err != nil {
			return
		}

		// Test equality function
		result := keysEqual(key1, key2)

		// Verify reflexivity: key equals itself
		if bytes.Equal(data1, data2) {
			if !keysEqual(key1, key1) {
				t.Errorf("Key should equal itself")
			}
		}

		// Verify symmetry
		if result != keysEqual(key2, key1) {
			t.Errorf("keysEqual not symmetric")
		}
	})
}

// mockAddr implements net.Addr for testing
type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }

// mockConnMetadata implements ssh.ConnMetadata for testing
type mockConnMetadata struct {
	user string
}

func (m *mockConnMetadata) User() string          { return m.user }
func (m *mockConnMetadata) SessionID() []byte     { return []byte("test-session") }
func (m *mockConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-Test") }
func (m *mockConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-Test") }
func (m *mockConnMetadata) RemoteAddr() net.Addr  { return &mockAddr{addr: "127.0.0.1:12345"} }
func (m *mockConnMetadata) LocalAddr() net.Addr   { return &mockAddr{addr: "127.0.0.1:22"} }
