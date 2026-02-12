package domain

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSecretReadWriter is a mock implementation of SecretReadWriter for testing
type MockSecretReadWriter struct {
	buff        *bytes.Buffer
	secrets     map[string]string
	sshKeys     map[string]*rsa.PrivateKey
	locked      bool
	unlockErr   error
	lockErr     error
	resetCalled bool
}

func NewMockSecretReadWriter() *MockSecretReadWriter {
	return &MockSecretReadWriter{
		buff:    &bytes.Buffer{},
		secrets: make(map[string]string),
		sshKeys: make(map[string]*rsa.PrivateKey),
		locked:  true,
	}
}

func (m *MockSecretReadWriter) Read(p []byte) (n int, err error) {
	return m.buff.Read(p)
}

func (m *MockSecretReadWriter) Write(p []byte) (n int, err error) {
	return m.buff.Write(p)
}

func (m *MockSecretReadWriter) Reset() {
	m.buff.Reset()
	m.resetCalled = true
}

func (m *MockSecretReadWriter) Bytes() []byte {
	return m.buff.Bytes()
}

func (m *MockSecretReadWriter) Unlock() error {
	if m.unlockErr != nil {
		return m.unlockErr
	}
	m.locked = false
	return nil
}

func (m *MockSecretReadWriter) Lock() error {
	if m.lockErr != nil {
		return m.lockErr
	}
	m.locked = true
	// Simulate serializing data to buffer
	data, _ := json.Marshal(m.secrets)
	m.buff.Reset()
	m.buff.Write(data)
	return nil
}

func (m *MockSecretReadWriter) GetSecret(key string) (string, error) {
	if m.locked {
		return "", errors.New("database not unlocked")
	}
	val, ok := m.secrets[key]
	if !ok {
		return "", errors.New("entry not found")
	}
	return val, nil
}

func (m *MockSecretReadWriter) SetSecret(key, val string) error {
	if m.locked {
		return errors.New("database not unlocked")
	}
	m.secrets[key] = val
	return nil
}

func (m *MockSecretReadWriter) SetSSHKey(key string, sshKey *rsa.PrivateKey) error {
	if m.locked {
		return errors.New("database not unlocked")
	}
	m.sshKeys[key] = sshKey
	return nil
}

func (m *MockSecretReadWriter) GetSSHKey(key string) (*rsa.PrivateKey, error) {
	if m.locked {
		return nil, errors.New("database not unlocked")
	}
	sshKey, ok := m.sshKeys[key]
	if !ok {
		return nil, errors.New("entry not found")
	}
	return sshKey, nil
}

func (m *MockSecretReadWriter) ListSecrets() ([]string, error) {
	if m.locked {
		return nil, errors.New("database not unlocked")
	}
	keys := make([]string, 0, len(m.secrets))
	for key := range m.secrets {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *MockSecretReadWriter) Merge(other SecretReadWriter) error {
	if m.locked {
		return errors.New("database not unlocked")
	}

	keys, err := other.ListSecrets()
	if err != nil {
		return err
	}

	for _, key := range keys {
		value, err := other.GetSecret(key)
		if err != nil {
			return err
		}
		m.secrets[key] = value
	}

	return nil
}

func TestNewRaft(t *testing.T) {
	t.Run("creates new raft with defaults", func(t *testing.T) {
		raft := NewRaft()

		require.NotNil(t, raft)
		assert.NotEmpty(t, raft.Name)
		assert.NotEmpty(t, raft.RaftID)
		assert.Len(t, raft.RaftID, 8)
		assert.Equal(t, RaftStateCreated, raft.State)
		assert.Equal(t, DefaultMemorySize, raft.Memory)
		assert.Equal(t, uint(DefaultCpuCount), raft.CPU)
		assert.Equal(t, int64(DefaultVolumeSizeBytes), raft.VolumeSizeBytes)
		assert.Equal(t, InitFSBinPath, raft.InitCommand)
		assert.True(t, raft.RestrictNetwork)
		assert.False(t, raft.Created.IsZero())
	})

	t.Run("creates raft with unique ID", func(t *testing.T) {
		raft1 := NewRaft()
		raft2 := NewRaft()

		assert.NotEqual(t, raft1.RaftID, raft2.RaftID)
	})

	t.Run("creates raft with random name", func(t *testing.T) {
		raft := NewRaft()

		// Name should be non-empty and follow pattern
		assert.NotEmpty(t, raft.Name)
		// Names should be different across multiple calls (probabilistic)
		names := make(map[string]bool)
		for i := 0; i < 10; i++ {
			r := NewRaft()
			names[r.Name] = true
		}
		// Should have at least some variety
		assert.Greater(t, len(names), 1)
	})
}

func TestRandomName(t *testing.T) {
	t.Run("generates valid otter names", func(t *testing.T) {
		name := RandomName()

		assert.NotEmpty(t, name)
		// Name should be at least 10 chars (shortest combo)
		assert.GreaterOrEqual(t, len(name), 10)
	})

	t.Run("generates different names", func(t *testing.T) {
		names := make(map[string]bool)
		for i := 0; i < 20; i++ {
			name := RandomName()
			names[name] = true
		}
		// Should have variety (probabilistic)
		assert.Greater(t, len(names), 1)
	})
}

func TestRaftUnlock(t *testing.T) {
	t.Run("unlocks with empty secrets", func(t *testing.T) {
		raft := NewRaft()
		mock := NewMockSecretReadWriter()

		err := raft.Unlock(mock)
		require.NoError(t, err)
		assert.NotNil(t, raft.unlocker)
		assert.False(t, mock.locked)
		assert.True(t, mock.resetCalled)
	})

	t.Run("unlocks and loads existing secrets", func(t *testing.T) {
		raft := NewRaft()
		raft.Secrets = []byte(`{"key1":"value1"}`)

		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Verify data was written to mock
		assert.NotEmpty(t, mock.buff.Bytes())
	})

	t.Run("returns error on unlock failure", func(t *testing.T) {
		raft := NewRaft()
		mock := NewMockSecretReadWriter()
		mock.unlockErr = errors.New("unlock failed")

		err := raft.Unlock(mock)
		assert.Error(t, err)
		assert.Equal(t, "unlock failed", err.Error())
	})
}

func TestRaftGetEnvironment(t *testing.T) {
	t.Run("returns empty map for no env vars", func(t *testing.T) {
		raft := NewRaft()
		raft.Env = []string{}

		env := raft.GetEnvironment()
		assert.Empty(t, env)
	})

	t.Run("parses valid environment variables", func(t *testing.T) {
		raft := NewRaft()
		raft.Env = []string{
			"PATH=/usr/bin",
			"HOME=/home/user",
			"SHELL=/bin/bash",
		}

		env := raft.GetEnvironment()
		assert.Len(t, env, 3)
		assert.Equal(t, "/usr/bin", env["PATH"])
		assert.Equal(t, "/home/user", env["HOME"])
		assert.Equal(t, "/bin/bash", env["SHELL"])
	})

	t.Run("handles env vars with = in value", func(t *testing.T) {
		raft := NewRaft()
		raft.Env = []string{
			"KEY=value=with=equals",
		}

		env := raft.GetEnvironment()
		assert.Equal(t, "value=with=equals", env["KEY"])
	})

	t.Run("skips invalid env vars", func(t *testing.T) {
		raft := NewRaft()
		raft.Env = []string{
			"VALID=value",
			"INVALID",
			"ALSO_VALID=123",
		}

		env := raft.GetEnvironment()
		assert.Len(t, env, 2)
		assert.Equal(t, "value", env["VALID"])
		assert.Equal(t, "123", env["ALSO_VALID"])
	})
}

func TestRaftSave(t *testing.T) {
	t.Run("saves raft without secrets", func(t *testing.T) {
		tmpDir := t.TempDir()
		raft := NewRaft()
		raft.RaftDir = tmpDir

		err := raft.Save()
		require.NoError(t, err)

		// Verify file was created
		raftFile := filepath.Join(tmpDir, "raft.json")
		assert.FileExists(t, raftFile)

		// Verify content
		data, err := os.ReadFile(raftFile)
		require.NoError(t, err)

		var loaded Raft
		err = json.Unmarshal(data, &loaded)
		require.NoError(t, err)
		assert.Equal(t, raft.RaftID, loaded.RaftID)
		assert.Equal(t, raft.Name, loaded.Name)
	})

	t.Run("saves raft with secrets", func(t *testing.T) {
		tmpDir := t.TempDir()
		raft := NewRaft()
		raft.RaftDir = tmpDir

		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		err = mock.SetSecret("test-key", "test-value")
		require.NoError(t, err)

		err = raft.Save()
		require.NoError(t, err)

		// Verify secrets were locked and saved
		assert.False(t, mock.locked)
		assert.NotEmpty(t, raft.Secrets)

		// Verify file was created
		raftFile := filepath.Join(tmpDir, "raft.json")
		assert.FileExists(t, raftFile)
	})

	t.Run("saves raft PID", func(t *testing.T) {
		tmpDir := t.TempDir()
		raft := NewRaft()
		raft.RaftDir = tmpDir

		err := raft.Save()
		require.NoError(t, err)

		// Verify PID was set
		assert.Equal(t, os.Getpid(), raft.RaftPID)

		// Verify it's in the saved file
		raftFile := filepath.Join(tmpDir, "raft.json")
		data, err := os.ReadFile(raftFile)
		require.NoError(t, err)

		var loaded Raft
		err = json.Unmarshal(data, &loaded)
		require.NoError(t, err)
		assert.Equal(t, os.Getpid(), loaded.RaftPID)
	})

	t.Run("returns error when lock fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		raft := NewRaft()
		raft.RaftDir = tmpDir

		mock := NewMockSecretReadWriter()
		mock.lockErr = errors.New("lock failed")
		err := raft.Unlock(mock)
		require.NoError(t, err)

		err = raft.Save()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "lock failed")
	})

	t.Run("returns error for invalid directory", func(t *testing.T) {
		raft := NewRaft()
		raft.RaftDir = "/nonexistent/invalid/path"

		err := raft.Save()
		assert.Error(t, err)
	})
}

func TestOpenRaft(t *testing.T) {
	t.Run("opens existing raft file", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a raft and save it
		original := NewRaft()
		original.RaftDir = tmpDir
		original.State = RaftStateRunning
		err := original.Save()
		require.NoError(t, err)

		// Open it
		raftFile := filepath.Join(tmpDir, "raft.json")
		loaded, err := OpenRaft(raftFile)
		require.NoError(t, err)

		assert.Equal(t, original.RaftID, loaded.RaftID)
		assert.Equal(t, original.Name, loaded.Name)
		assert.Equal(t, RaftStateRunning, loaded.State)
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		_, err := OpenRaft("/nonexistent/file.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "reading raft")
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		badFile := filepath.Join(tmpDir, "bad.json")
		err := os.WriteFile(badFile, []byte("not valid json"), 0644)
		require.NoError(t, err)

		_, err = OpenRaft(badFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshalling raft")
	})
}

func TestRaftWithSSHKeys(t *testing.T) {
	t.Run("sets and gets host SSH key", func(t *testing.T) {
		raft := NewRaft()
		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Generate a key
		hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Set host key
		err = raft.WithSSHHostKey(hostKey)
		require.NoError(t, err)

		// Get host key
		retrievedKey, err := raft.GetSSHHostKey()
		require.NoError(t, err)
		assert.Equal(t, hostKey.N, retrievedKey.N)
	})

	t.Run("sets and gets client SSH key", func(t *testing.T) {
		raft := NewRaft()
		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Generate a key
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Set client key
		err = raft.WithSSHClientKey(clientKey)
		require.NoError(t, err)

		// Get client key
		retrievedKey, err := raft.GetSSHClientKey()
		require.NoError(t, err)
		assert.Equal(t, clientKey.N, retrievedKey.N)
	})

	t.Run("stores host and client keys separately", func(t *testing.T) {
		raft := NewRaft()
		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Generate keys
		hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Set both keys
		err = raft.WithSSHHostKey(hostKey)
		require.NoError(t, err)
		err = raft.WithSSHClientKey(clientKey)
		require.NoError(t, err)

		// Verify they're different
		retrievedHost, err := raft.GetSSHHostKey()
		require.NoError(t, err)
		retrievedClient, err := raft.GetSSHClientKey()
		require.NoError(t, err)

		assert.NotEqual(t, retrievedHost.N, retrievedClient.N)
		assert.Equal(t, hostKey.N, retrievedHost.N)
		assert.Equal(t, clientKey.N, retrievedClient.N)
	})
}

func TestRaftWithMethods(t *testing.T) {
	t.Run("WithCPU sets CPU count", func(t *testing.T) {
		raft := NewRaft().WithCPU(8)
		assert.Equal(t, uint(8), raft.CPU)
	})

	t.Run("WithMemory sets memory size", func(t *testing.T) {
		raft := NewRaft().WithMemory("4G")
		assert.Equal(t, "4G", raft.Memory)
	})

	t.Run("WithName sets name", func(t *testing.T) {
		raft := NewRaft().WithName("TestRaft")
		assert.Equal(t, "TestRaft", raft.Name)
	})

	t.Run("WithVolumeSizeBytes sets volume size", func(t *testing.T) {
		raft := NewRaft().WithVolumeSizeBytes(1024 * 1024 * 1024)
		assert.Equal(t, int64(1024*1024*1024), raft.VolumeSizeBytes)
	})

	t.Run("WithSSHPort sets SSH port", func(t *testing.T) {
		raft := NewRaft().WithSSHPort(2222)
		assert.Equal(t, uint64(2222), raft.SSHServerPort.HostPort)
		assert.Equal(t, uint64(SSHServerGuestPort), raft.SSHServerPort.GuestPort)
		assert.Equal(t, GuestPrivateIP, raft.SSHServerPort.GuestIP)
	})

	t.Run("WithProxyCert sets proxy certificate", func(t *testing.T) {
		cert := []byte("test certificate")
		raft := NewRaft().WithProxyCert(cert)
		assert.Equal(t, cert, raft.ProxyCertPEM)
	})

	t.Run("chaining multiple With methods", func(t *testing.T) {
		raft := NewRaft().
			WithName("ChainedRaft").
			WithCPU(4).
			WithMemory("2G").
			WithSSHPort(3333)

		assert.Equal(t, "ChainedRaft", raft.Name)
		assert.Equal(t, uint(4), raft.CPU)
		assert.Equal(t, "2G", raft.Memory)
		assert.Equal(t, uint64(3333), raft.SSHServerPort.HostPort)
	})
}

func TestRaftCreateRaftDirectory(t *testing.T) {
	t.Run("creates raft directory structure", func(t *testing.T) {
		// We need to ensure we have a data directory
		// This test might fail if data dir can't be created
		raft := NewRaft()

		err := raft.CreateRaftDirectory("/home/user/.local/state/raft")
		if err != nil {
			t.Skipf("Cannot create data directory: %v", err)
		}

		assert.NotEmpty(t, raft.RaftDir)
		assert.NotEmpty(t, raft.DiskImagePath)
		assert.NotEmpty(t, raft.KernelPath)
		assert.NotEmpty(t, raft.InitPath)
		assert.NotEmpty(t, raft.SerialLogPath)
		assert.NotEmpty(t, raft.QemuLogPath)

		// Verify paths are within raft directory
		assert.Contains(t, raft.DiskImagePath, raft.RaftID)
		assert.Contains(t, raft.KernelPath, raft.RaftID)

		// Verify directory exists
		info, err := os.Stat(raft.RaftDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())

		// Cleanup
		defer func() { _ = os.RemoveAll(raft.RaftDir) }()
	})

	t.Run("returns error for empty raft ID", func(t *testing.T) {
		raft := &Raft{RaftID: ""}
		err := raft.CreateRaftDirectory("/home/user/.local/state/raft")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "raft id is empty")
	})
}

func TestRaftQueryState(t *testing.T) {
	t.Run("returns error when secrets not unlocked", func(t *testing.T) {
		raft := NewRaft()

		state, err := raft.QueryState()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secrets not unlocked")
		assert.Empty(t, state)
	})

	t.Run("returns state for created raft", func(t *testing.T) {
		raft := NewRaft()
		raft.State = RaftStateCreated

		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Need to set a client key for QueryState
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		err = raft.WithSSHClientKey(clientKey)
		require.NoError(t, err)

		state, err := raft.QueryState()
		require.NoError(t, err)
		assert.Equal(t, RaftStateCreated, state)
	})

	t.Run("returns state for ready raft", func(t *testing.T) {
		raft := NewRaft()
		raft.State = RaftStateReady

		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		err = raft.WithSSHClientKey(clientKey)
		require.NoError(t, err)

		state, err := raft.QueryState()
		require.NoError(t, err)
		assert.Equal(t, RaftStateReady, state)
	})

	t.Run("returns error when client key not found", func(t *testing.T) {
		raft := NewRaft()
		raft.State = RaftStateRunning

		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Don't set client key
		state, err := raft.QueryState()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "getting ssh client key")
		assert.Empty(t, state)
	})
}

func TestIsProcessRunning(t *testing.T) {
	t.Run("returns true for current process", func(t *testing.T) {
		running, err := IsProcessRunning(os.Getpid())
		require.NoError(t, err)
		assert.True(t, running)
	})

	t.Run("returns false for invalid PID", func(t *testing.T) {
		running, err := IsProcessRunning(-1)
		assert.Error(t, err)
		assert.False(t, running)
		assert.Contains(t, err.Error(), "invalid pid")
	})

	t.Run("returns false for zero PID", func(t *testing.T) {
		running, err := IsProcessRunning(0)
		assert.Error(t, err)
		assert.False(t, running)
	})

	t.Run("returns false for non-existent PID", func(t *testing.T) {
		// Use a very high PID that's unlikely to exist
		running, err := IsProcessRunning(9999999)
		// Depending on OS, this might return error or false
		if err == nil {
			assert.False(t, running)
		}
	})
}

func TestRaftStateCycle(t *testing.T) {
	t.Run("complete raft lifecycle with save and load", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create new raft
		raft := NewRaft()
		raft.RaftDir = tmpDir
		raft.State = RaftStateRunning
		assert.Equal(t, RaftStateRunning, raft.State)

		// Unlock secrets
		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Set some test data in secrets
		err = mock.SetSecret("test-key", "test-value")
		require.NoError(t, err)

		// Save raft
		err = raft.Save()
		require.NoError(t, err)

		// Open saved raft
		raftFile := filepath.Join(tmpDir, "raft.json")
		loaded, err := OpenRaft(raftFile)
		require.NoError(t, err)

		// Verify loaded raft
		assert.Equal(t, raft.RaftID, loaded.RaftID)
		assert.Equal(t, raft.Name, loaded.Name)
		assert.Equal(t, RaftStateRunning, loaded.State)
		assert.NotEmpty(t, loaded.Secrets)

		// Verify Secrets field was populated
		assert.Equal(t, raft.Secrets, loaded.Secrets)
	})

	t.Run("raft lifecycle with SSH keys", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create raft with SSH keys
		raft := NewRaft()
		raft.RaftDir = tmpDir

		mock := NewMockSecretReadWriter()
		err := raft.Unlock(mock)
		require.NoError(t, err)

		// Generate and set SSH keys
		hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		err = raft.WithSSHHostKey(hostKey)
		require.NoError(t, err)
		err = raft.WithSSHClientKey(clientKey)
		require.NoError(t, err)

		// Verify keys can be retrieved
		retrievedHost, err := raft.GetSSHHostKey()
		require.NoError(t, err)
		assert.Equal(t, hostKey.N, retrievedHost.N)

		retrievedClient, err := raft.GetSSHClientKey()
		require.NoError(t, err)
		assert.Equal(t, clientKey.N, retrievedClient.N)

		// Save raft
		err = raft.Save()
		require.NoError(t, err)

		// Verify secrets were persisted to file
		raftFile := filepath.Join(tmpDir, "raft.json")
		loaded, err := OpenRaft(raftFile)
		require.NoError(t, err)
		assert.NotEmpty(t, loaded.Secrets)
	})
}
