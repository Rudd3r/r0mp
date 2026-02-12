package domain

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

const (
	InitConfigPath = "/etc/raft.cfg"
	InitFSBinPath  = "/bin/raftinit"

	RaftStateUnknown  = "unknown"
	RaftStateCreated  = "created"
	RaftStateStarting = "starting"
	RaftStateReady    = "ready"
	RaftStateRunning  = "running"
	RaftStateStopped  = "stopped"

	sshHostKey   = "ssh-host"
	sshClientKey = "ssh-client"
)

type Raft struct {
	RaftID     string
	Name       string
	State      string
	Created    time.Time
	Started    time.Time
	Stopped    time.Time
	Cmd        []string
	Entrypoint []string
	Env        []string
	Hostname   string
	Image      string
	User       string
	WorkingDir string

	RaftDir         string
	KernelPath      string
	InitPath        string
	InitCommand     string
	QemuPath        string
	DiskImagePath   string
	SerialLogPath   string
	QemuLogPath     string
	KernelAppend    string
	RestrictNetwork bool
	Memory          string
	CPU             uint
	VolumeSizeBytes int64
	Ports           []Ports
	FSShares        []FSShare
	BalloonDevice   bool

	EgressProxyPolicyName string
	IngressProxyPorts     []IngressProxyPort

	SSHServerPort Ports
	ProxyCertPEM  []byte
	Secrets       []byte
	QemuPID       int
	RaftPID       int

	unlocker SecretReadWriter
}

var (
	adjectives = []string{
		"Swift", "Brave", "Clever", "Gentle", "Fierce",
		"Wild", "Calm", "Bold", "Sly", "Wise",
		"Proud", "Shy", "Eager", "Loyal", "Noble",
	}
	otterSpecies = []string{
		"EnhydraLutris",          // Sea Otter
		"LontraCanadensis",       // North American River Otter
		"PteronuraBrasiliensis",  // Giant Otter
		"AonyxCinereus",          // Asian Small-Clawed
		"LutraLutra",             // Eurasian Otter
		"LutrogalePerspicillata", // Smooth-Coated
		"LutraSumatrana",         // Hairy-Nosed
		"HydrictisMaculicollis",  // Spotted-Necked
		"LontraLongicaudis",      // Neotropical
		"AonyxCongicus",          // Congo Clawless
		"AonyxCapensis",          // Cape Clawless
		"LontraFelina",           // Marine Otter
		"LontraProvocax",         // Southern River Otter
	}
)

func OpenRaft(path string) (*Raft, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading raft %s: %w", path, err)
	}
	raft := &Raft{}
	if err := json.Unmarshal(data, raft); err != nil {
		return nil, fmt.Errorf("unmarshalling raft %s: %w", path, err)
	}
	return raft, nil
}

func RandomName() string {
	first := adjectives[rand.IntN(len(adjectives))]
	last := otterSpecies[rand.IntN(len(otterSpecies))]
	return first + last
}

func NewRaft() *Raft {
	return &Raft{
		Name:            RandomName(),
		Created:         time.Now(),
		State:           RaftStateCreated,
		RaftID:          uuid.NewString()[0:8],
		Memory:          DefaultMemorySize,
		CPU:             DefaultCpuCount,
		VolumeSizeBytes: DefaultVolumeSizeBytes,
		InitCommand:     InitFSBinPath,
		RestrictNetwork: true,
	}
}

func (s *Raft) Unlock(unlocker SecretReadWriter) (err error) {
	unlocker.Reset()
	s.unlocker = unlocker
	_, err = io.Copy(s.unlocker, bytes.NewReader(s.Secrets))
	if err != nil {
		return err
	}
	return s.unlocker.Unlock()
}

func (s *Raft) GetEnvironment() map[string]string {
	env := make(map[string]string)
	for _, e := range s.Env {
		split := strings.SplitN(e, "=", 2)
		if len(split) != 2 {
			continue
		}
		env[split[0]] = split[1]
	}
	return env
}

func (s *Raft) Save() error {
	if s.unlocker != nil {
		if err := s.unlocker.Lock(); err != nil {
			return fmt.Errorf("writing secret: %w", err)
		}
		s.Secrets = s.unlocker.Bytes()
		s.unlocker.Reset()
		if err := s.Unlock(s.unlocker); err != nil {
			return fmt.Errorf("writing secret: %w", err)
		}
	}
	s.RaftPID = os.Getpid()
	data, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return fmt.Errorf("marshalling raft data: %w", err)
	}
	create, err := os.Create(filepath.Join(s.RaftDir, "raft.json"))
	if err != nil {
		return fmt.Errorf("creating raft.json: %w", err)
	}
	defer func() { _ = create.Close() }()
	if _, err := create.Write(data); err != nil {
		return fmt.Errorf("writing raft data: %w", err)
	}
	return nil
}

func (s *Raft) CreateRaftDirectory(dataDir string) error {
	if s.RaftID == "" {
		return fmt.Errorf("raft id is empty")
	}
	if dataDir == "" {
		return fmt.Errorf("raft dir is empty")
	}
	s.RaftDir = filepath.Join(dataDir, s.RaftID)
	s.DiskImagePath = filepath.Join(s.RaftDir, "disk.img")
	s.KernelPath = filepath.Join(s.RaftDir, "vmlinuz")
	s.InitPath = filepath.Join(s.RaftDir, "initrd.gz")
	s.SerialLogPath = filepath.Join(s.RaftDir, fmt.Sprintf("serial.%d.log", time.Now().UnixNano()))
	s.QemuLogPath = filepath.Join(s.RaftDir, fmt.Sprintf("qemu.%d.log", time.Now().UnixNano()))
	return EnsureDir(s.RaftDir)
}

func (s *Raft) WithImage(imgCfg *v1.ConfigFile) *Raft {
	s.Image = imgCfg.Config.Image
	s.Cmd = imgCfg.Config.Cmd
	s.Entrypoint = imgCfg.Config.Entrypoint
	s.Env = imgCfg.Config.Env
	s.User = imgCfg.Config.User
	s.WorkingDir = imgCfg.Config.WorkingDir
	return s
}

func (s *Raft) WithProxyPolicy(policy string) *Raft {
	s.EgressProxyPolicyName = policy
	return s
}

func (s *Raft) SetEnv(key, val string) *Raft {
	for i, e := range s.Env {
		split := strings.SplitN(e, "=", 2)
		if len(split) == 2 && split[0] == key {
			s.Env[i] = val
		}
	}
	return s
}

func (s *Raft) WithCPU(cpu uint) *Raft {
	s.CPU = cpu
	return s
}

func (s *Raft) WithVolumeSizeBytes(size int64) *Raft {
	s.VolumeSizeBytes = size
	return s
}

func (s *Raft) WithSSHPort(port uint64) *Raft {
	s.SSHServerPort = Ports{
		HostPort:  port,
		GuestPort: SSHServerGuestPort,
		GuestIP:   GuestPrivateIP,
	}
	return s
}

func (s *Raft) WithName(name string) *Raft {
	s.Name = name
	return s
}

func (s *Raft) WithProxyCert(cert []byte) *Raft {
	s.ProxyCertPEM = cert
	return s
}

func (s *Raft) WithMemory(mem string) *Raft {
	s.Memory = mem
	return s
}

func (s *Raft) WithSSHHostKey(key *rsa.PrivateKey) (err error) {
	return s.unlocker.SetSSHKey(sshHostKey, key)
}

func (s *Raft) GetSSHHostKey() (*rsa.PrivateKey, error) {
	return s.unlocker.GetSSHKey(sshHostKey)
}

func (s *Raft) WithSSHClientKey(key *rsa.PrivateKey) (err error) {
	return s.unlocker.SetSSHKey(sshClientKey, key)
}

func (s *Raft) GetSSHClientKey() (*rsa.PrivateKey, error) {
	return s.unlocker.GetSSHKey(sshClientKey)
}

func (s *Raft) QueryState() (state string, err error) {
	defer func() {
		s.State = state
	}()

	if s.unlocker == nil {
		return "", fmt.Errorf("secrets not unlocked")
	}

	privateKey, err := s.unlocker.GetSSHKey(sshClientKey)
	if err != nil {
		return "", fmt.Errorf("getting ssh client key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return RaftStateUnknown, fmt.Errorf("parsing private key: %w", err)
	}

	switch s.State {
	case RaftStateCreated, RaftStateReady:
		return s.State, nil
	}

	if s.RaftPID != 0 {
		running, _ := IsProcessRunning(s.RaftPID)
		if !running {
			return RaftStateStopped, nil
		}
	}

	if s.QemuPID != 0 {
		running, _ := IsProcessRunning(s.QemuPID)
		if !running {
			return RaftStateStopped, nil
		}
	}

	if s.State == RaftStateStarting {
		return s.State, nil
	}

	config := &ssh.ClientConfig{
		User: SSHManagementUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", s.SSHServerPort.HostPort), config)
	if err != nil {
		return RaftStateStopped, nil
	}
	defer func() { _ = sshClient.Close() }()

	// TODO add health check command to ssh server
	return RaftStateRunning, nil
}

func IsProcessRunning(pid int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("invalid pid %d", pid)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	// Platform-specific check
	switch runtime.GOOS {
	case "windows":
		// On Windows, os.FindProcess typically succeeds if the PID is valid,
		// but it doesn't guarantee the process is still running;
		// however, trying to signal the process can reveal its status.
		// As of Go 1.23, internal changes help, but the general recommendation
		// is often to use the FindProcess return value on Windows.
		// For a reliable check, sending a signal is best practice across platforms.
		err = process.Signal(syscall.Signal(0))
		if err == nil {
			return true, nil
		}
		// If an error occurs, the process is likely not running or we lack permissions.
		// Common errors indicate the process is gone.
		if err.Error() == "os: process already finished" {
			return false, nil
		}

	case "linux", "darwin", "freebsd":
		// On Unix systems, os.FindProcess always succeeds and returns a *Process
		// for the given pid, regardless of whether the process exists.
		// To check if it actually exists, we must send an "empty" signal (0).
		err = process.Signal(syscall.Signal(0))
		if err == nil {
			return true, nil
		}

		// Check specific syscall errors
		var errno syscall.Errno
		ok := errors.As(err, &errno)
		if !ok {
			return false, err
		}
		switch {
		case errors.Is(errno, syscall.ESRCH): // No such process
			return false, nil
		case errors.Is(errno, syscall.EPERM): // Operation not permitted (process exists, but we can't signal it)
			return true, nil
		}
	default:
		// Fallback for other operating systems
		return false, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Default to false if the error wasn't explicitly handled above
	return false, err
}
