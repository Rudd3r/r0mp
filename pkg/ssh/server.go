package ssh

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// sshServerConfig is the internal configuration for the SSH server
type sshServerConfig struct {
	Addr           string
	Port           int
	HostKeys       []ssh.Signer
	AuthorizedKeys map[string][]ssh.PublicKey // username -> array of authorized public keys
	PasswordAuth   map[string]string          // username -> password
	Shell          string
	Env            []string
}

const (
	ServerEventFinalLayerWritten = "final-layer-written"
	ServerEventNewChrootSession  = "new-chroot-session"
)

type ServerEvent struct {
	Name       string
	Attributes map[string]string
}

type SSHServer struct {
	cfg      *sshServerConfig
	ctx      context.Context
	log      *slog.Logger
	listener net.Listener
	wg       sync.WaitGroup
	// Port forwarding state
	forwardedPorts   map[string]*forwardedPort
	forwardedPortsMu sync.Mutex
	eventCallbacks   []func(e ServerEvent)
}

// forwardedPort represents a forwarded port listener
type forwardedPort struct {
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func newSSHServer(ctx context.Context, log *slog.Logger, cfg *sshServerConfig) *SSHServer {
	return &SSHServer{
		cfg:            cfg,
		ctx:            ctx,
		log:            log,
		forwardedPorts: make(map[string]*forwardedPort),
	}
}

// NewSSHServerFromInit creates a new SSH server from domain.SSHServer configuration.
// It handles host key parsing/generation and authorized key parsing.
func NewSSHServerFromInit(ctx context.Context, log *slog.Logger, initCfg *domain.SSHServer) (*SSHServer, error) {
	if initCfg == nil || !initCfg.Enabled {
		return nil, errors.New("SSH server not enabled")
	}

	hostKey, err := ssh.ParsePrivateKey(initCfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %w", err)
	}

	// Parse authorized keys for each user
	authorizedKeys := make(map[string][]ssh.PublicKey)
	for username, keyStrings := range initCfg.AuthorizedKeys {
		userKeys := make([]ssh.PublicKey, 0, len(keyStrings))
		for _, keyStr := range keyStrings {
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
			if err != nil {
				log.Warn("failed to parse authorized key", "user", username, "error", err)
				continue
			}
			userKeys = append(userKeys, pubKey)
		}
		if len(userKeys) > 0 {
			authorizedKeys[username] = userKeys
			log.Info("loaded authorized keys", "user", username, "count", len(userKeys))
		}
	}

	// Build SSH server config
	cfg := &sshServerConfig{
		Addr:           initCfg.Addr,
		Port:           initCfg.Port,
		HostKeys:       []ssh.Signer{hostKey},
		AuthorizedKeys: authorizedKeys,
		PasswordAuth:   initCfg.PasswordAuth,
		Shell:          initCfg.Shell,
		Env:            initCfg.Env,
	}

	return newSSHServer(ctx, log, cfg), nil
}

func (s *SSHServer) RegisterEventCallback(f func(e ServerEvent)) {
	s.eventCallbacks = append(s.eventCallbacks, f)
}

func (s *SSHServer) notify(e ServerEvent) {
	for _, f := range s.eventCallbacks {
		f(e)
	}
}

func GenerateHostKey() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return privateKeyPEM, nil
}

func MustGenerateHostKey() []byte {
	privateKey, err := GenerateHostKey()
	if err != nil {
		panic(fmt.Errorf("rsa generate host key: %w", err))
	}
	return privateKey
}

func (s *SSHServer) Start() error {
	if len(s.cfg.HostKeys) == 0 {
		return errors.New("no host keys configured")
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Addr, s.cfg.Port)
	s.log.Info("starting SSH server", "addr", addr)

	config := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		PasswordCallback:  s.passwordCallback,
	}

	for _, key := range s.cfg.HostKeys {
		config.AddHostKey(key)
	}

	var err error
	s.log.Info("attempting to listen", "addr", addr)
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		s.log.Error("failed to listen", "addr", addr, "error", err)
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.log.Info("SSH server listening successfully", "addr", addr)
	s.log.Info("starting accept loop goroutine")
	go s.acceptConnections(config)
	s.log.Info("accept loop goroutine started, waiting for context cancellation")

	<-s.ctx.Done()
	s.log.Info("shutting down SSH server")

	if err := s.listener.Close(); err != nil {
		s.log.Error("error closing listener", "error", err)
	}

	s.wg.Wait()
	return nil
}

func (s *SSHServer) acceptConnections(config *ssh.ServerConfig) {
	s.log.Info("accept loop started")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				s.log.Info("accept loop stopping")
				return
			default:
				s.log.Error("failed to accept connection", "error", err)
				continue
			}
		}

		s.log.Info("accepted connection", "remote", conn.RemoteAddr())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, config)
		}()
	}
}

func (s *SSHServer) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()

	s.log.Info("new connection", "remote", conn.RemoteAddr())

	s.log.Info("starting SSH handshake", "remote", conn.RemoteAddr())
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		s.log.Error("failed to handshake", "error", err, "remote", conn.RemoteAddr())
		return
	}
	defer func() { _ = sshConn.Close() }()

	s.log.Info("handshake complete, authenticated", "user", sshConn.User(), "remote", conn.RemoteAddr())

	go s.handleGlobalRequests(sshConn, reqs)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				s.log.Error("failed to accept channel", "error", err)
				continue
			}
			go s.handleSession(channel, requests, sshConn.User())

		case "direct-tcpip":
			go s.handleDirectTCPIP(newChannel)

		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (s *SSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, user string) {
	defer func() { _ = channel.Close() }()

	var shell string
	var ptyReq *ptyRequestMsg
	var env []string
	var ptmx *os.File
	var cmdDone chan struct{}

	// Add configured environment variables
	if len(s.cfg.Env) > 0 {
		env = append(env, s.cfg.Env...)
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-cmdDone:
			// Command completed, exit the session
			return
		case req, ok := <-requests:
			if !ok {
				return
			}

			switch req.Type {
			case "pty-req":
				ptyReq = &ptyRequestMsg{}
				if err := ssh.Unmarshal(req.Payload, ptyReq); err != nil {
					s.log.Error("failed to parse pty-req", "error", err)
					_ = req.Reply(false, nil)
					continue
				}
				s.log.Info("pty requested", "term", ptyReq.Term, "width", ptyReq.Width, "height", ptyReq.Height)
				_ = req.Reply(true, nil)

			case "window-change":
				if ptyReq == nil {
					_ = req.Reply(false, nil)
					continue
				}
				winChange := &windowChangeMsg{}
				if err := ssh.Unmarshal(req.Payload, winChange); err != nil {
					s.log.Error("failed to parse window-change", "error", err)
					_ = req.Reply(false, nil)
					continue
				}
				ptyReq.Width = winChange.Width
				ptyReq.Height = winChange.Height

				// Update PTY size if we have a PTY open
				if ptmx != nil {
					if err := pty.Setsize(ptmx, &pty.Winsize{
						Rows: uint16(winChange.Height),
						Cols: uint16(winChange.Width),
					}); err != nil {
						s.log.Error("failed to set pty size", "error", err)
					} else {
						s.log.Info("window resized", "width", winChange.Width, "height", winChange.Height)
					}
				}
				_ = req.Reply(true, nil)

			case "env":
				envReq := &envRequestMsg{}
				if err := ssh.Unmarshal(req.Payload, envReq); err != nil {
					s.log.Error("failed to parse env", "error", err)
					_ = req.Reply(false, nil)
					continue
				}
				env = append(env, fmt.Sprintf("%s=%s", envReq.Name, envReq.Value))
				_ = req.Reply(true, nil)

			case "shell":
				shell = s.cfg.Shell
				if shell == "" {
					shell = "/bin/sh"
				}
				_ = req.Reply(true, nil)
				cmdDone = make(chan struct{})
				ptmx = s.runCommandWithPty(channel, shell, nil, env, ptyReq, cmdDone, false, false)
				// If no PTY was requested, command completed synchronously, exit the session
				if ptyReq == nil {
					return
				}
				// With PTY, continue loop to handle window-change requests

			case "exec":
				execReq := &execRequestMsg{}
				if err := ssh.Unmarshal(req.Payload, execReq); err != nil {
					s.log.Error("failed to parse exec", "error", err)
					_ = req.Reply(false, nil)
					continue
				}

				// Check for detach and log output flags in environment
				detach := false
				logOutput := false
				for _, e := range env {
					if strings.HasPrefix(e, EnvRaftDetach+"=") {
						detach = strings.HasSuffix(e, "=1")
					}
					if strings.HasPrefix(e, EnvRaftLogOutput+"=") {
						logOutput = strings.HasSuffix(e, "=1")
					}
				}

				_ = req.Reply(true, nil)
				cmdDone = make(chan struct{})
				ptmx = s.runCommandWithPty(channel, s.cfg.Shell, []string{"-c", execReq.Command}, env, ptyReq, cmdDone, detach, logOutput)
				// If no PTY was requested, command completed synchronously, exit the session
				if ptyReq == nil {
					return
				}
				// With PTY, continue loop to handle window-change requests

			case "subsystem":
				subsysReq := &subsystemRequestMsg{}
				if err := ssh.Unmarshal(req.Payload, subsysReq); err != nil {
					s.log.Error("failed to parse subsystem", "error", err)
					_ = req.Reply(false, nil)
					continue
				}

				s.log.Info("subsystem requested", "name", subsysReq.Subsystem, "user", user)

				switch subsysReq.Subsystem {
				case "layer-writer":
					_ = req.Reply(true, nil)
					s.handleLayerWriter(channel, user)
					return
				case "port-proxy":
					_ = req.Reply(true, nil)
					s.handlePortProxy(channel, user)
					return
				case "sftp":
					_ = req.Reply(true, nil)
					s.handleSFTP(channel, user)
					return
				default:
					s.log.Warn("unknown subsystem", "subsystem", subsysReq.Subsystem)
					_ = req.Reply(false, nil)
				}

			default:
				s.log.Warn("unknown request type", "type", req.Type)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}
}

func (s *SSHServer) runCommandWithPty(channel ssh.Channel, shell string, args []string, env []string, ptyReq *ptyRequestMsg, cmdDone chan struct{}, detach bool, logOutput bool) *os.File {
	if shell == "" {
		shell = "/bin/sh"
	}

	// Extract session configuration (chroot and user)
	sessionCfg, err := extractSessionConfig(env)
	if err != nil {
		s.log.Error("failed to extract session config", "error", err)
		_, _ = fmt.Fprintf(channel, "Failed to configure session: %v\r\n", err)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
		return nil
	}

	if sessionCfg.Chroot != "" {
		s.log.Info("session will use chroot", "chroot", sessionCfg.Chroot, "user", sessionCfg.TargetUser, "uid", sessionCfg.UID, "gid", sessionCfg.GID)
		s.notify(ServerEvent{
			Name: ServerEventNewChrootSession,
			Attributes: map[string]string{
				"target": sessionCfg.Chroot,
			},
		})
	}

	// Filter out session configuration env vars before passing to command
	filteredEnv := filterSessionEnv(env)

	// Use CommandContext so processes die when server exits (init system shutdown)
	cmd := exec.CommandContext(s.ctx, shell, args...)
	cmd.Env = filteredEnv

	// Handle detached processes - don't use PTY even if requested
	if detach {
		if ptyReq != nil {
			_, _ = fmt.Fprintf(channel, "Warning: ignoring PTY request for detached process\r\n")
		}

		// Always redirect stdin to /dev/null for detached processes
		devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			s.log.Error("failed to open /dev/null", "error", err)
			_, _ = fmt.Fprintf(channel, "Failed to open /dev/null: %v\r\n", err)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
			return nil
		}
		defer func() { _ = devNull.Close() }()

		cmd.Stdin = devNull

		// Set up stdout/stderr based on logOutput flag
		if logOutput {
			// Create pipes for logging stdout and stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				s.log.Error("failed to create stdout pipe", "error", err)
				_, _ = fmt.Fprintf(channel, "Failed to create stdout pipe: %v\r\n", err)
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
				return nil
			}

			stderr, err := cmd.StderrPipe()
			if err != nil {
				s.log.Error("failed to create stderr pipe", "error", err)
				_, _ = fmt.Fprintf(channel, "Failed to create stderr pipe: %v\r\n", err)
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
				return nil
			}

			// Set up goroutines to read and log output
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					s.log.Info("process output", "shell", shell, "stream", "stdout", "line", scanner.Text())
				}
				if err := scanner.Err(); err != nil {
					s.log.Error("error reading stdout", "shell", shell, "error", err)
				}
			}()

			go func() {
				scanner := bufio.NewScanner(stderr)
				for scanner.Scan() {
					s.log.Error("process output", "shell", shell, "stream", "stderr", "line", scanner.Text())
				}
				if err := scanner.Err(); err != nil {
					s.log.Error("error reading stderr", "shell", shell, "error", err)
				}
			}()
		} else {
			// Redirect stdout/stderr to /dev/null
			cmd.Stdout = devNull
			cmd.Stderr = devNull
		}

		// Set up process attributes for detached process
		// Setsid=true creates new session, Setctty=false prevents SIGHUP on client disconnect
		// Process will survive client disconnect but die when server context is cancelled (init system shutdown)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,  // Create new session
			Setctty: false, // Don't make this the controlling terminal (prevents SIGHUP on disconnect)
		}

		// Apply chroot if specified
		if sessionCfg.Chroot != "" {
			cmd.SysProcAttr.Chroot = sessionCfg.Chroot
			cmd.Dir = "/"
		}

		// Apply UID/GID if target user specified
		if sessionCfg.TargetUser != "" {
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: sessionCfg.UID,
				Gid: sessionCfg.GID,
			}
		}

		if err := cmd.Start(); err != nil {
			s.log.Error("failed to start detached command", "error", err)
			_, _ = fmt.Fprintf(channel, "Failed to start command: %v\r\n", err)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
			return nil
		}

		s.log.Info("detached command started", "pid", cmd.Process.Pid, "shell", shell, "args", args, "logOutput", logOutput)
		_, _ = fmt.Fprintf(channel, "Detached process started with PID %d\r\n", cmd.Process.Pid)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 0}))

		// Reap zombie in background - process will survive client disconnect
		go func() {
			_ = cmd.Wait()
			s.log.Info("detached command exited", "pid", cmd.Process.Pid)
		}()

		close(cmdDone)
		return nil
	}

	if ptyReq != nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))

		ptmx, tty, err := s.openPty()
		if err != nil {
			s.log.Error("failed to open pty", "error", err)
			_, _ = fmt.Fprintf(channel, "Failed to open pty: %v\r\n", err)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
			return nil
		}
		defer func() { _ = tty.Close() }()

		// Set initial PTY size
		if err := pty.Setsize(ptmx, &pty.Winsize{
			Rows: uint16(ptyReq.Height),
			Cols: uint16(ptyReq.Width),
		}); err != nil {
			s.log.Warn("failed to set initial pty size", "error", err)
		}

		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty

		// Set up system process attributes with chroot and credentials
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
		}

		// Apply chroot if specified
		if sessionCfg.Chroot != "" {
			cmd.SysProcAttr.Chroot = sessionCfg.Chroot
			cmd.Dir = "/" // Set working directory to root after chroot
		}

		// Apply UID/GID if target user specified
		if sessionCfg.TargetUser != "" {
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: sessionCfg.UID,
				Gid: sessionCfg.GID,
			}
		}

		if err := cmd.Start(); err != nil {
			s.log.Error("failed to start command", "error", err)
			_, _ = fmt.Fprintf(channel, "Failed to start command: %v\r\n", err)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
			_ = ptmx.Close()
			return nil
		}

		go func() {
			_, _ = io.Copy(channel, ptmx)
		}()
		go func() {
			_, _ = io.Copy(ptmx, channel)
		}()

		go func() {
			defer func() { _ = ptmx.Close() }()
			defer close(cmdDone)
			if err := cmd.Wait(); err != nil {
				exitCode := 1
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					exitCode = exitErr.ExitCode()
				}
				s.log.Info("command exited with error", "error", err, "exitCode", exitCode)
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: uint32(exitCode)}))
				return
			}

			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 0}))
		}()

		return ptmx
	} else {
		// For non-PTY mode, pipe stdin/stdout/stderr
		stdin, err := cmd.StdinPipe()
		if err != nil {
			s.log.Error("failed to create stdin pipe", "error", err)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
			return nil
		}

		cmd.Stdout = channel
		cmd.Stderr = channel

		cmd.SysProcAttr = &syscall.SysProcAttr{}
		if sessionCfg.Chroot != "" {
			cmd.SysProcAttr.Chroot = sessionCfg.Chroot
			cmd.Dir = "/" // Set working directory to root after chroot
		}
		if sessionCfg.TargetUser != "" {
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: sessionCfg.UID,
				Gid: sessionCfg.GID,
			}
		}

		if err := cmd.Start(); err != nil {
			s.log.Error("failed to start command", "error", err)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 1}))
			return nil
		}

		go func() {
			_, _ = io.Copy(stdin, channel)
			_ = stdin.Close()
		}()

		if err := cmd.Wait(); err != nil {
			exitCode := 1
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
			s.log.Info("command exited with error", "error", err, "exitCode", exitCode)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: uint32(exitCode)}))
		} else {
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 0}))
		}

		return nil
	}
}

func (s *SSHServer) openPty() (*os.File, *os.File, error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, nil, err
	}
	return ptmx, tty, nil
}

func (s *SSHServer) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if s.cfg.AuthorizedKeys == nil {
		return nil, errors.New("public key authentication not configured")
	}

	authorizedKeys, ok := s.cfg.AuthorizedKeys[conn.User()]
	if !ok {
		s.log.Warn("user not found", "user", conn.User())
		return nil, errors.New("unknown user")
	}

	for _, authorizedKey := range authorizedKeys {
		if keysEqual(key, authorizedKey) {
			s.log.Info("public key authentication successful", "user", conn.User())
			return &ssh.Permissions{}, nil
		}
	}

	s.log.Warn("key not authorized", "user", conn.User())
	return nil, errors.New("key not authorized")
}

func (s *SSHServer) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if s.cfg.PasswordAuth == nil {
		return nil, errors.New("password authentication not configured")
	}

	expectedPassword, ok := s.cfg.PasswordAuth[conn.User()]
	if !ok {
		s.log.Warn("user not found", "user", conn.User())
		return nil, errors.New("unknown user")
	}

	if expectedPassword != string(password) {
		s.log.Warn("password mismatch", "user", conn.User())
		return nil, errors.New("password mismatch")
	}

	s.log.Info("password authentication successful", "user", conn.User())
	return &ssh.Permissions{}, nil
}

func keysEqual(a, b ssh.PublicKey) bool {
	return a.Type() == b.Type() && string(a.Marshal()) == string(b.Marshal())
}

// passwdEntry represents an entry from /etc/passwd
type passwdEntry struct {
	Username string
	UID      uint32
	GID      uint32
	Home     string
	Shell    string
}

// parsePasswdFile parses /etc/passwd file and returns user information
// If chrootPath is specified, it will look for /etc/passwd inside the chroot
func parsePasswdFile(chrootPath string) (map[string]passwdEntry, error) {
	passwdPath := "/etc/passwd"
	if chrootPath != "" {
		passwdPath = filepath.Join(chrootPath, "etc/passwd")
	}

	file, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open passwd file: %w", err)
	}
	defer func() { _ = file.Close() }()

	entries := make(map[string]passwdEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: username:password:uid:gid:gecos:home:shell
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		uid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}

		gid, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil {
			continue
		}

		entries[parts[0]] = passwdEntry{
			Username: parts[0],
			UID:      uint32(uid),
			GID:      uint32(gid),
			Home:     parts[5],
			Shell:    parts[6],
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading passwd file: %w", err)
	}

	return entries, nil
}

// sessionConfig contains chroot and user information for a session
type sessionConfig struct {
	Chroot     string
	TargetUser string
	UID        uint32
	GID        uint32
}

// Environment variable names for session configuration
const (
	EnvRaftChroot    = "RAFT_CHROOT"
	EnvRaftUser      = "RAFT_USER"
	EnvRaftDetach    = "RAFT_DETACH"
	EnvRaftLogOutput = "RAFT_LOG_OUTPUT"
)

// extractSessionConfig extracts chroot and user information from environment variables
// Looks for RAFT_CHROOT and RAFT_USER environment variables
func extractSessionConfig(env []string) (*sessionConfig, error) {
	cfg := &sessionConfig{}

	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case EnvRaftChroot:
			cfg.Chroot = parts[1]
		case EnvRaftUser:
			cfg.TargetUser = parts[1]
		}
	}

	if cfg.TargetUser != "" {
		users, err := parsePasswdFile(cfg.Chroot)
		if err != nil {
			return nil, fmt.Errorf("failed to parse passwd: %w", err)
		}

		entry, ok := users[cfg.TargetUser]
		if !ok {
			return nil, fmt.Errorf("user %s not found in passwd", cfg.TargetUser)
		}

		cfg.UID = entry.UID
		cfg.GID = entry.GID
	}

	return cfg, nil
}

// filterSessionEnv removes session configuration environment variables
// These should not be passed to child processes
func filterSessionEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, EnvRaftChroot+"=") ||
			strings.HasPrefix(e, EnvRaftUser+"=") ||
			strings.HasPrefix(e, EnvRaftDetach+"=") ||
			strings.HasPrefix(e, EnvRaftLogOutput+"=") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

type ptyRequestMsg struct {
	Term     string
	Width    uint32
	Height   uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type windowChangeMsg struct {
	Width    uint32
	Height   uint32
	WidthPx  uint32
	HeightPx uint32
}

type envRequestMsg struct {
	Name  string
	Value string
}

type execRequestMsg struct {
	Command string
}

type subsystemRequestMsg struct {
	Subsystem string
}

type exitStatusMsg struct {
	Status uint32
}

type tcpipForwardMsg struct {
	BindAddr string
	BindPort uint32
}

type tcpipForwardReplyMsg struct {
	BoundPort uint32
}

type cancelTcpipForwardMsg struct {
	BindAddr string
	BindPort uint32
}

type forwardedTCPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type directTCPIPMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// handleGlobalRequests processes global SSH requests like tcpip-forward
func (s *SSHServer) handleGlobalRequests(sshConn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			s.handleTCPIPForward(sshConn, req)
		case "cancel-tcpip-forward":
			s.handleCancelTCPIPForward(req)
		default:
			s.log.Warn("unknown global request", "type", req.Type)
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// handleTCPIPForward handles a tcpip-forward request
func (s *SSHServer) handleTCPIPForward(sshConn *ssh.ServerConn, req *ssh.Request) {
	var forwardReq tcpipForwardMsg
	if err := ssh.Unmarshal(req.Payload, &forwardReq); err != nil {
		s.log.Error("failed to unmarshal tcpip-forward request", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	s.log.Info("tcpip-forward request", "addr", forwardReq.BindAddr, "port", forwardReq.BindPort)

	bindAddr := forwardReq.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	addr := fmt.Sprintf("%s:%d", bindAddr, forwardReq.BindPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.log.Error("failed to listen for port forwarding", "addr", addr, "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	boundPort := uint32(listener.Addr().(*net.TCPAddr).Port)
	s.log.Info("started port forwarding", "addr", bindAddr, "port", boundPort)

	ctx, cancel := context.WithCancel(s.ctx)
	fwdPort := &forwardedPort{
		listener: listener,
		cancel:   cancel,
	}

	key := fmt.Sprintf("%s:%d", bindAddr, boundPort)
	s.forwardedPortsMu.Lock()
	s.forwardedPorts[key] = fwdPort
	s.forwardedPortsMu.Unlock()

	if req.WantReply {
		reply := tcpipForwardReplyMsg{BoundPort: boundPort}
		_ = req.Reply(true, ssh.Marshal(&reply))
	}

	fwdPort.wg.Add(1)
	go func() {
		defer fwdPort.wg.Done()
		s.acceptForwardedConnections(ctx, sshConn, listener, bindAddr, boundPort)
	}()
}

// handleCancelTCPIPForward handles a cancel-tcpip-forward request
func (s *SSHServer) handleCancelTCPIPForward(req *ssh.Request) {
	var cancelReq cancelTcpipForwardMsg
	if err := ssh.Unmarshal(req.Payload, &cancelReq); err != nil {
		s.log.Error("failed to unmarshal cancel-tcpip-forward request", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	s.log.Info("cancel-tcpip-forward request", "addr", cancelReq.BindAddr, "port", cancelReq.BindPort)

	bindAddr := cancelReq.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	key := fmt.Sprintf("%s:%d", bindAddr, cancelReq.BindPort)

	s.forwardedPortsMu.Lock()
	fwdPort, exists := s.forwardedPorts[key]
	if exists {
		delete(s.forwardedPorts, key)
	}
	s.forwardedPortsMu.Unlock()

	if !exists {
		s.log.Warn("port forwarding not found", "addr", bindAddr, "port", cancelReq.BindPort)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// Stop the forwarding
	fwdPort.cancel()
	_ = fwdPort.listener.Close()
	fwdPort.wg.Wait()

	s.log.Info("stopped port forwarding", "addr", bindAddr, "port", cancelReq.BindPort)

	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

// acceptForwardedConnections accepts connections on a forwarded port and creates SSH channels
func (s *SSHServer) acceptForwardedConnections(ctx context.Context, sshConn *ssh.ServerConn, listener net.Listener, bindAddr string, boundPort uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				// Context cancelled, normal shutdown
				return
			default:
				s.log.Error("failed to accept forwarded connection", "error", err)
				return
			}
		}

		// Get originator address
		originAddr, originPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
		originPort := uint32(0)
		_, _ = fmt.Sscanf(originPortStr, "%d", &originPort)

		s.log.Info("accepted forwarded connection", "origin", conn.RemoteAddr())

		// Open a forwarded-tcpip channel to the client
		payload := ssh.Marshal(&forwardedTCPPayload{
			DestAddr:   bindAddr,
			DestPort:   boundPort,
			OriginAddr: originAddr,
			OriginPort: originPort,
		})

		channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			s.log.Error("failed to open forwarded-tcpip channel", "error", err)
			_ = conn.Close()
			continue
		}

		go ssh.DiscardRequests(reqs)

		go func() {
			defer func() { _ = conn.Close() }()
			defer func() { _ = channel.Close() }()

			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(channel, conn)
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(conn, channel)
				done <- struct{}{}
			}()

			<-done
		}()
	}
}

// handleDirectTCPIP handles direct-tcpip channel requests for remote forwarding
// This allows SSH clients to use Dial() to connect to remote hosts through the server
func (s *SSHServer) handleDirectTCPIP(newChannel ssh.NewChannel) {
	var req directTCPIPMsg
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		s.log.Error("failed to unmarshal direct-tcpip request", "error", err)
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to parse request")
		return
	}

	s.log.Info("direct-tcpip request",
		"dest", fmt.Sprintf("%s:%d", req.DestAddr, req.DestPort),
		"origin", fmt.Sprintf("%s:%d", req.OriginAddr, req.OriginPort))

	// Establish connection to the target host
	destAddr := net.JoinHostPort(req.DestAddr, strconv.Itoa(int(req.DestPort)))
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		s.log.Error("failed to connect to destination", "dest", destAddr, "error", err)
		_ = newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to connect to %s: %v", destAddr, err))
		return
	}

	// Accept the channel
	channel, reqs, err := newChannel.Accept()
	if err != nil {
		s.log.Error("failed to accept direct-tcpip channel", "error", err)
		_ = destConn.Close()
		return
	}

	s.log.Info("established direct-tcpip connection", "dest", destAddr)

	// Discard any requests on this channel
	go ssh.DiscardRequests(reqs)

	// Proxy data bidirectionally
	go func() {
		defer func() { _ = destConn.Close() }()
		defer func() { _ = channel.Close() }()

		done := make(chan struct{}, 2)

		// Copy from SSH channel to destination
		go func() {
			_, _ = io.Copy(destConn, channel)
			done <- struct{}{}
		}()

		// Copy from destination to SSH channel
		go func() {
			_, _ = io.Copy(channel, destConn)
			done <- struct{}{}
		}()

		// Wait for one direction to complete
		<-done

		s.log.Info("direct-tcpip connection closed", "dest", destAddr)
	}()
}

// handlePortProxy handles the port-proxy subsystem (stub implementation)
func (s *SSHServer) handlePortProxy(channel ssh.Channel, user string) {
	defer func() { _ = channel.Close() }()
	s.log.Warn("port-proxy subsystem not yet implemented", "user", user)
}

// handleSFTP handles the SFTP subsystem
func (s *SSHServer) handleSFTP(channel ssh.Channel, user string) {
	defer func() { _ = channel.Close() }()
	s.log.Info("SFTP subsystem started", "user", user)

	server, err := sftp.NewServer(channel)
	if err != nil {
		s.log.Error("failed to create SFTP server", "error", err)
		return
	}
	defer func() { _ = server.Close() }()

	if err := server.Serve(); err != nil {
		if err != io.EOF {
			s.log.Error("SFTP server error", "error", err)
		}
	}

	s.log.Info("SFTP subsystem ended", "user", user)
}
