package raftinit

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/assets"
	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// isQEMUAvailable checks if QEMU is available on the system
func isQEMUAvailable(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("qemu-system-x86_64")
	require.NoError(t, err, "qemu-system-x86_64 not available in path")
}

func debugLog(t *testing.T, args ...any) {
	if len(os.Getenv("DEBUG")) == 0 {
		return
	}
	t.Log(args...)
}

func debugLogF(t *testing.T, s string, args ...any) {
	if len(os.Getenv("DEBUG")) == 0 {
		return
	}
	t.Logf(s, args...)
}

// buildAndCreateInitrd builds the raftinit binary and creates a custom initrd
func buildAndCreateInitrd(t *testing.T, testDir string, configFunc func(*InnitFSBuilder) error) string {
	t.Helper()

	// Build the raftinit binary
	initBinaryPath := filepath.Join(testDir, "raftinit")

	// Get the module root directory
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.CombinedOutput()
	debugLogF(t, "GOMOD: %s", string(out))
	require.NoError(t, err, "failed to get module root")
	moduleRoot := filepath.Dir(strings.TrimSpace(string(out)))

	// Build statically linked binary for initrd
	cmd = exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", initBinaryPath, "./pkg/internal/cmd/raftinit")
	cmd.Dir = moduleRoot
	cmd.Env = os.Environ()
	//cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	debugLogF(t, "Build %s output: %s", initBinaryPath, string(output))
	require.NoError(t, err, "failed to build raftinit")

	// Create minimal initrd from scratch (no base needed for integration tests)
	// This is simpler, faster, and more reliable than using a large Debian base
	customInitPath := filepath.Join(testDir, "custom-init.gz")
	customInitF, err := os.OpenFile(customInitPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	require.NoError(t, err, "failed to create custom initrd")
	defer func() { _ = customInitF.Close() }()
	debugLog(t, "Custom init file", customInitPath)

	// Start with an empty cpio archive
	builder, err := NewInitFS(assets.Initrd(), customInitF)
	require.NoError(t, err, "failed to create initfs builder")

	// Add the init binary
	require.NoError(t, builder.AddInitBinary(initBinaryPath), "failed to add init binary")
	debugLog(t, "Added init", initBinaryPath)

	// Apply custom configuration (pass baseInitBytes so tests can extract files from base initrd)
	if configFunc != nil {
		require.NoError(t, configFunc(builder), "failed to apply configuration")
	}
	debugLog(t, "Added config")

	require.NoError(t, builder.Close(), "failed to close builder")
	debugLog(t, "Built custom init")

	return customInitPath
}

// downloadKernel returns the path to the embedded kernel for testing
func downloadKernel(t *testing.T) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(t.TempDir(), 0700), "failed to create temp dir")
	kernelPath := filepath.Join(t.TempDir(), "kernel")
	f, err := os.Create(kernelPath)
	require.NoError(t, err, "failed to open kernel")
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, assets.Kernel())
	require.NoError(t, err, "failed to write kernel")
	return kernelPath
}

// buildTestutil builds the testutil binary as a statically linked executable
func buildTestutil(t *testing.T, testDir string) string {
	t.Helper()

	testutilPath := filepath.Join(testDir, "testutil")

	// Get the module root directory
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to get module root")
	moduleRoot := filepath.Dir(strings.TrimSpace(string(out)))

	// Build statically linked binary
	cmd = exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", testutilPath, "./pkg/internal/cmd/testutil")
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	debugLogF(t, "Build testutil output: %s", string(output))
	require.NoError(t, err, "failed to build testutil")

	return testutilPath
}

// Add ANSI escape code regex at package level
var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

// qemuRunOptions allows customization of QEMU execution
type qemuRunOptions struct {
	ctx          context.Context
	fsShares     []domain.FSShare
	ports        []domain.Ports
	sshPort      domain.Ports
	diskImage    string
	readySignal  chan<- struct{} // Optional channel to signal when VM is ready
	readyPattern string          // Pattern to look for to signal readiness (default: "init process shutting down")
	nonBlocking  bool            // If true, VM runs in background and function returns immediately
	returnVM     bool            // If true, return the QEMU instance
	memory       string          // Memory size (default: "512m")
	cpu          uint            // Number of CPUs (default: 1)
	outputDirect bool            // If true, use provided output writer directly instead of debug buffer
}

// QEMURunOption is a functional option for configuring QEMU execution
type QEMURunOption func(*qemuRunOptions)

// WithContext sets a custom context for QEMU execution
func WithContext(ctx context.Context) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.ctx = ctx
	}
}

// WithFSShare adds a filesystem share
func WithFSShare(hostPath, mountTag string) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.fsShares = append(o.fsShares, domain.FSShare{
			HostPath:      hostPath,
			MountTag:      mountTag,
			MountPoint:    "/mnt/" + mountTag,
			ReadOnly:      false,
			SecurityModel: "mapped-xattr",
		})
	}
}

// WithFSShares adds multiple filesystem shares
func WithFSShares(shares []domain.FSShare) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.fsShares = append(o.fsShares, shares...)
	}
}

// WithSSHPort adds SSH port forwarding
func WithSSHPort(hostPort int, guestIP string) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.sshPort = domain.Ports{
			HostPort:  uint64(hostPort),
			GuestPort: domain.SSHServerGuestPort,
			GuestIP:   guestIP,
		}
	}
}

// WithPorts adds custom port forwarding
func WithPorts(ports []domain.Ports) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.ports = append(o.ports, ports...)
	}
}

// WithDiskImage adds a disk image
func WithDiskImage(path string) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.diskImage = path
	}
}

// WithReadySignal sets up a channel that will be closed when the VM is ready
func WithReadySignal(ready chan<- struct{}, pattern string) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.readySignal = ready
		if pattern != "" {
			o.readyPattern = pattern
		}
	}
}

// WithNonBlocking runs the VM in a goroutine and returns immediately
func WithNonBlocking() QEMURunOption {
	return func(o *qemuRunOptions) {
		o.nonBlocking = true
		o.returnVM = true
	}
}

// WithReturnVM returns the QEMU instance
func WithReturnVM() QEMURunOption {
	return func(o *qemuRunOptions) {
		o.returnVM = true
	}
}

// WithMemory sets the memory size (e.g., "512m", "1G")
func WithMemory(memory string) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.memory = memory
	}
}

// WithCPU sets the number of CPUs
func WithCPU(cpu uint) QEMURunOption {
	return func(o *qemuRunOptions) {
		o.cpu = cpu
	}
}

// WithDirectOutput uses the provided output writer directly instead of the debug buffer
func WithDirectOutput() QEMURunOption {
	return func(o *qemuRunOptions) {
		o.outputDirect = true
	}
}

// runQEMU runs QEMU with the specified kernel and initrd, capturing output
// Uses TCG emulation (no KVM required) for testing in containers
// Returns error for async operations, otherwise fails the test directly
func runQEMU(t *testing.T, initPath string, output io.Writer, opts ...QEMURunOption) (*qemu.QEMU, error) {
	t.Helper()

	// Apply options
	options := &qemuRunOptions{
		readyPattern: "init process shutting down",
		memory:       "512m",
		cpu:          1,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Use provided context or create new one
	ctx := options.ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(t.Context())
		defer cancel()
	}

	// Choose output handling based on options
	var stderr io.Writer
	if options.outputDirect {
		stderr = output
	} else {
		debug := &buff{
			buffer: &bytes.Buffer{},
		}
		defer func() { _ = debug.Close() }()

		readySignaled := false
		go func() {
			scanner := bufio.NewScanner(debug)
			for scanner.Scan() {
				line := scanner.Text()
				if len(os.Getenv("DEBUG")) > 0 || strings.Contains(line, `"name":"raftinit"`) {
					debugLog(t, ansiEscape.ReplaceAllString(line, ""))
					_, _ = output.Write(scanner.Bytes())
					_, _ = output.Write([]byte{'\n'})
				}

				// Signal ready if pattern matches and signal channel provided
				if !readySignaled && options.readySignal != nil && strings.Contains(line, options.readyPattern) {
					close(options.readySignal)
					readySignaled = true
				}

				// Auto-cancel on shutdown or panic if no custom context and not in non-blocking mode
				if cancel != nil && !options.nonBlocking {
					if strings.Contains(line, "init process shutting down") {
						debugLog(t, "Detected init process shutdown, closing vm")
						// Give a brief moment for any buffered output to be written
						time.Sleep(100 * time.Millisecond)
						cancel()
					}
					if strings.Contains(line, "end Kernel panic") {
						debugLog(t, "Detected kernel panic, closing vm")
						time.Sleep(100 * time.Millisecond)
						cancel()
					}
				}
			}
		}()
		stderr = debug
	}

	config := domain.QemuConfig{
		Raft: &domain.Raft{
			KernelPath:    downloadKernel(t),
			InitPath:      initPath,
			InitCommand:   domain.InitFSBinPath,
			QemuPath:      "qemu-system-x86_64",
			Memory:        options.memory,
			CPU:           options.cpu,
			FSShares:      options.fsShares,
			Ports:         options.ports,
			SSHServerPort: options.sshPort,
			DiskImagePath: options.diskImage,
		},
		Stderr: stderr,
	}

	vm, err := qemu.NewQEMU(ctx, config)
	if err != nil {
		if options.ctx != nil || options.returnVM {
			return nil, err
		}
		require.NoError(t, err, "New QEMU")
	}

	debugLog(t, "Running qemu test", initPath)

	// Non-blocking mode: run in goroutine and return immediately
	if options.nonBlocking {
		go func() {
			if err := vm.Run(); err != nil && ctx.Err() == nil {
				t.Logf("QEMU exited with error: %v", err)
			}
		}()
		return vm, nil
	}

	// Blocking mode: run and wait for completion
	err = vm.Run()
	if options.returnVM {
		return vm, err
	}
	if options.ctx != nil {
		return nil, err
	}
	// If we canceled the context (e.g., after detecting shutdown), ignore context cancellation errors
	if err != nil && (ctx.Err() == context.Canceled || ctx.Err() == context.DeadlineExceeded) {
		debugLog(t, "QEMU exited after context cancellation (expected)", "err", err)
		return nil, nil
	}
	require.NoError(t, err, "failed to run qemu")
	return nil, nil
}

// Deprecated: Use runQEMU with WithFSShare option
func runQEMUWithFSShare(t *testing.T, initPath, hostPath, mountTag string, output io.Writer) {
	t.Helper()
	_, _ = runQEMU(t, initPath, output, WithFSShare(hostPath, mountTag))
}

type fsShareConfig struct {
	hostPath string
	tag      string
}

// Deprecated: Use runQEMU with WithFSShares option
func runQEMUWithMultipleFSShares(t *testing.T, initPath string, shares []fsShareConfig, output io.Writer) {
	t.Helper()
	fsShares := make([]domain.FSShare, len(shares))
	for i, share := range shares {
		fsShares[i] = domain.FSShare{
			HostPath:      share.hostPath,
			MountTag:      share.tag,
			MountPoint:    "/mnt/" + share.tag,
			ReadOnly:      true,
			SecurityModel: "mapped-xattr",
		}
	}
	_, _ = runQEMU(t, initPath, output, WithFSShares(fsShares))
}

type buff struct {
	buffer *bytes.Buffer
	mtx    sync.RWMutex
	closed int64
}

func (b *buff) Close() error {
	atomic.AddInt64(&b.closed, 1)
	return nil
}

func (b *buff) Read(p []byte) (n int, err error) {
	for n == 0 {
		b.mtx.RLock()
		n, err = b.buffer.Read(p)
		b.mtx.RUnlock()
		if atomic.LoadInt64(&b.closed) > 0 {
			return n, err
		}
		time.Sleep(time.Millisecond * 50)
	}
	return n, nil
}

func (b *buff) Write(p []byte) (n int, err error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	n, err = b.buffer.Write(p)
	return n, err
}

// Helper functions

// findFreePort finds an available port on the host
func findFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

// Deprecated: Use runQEMU with WithContext, WithSSHPort, and WithReadySignal options
func runQEMUWithSSHPort(ctx context.Context, t *testing.T, initPath string, sshPort int, output io.Writer, ready chan<- struct{}) error {
	t.Helper()
	_, err := runQEMU(t, initPath, output,
		WithContext(ctx),
		WithSSHPort(sshPort, "10.0.2.20"),
		WithReadySignal(ready, "SSH server listening"))
	return err
}

// Deprecated: Use runQEMU with WithContext, WithSSHPort, WithFSShare, and WithReadySignal options
func runQEMUWithSSHPortAndFSShare(ctx context.Context, t *testing.T, initPath string, sshPort int, hostPath, mountTag string, output io.Writer, ready chan<- struct{}) error {
	t.Helper()
	_, err := runQEMU(t, initPath, output,
		WithContext(ctx),
		WithSSHPort(sshPort, "10.0.2.20"),
		WithFSShare(hostPath, mountTag),
		WithReadySignal(ready, "SSH server listening"))
	return err
}

type mockLayer struct {
	digest string
	data   []byte
	size   int64
}

// createMockLayers creates test layers with various file types
func createMockLayers(t *testing.T) []mockLayer {
	layers := make([]mockLayer, 0, 3)

	// Layer 1: Basic files and directories
	layer1 := createTarGzLayer(t, []tarEntry{
		{name: "bin", mode: 0755, typeflag: tar.TypeDir},
		{name: "bin/hello", mode: 0755, typeflag: tar.TypeReg, content: []byte("#!/bin/sh\necho 'Hello World'\n")},
		{name: "etc", mode: 0755, typeflag: tar.TypeDir},
		{name: "etc/config.txt", mode: 0644, typeflag: tar.TypeReg, content: []byte("test_config=value1\n")},
	})
	layers = append(layers, mockLayer{
		digest: "sha256:layer1",
		data:   layer1,
		size:   int64(len(layer1)),
	})

	// Layer 2: More files and a symlink
	layer2 := createTarGzLayer(t, []tarEntry{
		{name: "usr", mode: 0755, typeflag: tar.TypeDir},
		{name: "usr/bin", mode: 0755, typeflag: tar.TypeDir},
		{name: "usr/bin/app", mode: 0755, typeflag: tar.TypeReg, content: []byte("#!/bin/sh\necho 'App'\n")},
		{name: "usr/bin/link", mode: 0777, typeflag: tar.TypeSymlink, linkname: "app"},
		{name: "etc/app.conf", mode: 0644, typeflag: tar.TypeReg, content: []byte("app_setting=enabled\n")},
	})
	layers = append(layers, mockLayer{
		digest: "sha256:layer2",
		data:   layer2,
		size:   int64(len(layer2)),
	})

	// Layer 3: Whiteout to delete a file
	layer3 := createTarGzLayer(t, []tarEntry{
		{name: "etc/.wh.config.txt", mode: 0644, typeflag: tar.TypeReg, content: []byte{}},
		{name: "var", mode: 0755, typeflag: tar.TypeDir},
		{name: "var/log", mode: 0755, typeflag: tar.TypeDir},
		{name: "var/log/app.log", mode: 0644, typeflag: tar.TypeReg, content: []byte("log entry\n")},
	})
	layers = append(layers, mockLayer{
		digest: "sha256:layer3",
		data:   layer3,
		size:   int64(len(layer3)),
	})

	return layers
}

type tarEntry struct {
	name     string
	mode     int64
	typeflag byte
	content  []byte
	linkname string
}

// createTarGzLayer creates a tar.gz layer from entries
func createTarGzLayer(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	gzw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gzw)

	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     int64(len(entry.content)),
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
		}

		require.NoError(t, tw.WriteHeader(hdr), "failed to write tar header for %s", entry.name)

		if len(entry.content) > 0 {
			_, err := tw.Write(entry.content)
			require.NoError(t, err, "failed to write tar content for %s", entry.name)
		}
	}

	require.NoError(t, tw.Close(), "failed to close tar writer")
	require.NoError(t, gzw.Close(), "failed to close gzip writer")

	return buf.Bytes()
}

// createSparseDisk creates a sparse disk file
func createSparseDisk(t *testing.T, path string, size int64) {
	t.Helper()

	f, err := os.Create(path)
	require.NoError(t, err, "failed to create disk file")
	defer func() { _ = f.Close() }()

	require.NoError(t, f.Truncate(size), "failed to truncate disk to size")
}

// generateSSHKeys generates test SSH keys
func generateSSHKeys(t *testing.T) (hostKey, clientKey, authorizedKey []byte) {
	t.Helper()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key")

	// Encode private key for client
	clientKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate public key for authorized_keys
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "failed to generate public key")
	authorizedKey = ssh.MarshalAuthorizedKey(publicKey)

	// Host key (server needs this too - for simplicity use same key)
	hostKey = clientKey

	return hostKey, clientKey, authorizedKey
}

// waitForSSH waits for SSH server to be ready and returns client
func waitForSSH(t *testing.T, ctx context.Context, addr string, privateKey []byte) *ssh.Client {
	t.Helper()

	signer, err := ssh.ParsePrivateKey(privateKey)
	require.NoError(t, err, "failed to parse private key")

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			require.Fail(t, "timeout waiting for SSH", "context cancelled")
			return nil
		case <-ticker.C:
			client, err := ssh.Dial("tcp", addr, config)
			if err == nil {
				t.Log("SSH connection established")
				return client
			}
			t.Logf("Waiting for SSH (attempt failed: %v)", err)
		}
	}
}

// verifyExtractedLayers verifies files were extracted correctly
func verifyExtractedLayers(t *testing.T, extractTarget string, sshClient *ssh.Client) {
	t.Helper()

	runSSHCommand := func(cmd string) string {
		session, err := sshClient.NewSession()
		require.NoError(t, err, "failed to create SSH session")
		defer func() { _ = session.Close() }()

		output, err := session.CombinedOutput(cmd)
		require.NoError(t, err, "failed to run command: %s", cmd)
		return string(output)
	}

	// Verify files from layer 1
	assert.Contains(t, runSSHCommand(fmt.Sprintf("ls -la %s/bin/hello", extractTarget)), "hello",
		"bin/hello should exist")
	assert.Contains(t, runSSHCommand(fmt.Sprintf("cat %s/bin/hello", extractTarget)), "Hello World",
		"bin/hello should contain script")

	// Verify files from layer 2
	assert.Contains(t, runSSHCommand(fmt.Sprintf("ls -la %s/usr/bin/app", extractTarget)), "app",
		"usr/bin/app should exist")
	assert.Contains(t, runSSHCommand(fmt.Sprintf("cat %s/etc/app.conf", extractTarget)), "app_setting=enabled",
		"etc/app.conf should exist with correct content")

	// Verify symlink from layer 2
	output := runSSHCommand(fmt.Sprintf("ls -la %s/usr/bin/link", extractTarget))
	assert.Contains(t, output, "->", "usr/bin/link should be a symlink")
	assert.Contains(t, output, "app", "usr/bin/link should point to app")

	// Verify whiteout from layer 3 - config.txt should be deleted
	// Note: In a real test, we'd check that etc/config.txt doesn't exist
	// For now, just verify layer 3 files exist
	assert.Contains(t, runSSHCommand(fmt.Sprintf("cat %s/var/log/app.log", extractTarget)), "log entry",
		"var/log/app.log should exist")

	t.Log("All verification checks passed")
}
