package raftinit

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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/assets"
	"github.com/Rudd3r/r0mp/pkg/domain"
	sshpkg "github.com/Rudd3r/r0mp/pkg/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestQEMUIntegration_SSHPasswordAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)
	// Note: Parallel execution disabled due to QEMU resource constraints

	testDir := t.TempDir()

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshtest",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Configure SSH server with password auth
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			PasswordAuth: map[string]string{
				"testuser": "testpass",
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TEST_VAR=integration_test",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPort(ctx, t, initPath, sshPort, vmOutput, vmReady)
	}()

	// Wait for VM to be ready (increased timeout for parallel test execution)
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	// Test SSH connection with password auth
	var stdout bytes.Buffer
	clientCfg := &domain.SSHClientConfig{
		User:            "testuser",
		Host:            "127.0.0.1",
		Port:            sshPort,
		Command:         "echo SSH_PASSWORD_AUTH_WORKS",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &bytes.Buffer{},
		Stdin:           &bytes.Buffer{},
	}

	clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
	defer clientCancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := sshpkg.Client(clientCtx, log, clientCfg)
	require.NoError(t, err, "SSH client should connect successfully")

	// Verify command output
	assert.Contains(t, stdout.String(), "SSH_PASSWORD_AUTH_WORKS", "SSH command should execute")

	// Test environment variable
	stdout.Reset()
	clientCfg.Command = "echo $TEST_VAR"
	clientCtx2, clientCancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer clientCancel2()
	err = sshpkg.Client(clientCtx2, log, clientCfg)
	require.NoError(t, err, "SSH client should connect successfully")
	assert.Contains(t, stdout.String(), "integration_test", "Environment variable should be set")

	// Stop the VM
	cancel()
}

// TestQEMUIntegration_SSHPublicKeyAuth tests SSH server with public key authentication
func TestQEMUIntegration_SSHPublicKeyAuth(t *testing.T) {
	isQEMUAvailable(t)
	// Note: Parallel execution disabled due to QEMU resource constraints

	testDir := t.TempDir()

	// Generate SSH key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key")

	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err, "failed to create signer")

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "failed to create public key")

	authorizedKey := string(ssh.MarshalAuthorizedKey(publicKey))

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshkeytest",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Configure SSH server with public key auth
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			AuthorizedKeys: map[string][]string{
				"root": {authorizedKey},
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPort(ctx, t, initPath, sshPort, vmOutput, vmReady)
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	// Test SSH connection with public key auth
	var stdout bytes.Buffer
	clientCfg := &domain.SSHClientConfig{
		User:            "root",
		Host:            "127.0.0.1",
		Port:            sshPort,
		Command:         "echo SSH_KEY_AUTH_WORKS",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &bytes.Buffer{},
		Stdin:           &bytes.Buffer{},
	}

	clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
	defer clientCancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = sshpkg.Client(clientCtx, log, clientCfg)
	require.NoError(t, err, "SSH client should connect successfully")

	// Verify command output
	assert.Contains(t, stdout.String(), "SSH_KEY_AUTH_WORKS", "SSH command should execute")

	// Stop the VM
	cancel()
}

// TestQEMUIntegration_SSHMultipleCommands tests executing multiple SSH commands
func TestQEMUIntegration_SSHMultipleCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)
	// Note: Parallel execution disabled due to QEMU resource constraints

	testDir := t.TempDir()

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshmulti",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Configure SSH server
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			PasswordAuth: map[string]string{
				"user": "pass",
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPort(ctx, t, initPath, sshPort, vmOutput, vmReady)
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test multiple commands
	commands := []struct {
		cmd      string
		expected string
	}{
		{"echo test1", "test1"},
		{"hostname", "sshmulti"},
		{"pwd", "/"},
		{"echo hello && echo world", "hello"},
	}

	for _, tc := range commands {
		t.Run(tc.cmd, func(t *testing.T) {
			var stdout bytes.Buffer
			clientCfg := &domain.SSHClientConfig{
				User:            "user",
				Host:            "127.0.0.1",
				Port:            sshPort,
				Command:         tc.cmd,
				Auth:            []ssh.AuthMethod{ssh.Password("pass")},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Stdout:          &stdout,
				Stderr:          &bytes.Buffer{},
				Stdin:           &bytes.Buffer{},
			}

			clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
			defer clientCancel()

			err := sshpkg.Client(clientCtx, log, clientCfg)
			require.NoError(t, err, "SSH client should connect successfully")

			assert.Contains(t, stdout.String(), tc.expected, "Command output should contain expected text")
		})
	}

	// Stop the VM
	cancel()
}

// TestQEMUIntegration_SSHWithFSShare tests SSH access to filesystem shares
func TestQEMUIntegration_SSHWithFSShare(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)
	// Note: Parallel execution disabled due to QEMU resource constraints

	testDir := t.TempDir()

	// Create a host directory with test files
	hostShareDir := filepath.Join(testDir, "host_share")
	require.NoError(t, os.MkdirAll(hostShareDir, 0755))
	testFile := filepath.Join(hostShareDir, "shared.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("SHARED_VIA_SSH\n"), 0644))

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshfs",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Add FSShare
		builder.AddFSShare(domain.FSShare{
			HostPath:      hostShareDir,
			MountTag:      "host_share",
			MountPoint:    "/mnt/shared",
			ReadOnly:      false,
			SecurityModel: "mapped-xattr",
		})

		// Configure SSH server
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			PasswordAuth: map[string]string{
				"root": "root",
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding and FSShare
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPortAndFSShare(ctx, t, initPath, sshPort, hostShareDir, "host_share", vmOutput, vmReady)
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test reading shared file via SSH
	var stdout bytes.Buffer
	clientCfg := &domain.SSHClientConfig{
		User:            "root",
		Host:            "127.0.0.1",
		Port:            sshPort,
		Command:         "cat /mnt/shared/shared.txt",
		Auth:            []ssh.AuthMethod{ssh.Password("root")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Stdout:          &stdout,
		Stderr:          &bytes.Buffer{},
		Stdin:           &bytes.Buffer{},
	}

	clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
	defer clientCancel()

	err := sshpkg.Client(clientCtx, log, clientCfg)
	require.NoError(t, err, "SSH client should connect successfully")

	assert.Contains(t, stdout.String(), "SHARED_VIA_SSH", "Should read shared file content")

	// Test listing shared directory
	stdout.Reset()
	clientCfg.Command = "ls -la /mnt/shared"
	clientCtx2, clientCancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer clientCancel2()
	err = sshpkg.Client(clientCtx2, log, clientCfg)
	require.NoError(t, err, "SSH client should connect successfully")

	assert.Contains(t, stdout.String(), "shared.txt", "Should list shared file")

	// Stop the VM
	cancel()
}

// TestQEMUIntegration_SSHConcurrentConnections tests multiple concurrent SSH connections
func TestQEMUIntegration_SSHConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)
	// Note: Parallel execution disabled due to QEMU resource constraints

	testDir := t.TempDir()

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshconcurrent",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Configure SSH server
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			PasswordAuth: map[string]string{
				"user": "pass",
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPort(ctx, t, initPath, sshPort, vmOutput, vmReady)
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test concurrent connections
	numConnections := 3
	errCh := make(chan error, numConnections)
	var wg sync.WaitGroup

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			var stdout bytes.Buffer
			clientCfg := &domain.SSHClientConfig{
				User:            "user",
				Host:            "127.0.0.1",
				Port:            sshPort,
				Command:         fmt.Sprintf("echo connection-%d", id),
				Auth:            []ssh.AuthMethod{ssh.Password("pass")},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Stdout:          &stdout,
				Stderr:          &bytes.Buffer{},
				Stdin:           &bytes.Buffer{},
			}

			clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
			defer clientCancel()

			err := sshpkg.Client(clientCtx, log, clientCfg)
			if err != nil {
				errCh <- fmt.Errorf("connection %d failed: %w", id, err)
				return
			}

			expected := fmt.Sprintf("connection-%d", id)
			if !strings.Contains(stdout.String(), expected) {
				errCh <- fmt.Errorf("connection %d: expected %q in output, got: %q", id, expected, stdout.String())
				return
			}

			errCh <- nil
		}(i)
	}

	// Wait for all connections to complete
	wg.Wait()
	close(errCh)

	// Check for errors
	for err := range errCh {
		require.NoError(t, err)
	}

	// Stop the VM
	cancel()
}

func TestQEMUIntegration_SSHLayerWriter(t *testing.T) {
	isQEMUAvailable(t)

	testDir := t.TempDir()
	extractTarget := filepath.Join(testDir, "extracted")
	require.NoError(t, os.MkdirAll(extractTarget, 0755))

	// Generate SSH keys
	hostKey, clientKey, authorizedKey := generateSSHKeys(t)

	// Get module root for finding assets
	// TODO: Re-enable when AddMkfsTools is implemented
	// cmd := exec.Command("go", "env", "GOMOD")
	// out, err := cmd.CombinedOutput()
	// require.NoError(t, err, "failed to get module root")
	// moduleRoot := filepath.Dir(strings.TrimSpace(string(out)))

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Add mkfs tools for disk formatting
		if err := builder.WriteFile(domain.FileInfo{FName: "/bin/e2fsck", FMode: 0500, Uid: 0, Gid: 0}, assets.E2fsck()); err != nil {
			return fmt.Errorf("could not add e2fsck binary: %w", err)
		}
		if err := builder.WriteFile(domain.FileInfo{FName: "/bin/mke2fs", FMode: 0500, Uid: 0, Gid: 0}, assets.Mke2fs()); err != nil {
			return fmt.Errorf("could not add mke2fs binary: %w", err)
		}

		// Configure disk formatting
		builder.AddDiskFormat(domain.DiskFormat{
			Device: "/dev/vda",
			FSType: "ext4",
			Label:  "testfs",
		})

		// Configure mount
		builder.AddMount(domain.Mount{
			Device:     "/dev/vda",
			MountPoint: extractTarget,
			FSType:     "ext4",
			Options:    []string{},
		})

		// Configure SSH server
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled:        true,
			Addr:           "0.0.0.0",
			Port:           domain.SSHServerGuestPort,
			HostKey:        hostKey,
			AuthorizedKeys: map[string][]string{"root": {string(authorizedKey)}},
			Shell:          "/bin/sh",
		})

		// Add network interface
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "testhost",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			Gateway:     net.IPv4(10, 0, 2, 2),
			DNS:         net.IPv4(10, 0, 2, 3),
			DisableIPV6: true,
		})

		return nil
	})

	// Create mock layers in memory
	layers := createMockLayers(t)

	// Start QEMU with disk and SSH port forwarding
	diskPath := filepath.Join(testDir, "disk.ext4")
	createSparseDisk(t, diskPath, 100*1024*1024)

	output := &bytes.Buffer{}
	defer func() {
		debugLogF(t, "QEMU output:\n%s", output.String())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sshPort := 2222
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		_, err := runQEMU(t, initPath, output,
			WithContext(ctx),
			WithCPU(2),
			WithDiskImage(diskPath),
			WithSSHPort(sshPort, "10.0.2.20"),
			WithReadySignal(vmReady, "SSH server listening"))
		vmErr <- err
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server a moment to fully initialize
	time.Sleep(2 * time.Second)

	// Wait for SSH to be ready
	sshClient := waitForSSH(t, ctx, fmt.Sprintf("localhost:%d", sshPort), clientKey)
	defer func() { _ = sshClient.Close() }()

	t.Log("SSH connection established")

	// Create layer client and stream layers
	layerClient := sshpkg.NewLayerClient(sshClient, slog.Default())

	for i, layer := range layers {
		t.Logf("Streaming layer %d/%d (size=%d)", i+1, len(layers), layer.size)

		reader := bytes.NewReader(layer.data)
		isFinal := i == len(layers)-1
		err := layerClient.WriteLayer(extractTarget, layer.digest, reader, layer.size, isFinal)
		require.NoError(t, err, "failed to write layer %d", i+1)

		t.Logf("Layer %d/%d extracted successfully", i+1, len(layers))
	}

	// Verify extracted files
	verifyExtractedLayers(t, extractTarget, sshClient)

	t.Log("Layer extraction test completed successfully")
}

// TestQEMUIntegration_SSHWithChroot tests SSH access to a chroot environment with user credentials
func TestQEMUIntegration_SSHWithChroot(t *testing.T) {
	isQEMUAvailable(t)
	testDir := t.TempDir()

	// Generate SSH key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key")

	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err, "failed to create signer")

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "failed to create public key")

	authorizedKey := string(ssh.MarshalAuthorizedKey(publicKey))

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshchroottest",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/approot/", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/approot/etc", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/approot/bin", FMode: 0755, Uid: 0, Gid: 0}))

		// Build testutil as a statically linked binary
		testutilPath := buildTestutil(t, testDir)
		testutilContent, err := os.ReadFile(testutilPath)
		require.NoError(t, err, "failed to read testutil")

		// Copy testutil and create utilities
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/approot/bin/testutil", FMode: 0755, Uid: 0, Gid: 0},
			testutilContent,
		))
		for _, binary := range []string{"pwd", "ls", "cat", "id", "env", "grep", "sh"} {
			require.NoError(t, builder.WriteFile(
				domain.FileInfo{FName: "/mnt/approot/bin/" + binary, FMode: 0755, Uid: 0, Gid: 0},
				testutilContent,
			))
		}

		// Create a standard chroot with bind mounts
		chroot := NewStandardChroot("approot", "/mnt/approot")
		builder.AddChroot(chroot)

		// Create /etc/passwd in the chroot with test users
		passwdContent := []byte(`root:x:0:0:root:/root:/bin/sh
appuser:x:1000:1000:Application User:/app:/bin/sh
testuser:x:1001:1001:Test User:/home/testuser:/bin/sh
nobody:x:65534:65534:Nobody:/nonexistent:/bin/false
`)
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/approot/etc/passwd", FMode: 0644, Uid: 0, Gid: 0},
			passwdContent,
		))

		// Create /etc/group in the chroot
		groupContent := []byte(`root:x:0:
appuser:x:1000:
testuser:x:1001:
nobody:x:65534:
`)
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/approot/etc/group", FMode: 0644, Uid: 0, Gid: 0},
			groupContent,
		))

		// Create home directories in the chroot
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/approot/app", FMode: 0755, Uid: 1000, Gid: 1000}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/approot/home", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/approot/home/testuser", FMode: 0755, Uid: 1001, Gid: 1001}))

		// Create test marker files in chroot
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/approot/app/app-marker.txt", FMode: 0644, Uid: 1000, Gid: 1000},
			[]byte("APP_USER_FILE"),
		))
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/approot/home/testuser/test-marker.txt", FMode: 0644, Uid: 1001, Gid: 1001},
			[]byte("TEST_USER_FILE"),
		))

		// Configure SSH server
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			AuthorizedKeys: map[string][]string{
				"root": {authorizedKey},
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPort(ctx, t, initPath, sshPort, vmOutput, vmReady)
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	// Helper function to create SSH client
	createSSHClient := func() *ssh.Client {
		config := &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}

		addr := fmt.Sprintf("127.0.0.1:%d", sshPort)
		client, err := ssh.Dial("tcp", addr, config)
		require.NoError(t, err, "failed to connect to SSH")
		return client
	}

	// Test 1: SSH into chroot as appuser (UID 1000)
	t.Run("SSH_as_appuser", func(t *testing.T) {
		client := createSSHClient()
		defer func() { _ = client.Close() }()

		session, err := client.NewSession()
		require.NoError(t, err, "failed to create session")
		defer func() { _ = session.Close() }()

		// Set environment variables
		err = session.Setenv("RAFT_CHROOT", "/mnt/approot")
		require.NoError(t, err, "failed to set RAFT_CHROOT")
		err = session.Setenv("RAFT_USER", "appuser")
		require.NoError(t, err, "failed to set RAFT_USER")

		// Run command
		output, err := session.CombinedOutput("id && pwd && cat /app/app-marker.txt")
		require.NoError(t, err, "command should succeed")

		outputStr := string(output)
		t.Logf("Output: %s", outputStr)

		// Verify running as appuser (UID 1000, GID 1000)
		assert.Contains(t, outputStr, "uid=1000(appuser)", "should run as appuser")
		assert.Contains(t, outputStr, "gid=1000(appuser)", "should have appuser gid")

		// Verify we're in the chroot (root should be /)
		assert.Contains(t, outputStr, "/", "should be in chroot root")

		// Verify can access appuser's file
		assert.Contains(t, outputStr, "APP_USER_FILE", "should access appuser's file")
	})

	// Test 2: SSH into chroot as testuser (UID 1001)
	t.Run("SSH_as_testuser", func(t *testing.T) {
		client := createSSHClient()
		defer func() { _ = client.Close() }()

		session, err := client.NewSession()
		require.NoError(t, err, "failed to create session")
		defer func() { _ = session.Close() }()

		// Set environment variables
		err = session.Setenv("RAFT_CHROOT", "/mnt/approot")
		require.NoError(t, err, "failed to set RAFT_CHROOT")
		err = session.Setenv("RAFT_USER", "testuser")
		require.NoError(t, err, "failed to set RAFT_USER")

		// Run command
		output, err := session.CombinedOutput("id && cat /home/testuser/test-marker.txt")
		require.NoError(t, err, "command should succeed")

		outputStr := string(output)
		t.Logf("Output: %s", outputStr)

		// Verify running as testuser (UID 1001, GID 1001)
		assert.Contains(t, outputStr, "uid=1001(testuser)", "should run as testuser")
		assert.Contains(t, outputStr, "gid=1001(testuser)", "should have testuser gid")

		// Verify can access testuser's file
		assert.Contains(t, outputStr, "TEST_USER_FILE", "should access testuser's file")
	})

	// Test 3: SSH into chroot as root (UID 0) - should have full access
	t.Run("SSH_as_root_in_chroot", func(t *testing.T) {
		client := createSSHClient()
		defer func() { _ = client.Close() }()

		createSession := func(t *testing.T) *ssh.Session {
			session, err := client.NewSession()
			require.NoError(t, err, "failed to create session")

			// Set environment variables
			err = session.Setenv("RAFT_CHROOT", "/mnt/approot")
			require.NoError(t, err, "failed to set RAFT_CHROOT")
			err = session.Setenv("RAFT_USER", "root")
			require.NoError(t, err, "failed to set RAFT_USER")

			return session
		}
		t.Run("id", func(t *testing.T) {
			session := createSession(t)
			defer func() { _ = session.Close() }()

			output, err := session.CombinedOutput("id")
			debugLogF(t, "Output: %s", string(output))
			require.NoError(t, err, "command should succeed")
			assert.Contains(t, string(output), "uid=0", "should run as root")
			assert.Contains(t, string(output), "gid=0", "should have root gid")
		})
		t.Run("ls -la /proc", func(t *testing.T) {
			session := createSession(t)
			defer func() { _ = session.Close() }()

			output, err := session.CombinedOutput("ls -la /proc")
			debugLogF(t, "Output: %s", string(output))
			require.NoError(t, err, "command should succeed")
			assert.Contains(t, string(output), "cpuinfo", "should have /proc mounted")
		})
		t.Run("cat /app/app-marker.txt", func(t *testing.T) {
			session := createSession(t)
			defer func() { _ = session.Close() }()

			output, err := session.CombinedOutput("cat /app/app-marker.txt")
			debugLogF(t, "Output: %s", string(output))
			require.NoError(t, err, "command should succeed")
			assert.Contains(t, string(output), "APP_USER_FILE", "root should access appuser's file")
		})
		t.Run("cat /app/app-marker.txt", func(t *testing.T) {
			session := createSession(t)
			defer func() { _ = session.Close() }()

			output, err := session.CombinedOutput("cat /home/testuser/test-marker.txt")
			debugLogF(t, "Output: %s", string(output))
			require.NoError(t, err, "command should succeed")
			assert.Contains(t, string(output), "TEST_USER_FILE", "root should access testuser's file")
		})
	})

	// Test 4: Verify RAFT_* env vars are filtered from child process
	t.Run("SSH_env_vars_filtered", func(t *testing.T) {
		client := createSSHClient()
		defer func() { _ = client.Close() }()

		session, err := client.NewSession()
		require.NoError(t, err, "failed to create session")
		defer func() { _ = session.Close() }()

		// Set environment variables
		err = session.Setenv("RAFT_CHROOT", "/mnt/approot")
		require.NoError(t, err, "failed to set RAFT_CHROOT")
		err = session.Setenv("RAFT_USER", "appuser")
		require.NoError(t, err, "failed to set RAFT_USER")

		// Run command
		output, err := session.CombinedOutput("env | grep RAFT || echo 'NO_RAFT_VARS_FOUND'")
		require.NoError(t, err, "command should succeed")

		outputStr := string(output)
		t.Logf("Output: %s", outputStr)

		// Verify RAFT_* vars are NOT in the environment
		assert.Contains(t, outputStr, "NO_RAFT_VARS_FOUND", "RAFT_* vars should be filtered")
		assert.NotContains(t, outputStr, "RAFT_CHROOT", "RAFT_CHROOT should be filtered")
		assert.NotContains(t, outputStr, "RAFT_USER", "RAFT_USER should be filtered")
	})

	t.Log("SSH chroot integration test completed successfully")
}

// TestQEMUIntegration_SSHDetachExec tests detached command execution
func TestQEMUIntegration_SSHDetachExec(t *testing.T) {
	isQEMUAvailable(t)

	testDir := t.TempDir()

	// Generate SSH key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key")

	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err, "failed to create signer")

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "failed to create public key")

	authorizedKey := string(ssh.MarshalAuthorizedKey(publicKey))

	// Find a free port for SSH
	sshPort := findFreePort(t)

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "sshdetach",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Configure SSH server
		builder.ConfigureSSHServer(&domain.SSHServer{
			Enabled: true,
			Addr:    "0.0.0.0",
			Port:    domain.SSHServerGuestPort,
			AuthorizedKeys: map[string][]string{
				"root": {authorizedKey},
			},
			HostKey: sshpkg.MustGenerateHostKey(),
			Shell:   "/bin/sh",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		})

		return nil
	})

	// Start QEMU with SSH port forwarding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vmOutput := &bytes.Buffer{}
	vmReady := make(chan struct{})
	vmErr := make(chan error, 1)

	go func() {
		vmErr <- runQEMUWithSSHPort(ctx, t, initPath, sshPort, vmOutput, vmReady)
	}()

	// Wait for VM to be ready
	select {
	case <-vmReady:
	case err := <-vmErr:
		t.Fatalf("VM failed to start: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timeout waiting for VM to start")
	}

	// Give SSH server time to start
	time.Sleep(2 * time.Second)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test 1: Start a detached long-running FOREGROUND process
	t.Run("detach_long_running_foreground_process", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:    "root",
			Host:    "127.0.0.1",
			Port:    sshPort,
			Command: "sleep 30", // FOREGROUND process - no & backgrounding
			Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
			EnvironmentVars: map[string]string{
				sshpkg.EnvRaftDetach: "1",
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
		defer clientCancel()

		err := sshpkg.Client(clientCtx, log, clientCfg)
		require.NoError(t, err, "detached command should start successfully")

		output := stdout.String()
		t.Logf("Output: %s", output)

		// Should receive PID message
		assert.Contains(t, output, "Detached process started with PID", "should report PID")

		// Extract PID from output
		var pid int
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Detached process started with PID") {
				_, err := fmt.Sscanf(line, "Detached process started with PID %d", &pid)
				if err == nil {
					t.Logf("Started detached process with PID %d", pid)
					break
				}
			}
		}
		require.NotZero(t, pid, "should have extracted PID")

		// Verify the process is still running after a delay
		time.Sleep(2 * time.Second)
		
		stdout.Reset()
		checkCfg := &domain.SSHClientConfig{
			User:            "root",
			Host:            "127.0.0.1",
			Port:            sshPort,
			Command:         fmt.Sprintf("ps | grep -w '%d' | grep -v grep || echo PROCESS_DEAD", pid),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
		defer checkCancel()

		err = sshpkg.Client(checkCtx, log, checkCfg)
		require.NoError(t, err, "should check process status")

		output = stdout.String()
		t.Logf("Process check output: %s", output)
		assert.NotContains(t, output, "PROCESS_DEAD", "detached process should still be running")
		assert.Contains(t, output, "sleep", "should find sleep process")
	})

	// Test 2: Verify detached FOREGROUND process survives client disconnect
	t.Run("detached_foreground_process_survives_disconnect", func(t *testing.T) {
		// Start a detached FOREGROUND process that creates a marker file after 3 seconds
		// This is a foreground process (no &) - without detach, it would block until completion
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:    "root",
			Host:    "127.0.0.1",
			Port:    sshPort,
			Command: "sh -c 'sleep 3 && echo DETACHED_SUCCESS > /tmp/detach_marker'", // FOREGROUND - no &
			Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
			EnvironmentVars: map[string]string{
				sshpkg.EnvRaftDetach: "1",
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
		defer clientCancel()

		startTime := time.Now()
		err := sshpkg.Client(clientCtx, log, clientCfg)
		elapsed := time.Since(startTime)
		
		require.NoError(t, err, "detached command should start successfully")
		t.Logf("Detach output: %s", stdout.String())
		t.Logf("Client returned in %v (should be immediate, not 3+ seconds)", elapsed)

		// Client should return immediately (detached), not wait 3 seconds
		assert.Less(t, elapsed, 2*time.Second, "client should return immediately, not wait for process")

		// Client has disconnected, wait for the detached process to complete
		time.Sleep(5 * time.Second)

		// Verify the marker file was created (proves process survived disconnect)
		stdout.Reset()
		checkCfg := &domain.SSHClientConfig{
			User:            "root",
			Host:            "127.0.0.1",
			Port:            sshPort,
			Command:         "cat /tmp/detach_marker",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
		defer checkCancel()

		err = sshpkg.Client(checkCtx, log, checkCfg)
		require.NoError(t, err, "should read marker file")

		assert.Contains(t, stdout.String(), "DETACHED_SUCCESS", "detached process should have completed")
	})

	// Test 3: Verify RAFT_DETACH env var is filtered from child process
	t.Run("detach_env_var_filtered", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:    "root",
			Host:    "127.0.0.1",
			Port:    sshPort,
			Command: "env > /tmp/detach_env && echo WRITTEN",
			Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
			EnvironmentVars: map[string]string{
				sshpkg.EnvRaftDetach: "1",
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
		defer clientCancel()

		err := sshpkg.Client(clientCtx, log, clientCfg)
		require.NoError(t, err, "detached command should start successfully")

		// Wait for file to be written
		time.Sleep(2 * time.Second)

		// Check the environment
		stdout.Reset()
		checkCfg := &domain.SSHClientConfig{
			User:            "root",
			Host:            "127.0.0.1",
			Port:            sshPort,
			Command:         fmt.Sprintf("grep %s /tmp/detach_env || echo NO_%s", sshpkg.EnvRaftDetach, sshpkg.EnvRaftDetach),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
		defer checkCancel()

		err = sshpkg.Client(checkCtx, log, checkCfg)
		require.NoError(t, err, "should check environment")

		assert.Contains(t, stdout.String(), fmt.Sprintf("NO_%s", sshpkg.EnvRaftDetach), "RAFT_DETACH should be filtered")
	})

	// Test 4: Compare detached vs non-detached foreground process
	t.Run("compare_detached_vs_normal_foreground", func(t *testing.T) {
		// First: Non-detached foreground process should BLOCK until completion
		t.Run("non_detached_blocks", func(t *testing.T) {
			var stdout bytes.Buffer
			clientCfg := &domain.SSHClientConfig{
				User:            "root",
				Host:            "127.0.0.1",
				Port:            sshPort,
				Command:         "sleep 2", // Foreground, no detach - should block
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Stdout:          &stdout,
				Stderr:          &bytes.Buffer{},
				Stdin:           &bytes.Buffer{},
				// NO RAFT_DETACH env var
			}

			clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
			defer clientCancel()

			startTime := time.Now()
			err := sshpkg.Client(clientCtx, log, clientCfg)
			elapsed := time.Since(startTime)
			
			require.NoError(t, err, "non-detached command should succeed")
			t.Logf("Non-detached client returned in %v", elapsed)

			// Should wait for process to complete (~2 seconds)
			assert.GreaterOrEqual(t, elapsed, 2*time.Second, "non-detached should wait for process completion")
		})

		// Second: Detached foreground process should return IMMEDIATELY
		t.Run("detached_returns_immediately", func(t *testing.T) {
			var stdout bytes.Buffer
			clientCfg := &domain.SSHClientConfig{
				User:    "root",
				Host:    "127.0.0.1",
				Port:    sshPort,
				Command: "sleep 2", // Same command, but with detach
				Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
				EnvironmentVars: map[string]string{
					sshpkg.EnvRaftDetach: "1",
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Stdout:          &stdout,
				Stderr:          &bytes.Buffer{},
				Stdin:           &bytes.Buffer{},
			}

			clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
			defer clientCancel()

			startTime := time.Now()
			err := sshpkg.Client(clientCtx, log, clientCfg)
			elapsed := time.Since(startTime)
			
			require.NoError(t, err, "detached command should start successfully")
			t.Logf("Detached client returned in %v", elapsed)
			t.Logf("Detach output: %s", stdout.String())

			// Should return immediately, not wait for 2 seconds
			assert.Less(t, elapsed, 1*time.Second, "detached should return immediately")
			assert.Contains(t, stdout.String(), "Detached process started with PID", "should show detach message")
		})
	})

	// Test 5: Verify normal (non-detached) process behavior is unchanged
	t.Run("normal_exec_unchanged", func(t *testing.T) {
		var stdout bytes.Buffer
		clientCfg := &domain.SSHClientConfig{
			User:            "root",
			Host:            "127.0.0.1",
			Port:            sshPort,
			Command:         "echo NORMAL_EXEC",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Stdout:          &stdout,
			Stderr:          &bytes.Buffer{},
			Stdin:           &bytes.Buffer{},
		}

		clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
		defer clientCancel()

		err := sshpkg.Client(clientCtx, log, clientCfg)
		require.NoError(t, err, "normal command should succeed")

		assert.Contains(t, stdout.String(), "NORMAL_EXEC", "normal exec should work")
		assert.NotContains(t, stdout.String(), "Detached", "should not show detach message")
	})

	t.Log("SSH detach exec integration test completed successfully")
}
