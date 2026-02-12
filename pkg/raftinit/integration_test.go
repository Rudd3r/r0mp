package raftinit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/u-root/u-root/pkg/cpio"
)

// TestIntegration_BuildAndLoadConfig tests the complete workflow of building an initrd
// and then loading its configuration
func TestIntegration_BuildAndLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Create a base initrd
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	// Step 2: Build custom initrd using InnitFSBuilder
	customInitPath := filepath.Join(tmpDir, "custom-init.cpio.gz")

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Configure the init system
	expectedNet := domain.NetworkInterface{
		Device: "eth0",
		Host:   "integration-test",
		IP: net.IPNet{
			IP:   net.IPv4(10, 0, 2, 15),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		DNS:         net.IPv4(8, 8, 8, 8),
		Gateway:     net.IPv4(10, 0, 2, 2),
		DisableIPV6: true,
	}
	builder.AddNetworkInterface(expectedNet)

	expectedMount := domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/mnt/rootfs",
		FSType:     "ext4",
		Options:    []string{"rw", "noatime"},
	}
	builder.AddMount(expectedMount)

	expectedProc := domain.Process{
		Path: "/bin/sh",
		Args: []string{"-c", "echo integration test"},
		Env:  []string{"PATH=/bin:/usr/bin", "TEST=value"},
		Dir:  "/",
		UID:  0,
	}
	builder.AddProcess(expectedProc)

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Step 3: Extract and verify the configuration
	config := extractConfigFromInitrd(t, customInitPath)

	// Verify network configuration
	require.Len(t, config.Networking, 1)
	assert.Equal(t, expectedNet.Device, config.Networking[0].Device)
	assert.Equal(t, expectedNet.Host, config.Networking[0].Host)
	assert.Equal(t, expectedNet.IP.IP.String(), config.Networking[0].IP.IP.String())
	assert.Equal(t, expectedNet.DNS.String(), config.Networking[0].DNS.String())
	assert.Equal(t, expectedNet.Gateway.String(), config.Networking[0].Gateway.String())
	assert.Equal(t, expectedNet.DisableIPV6, config.Networking[0].DisableIPV6)

	// Verify mount configuration
	require.Len(t, config.Mounts, 1)
	assert.Equal(t, expectedMount, config.Mounts[0])

	// Verify process configuration
	require.Len(t, config.Processes, 1)
	assert.Equal(t, expectedProc, config.Processes[0])
}

// TestIntegration_MultiStageConfiguration tests building multiple initrd images
// with different configurations
func TestIntegration_MultiStageConfiguration(t *testing.T) {

	tmpDir := t.TempDir()

	// Create base initrd once
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	tests := []struct {
		name         string
		setupBuilder func(*InnitFSBuilder)
		verifyConfig func(*testing.T, domain.InitConfig)
	}{
		{
			name: "web server configuration",
			setupBuilder: func(b *InnitFSBuilder) {
				b.AddNetworkInterface(domain.NetworkInterface{
					Device: "eth0",
					Host:   "webserver",
					IP: net.IPNet{
						IP:   net.IPv4(10, 0, 2, 20),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					Gateway: net.IPv4(10, 0, 2, 2),
				})
				b.AddMount(domain.Mount{
					Device:     "/dev/vda",
					MountPoint: "/",
					FSType:     "ext4",
				})
				b.AddProcess(domain.Process{
					Path: "/usr/bin/nginx",
					Args: []string{"-g", "daemon off;"},
					UID:  33,
				})
			},
			verifyConfig: func(t *testing.T, cfg domain.InitConfig) {
				require.Len(t, cfg.Networking, 1)
				assert.Equal(t, "webserver", cfg.Networking[0].Host)
				require.Len(t, cfg.Processes, 1)
				assert.Equal(t, "/usr/bin/nginx", cfg.Processes[0].Path)
			},
		},
		{
			name: "database server configuration",
			setupBuilder: func(b *InnitFSBuilder) {
				b.AddNetworkInterface(domain.NetworkInterface{
					Device: "eth0",
					Host:   "dbserver",
					IP: net.IPNet{
						IP:   net.IPv4(10, 0, 2, 30),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					Gateway: net.IPv4(10, 0, 2, 2),
				})
				b.AddMount(domain.Mount{
					Device:     "/dev/vda",
					MountPoint: "/",
					FSType:     "ext4",
				})
				b.AddMount(domain.Mount{
					Device:     "/dev/vdb",
					MountPoint: "/var/lib/postgresql",
					FSType:     "ext4",
				})
				b.AddProcess(domain.Process{
					Path: "/usr/bin/postgres",
					Args: []string{"-D", "/var/lib/postgresql/data"},
					UID:  999,
				})
			},
			verifyConfig: func(t *testing.T, cfg domain.InitConfig) {
				require.Len(t, cfg.Networking, 1)
				assert.Equal(t, "dbserver", cfg.Networking[0].Host)
				require.Len(t, cfg.Mounts, 2)
				assert.Equal(t, "/var/lib/postgresql", cfg.Mounts[1].MountPoint)
				require.Len(t, cfg.Processes, 1)
				assert.Equal(t, "/usr/bin/postgres", cfg.Processes[0].Path)
			},
		},
		{
			name: "minimal configuration",
			setupBuilder: func(b *InnitFSBuilder) {
				b.AddProcess(domain.Process{
					Path: "/bin/sh",
				})
			},
			verifyConfig: func(t *testing.T, cfg domain.InitConfig) {
				require.Len(t, cfg.Processes, 1)
				assert.Equal(t, "/bin/sh", cfg.Processes[0].Path)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customInitPath := filepath.Join(tmpDir, tt.name+"-init.cpio.gz")

			customFile, err := os.Create(customInitPath)
			require.NoError(t, err)
			defer func() { _ = customFile.Close() }()

			builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
			require.NoError(t, err)

			tt.setupBuilder(builder)

			require.NoError(t, builder.Close())
			_ = customFile.Close()

			config := extractConfigFromInitrd(t, customInitPath)
			tt.verifyConfig(t, config)
		})
	}
}

// TestIntegration_RoundTripConfiguration tests that configuration can be
// marshaled, written to an initrd, extracted, and unmarshaled correctly
func TestIntegration_RoundTripConfiguration(t *testing.T) {

	originalConfig := domain.InitConfig{
		Networking: []domain.NetworkInterface{
			{
				Device: "eth0",
				Host:   "roundtrip-test",
				IP: net.IPNet{
					IP:   net.IPv4(172, 16, 0, 10),
					Mask: net.IPv4Mask(255, 255, 0, 0),
				},
				DNS:         net.IPv4(1, 1, 1, 1),
				Gateway:     net.IPv4(172, 16, 0, 1),
				DisableIPV6: false,
			},
			{
				Device: "eth1",
				IP: net.IPNet{
					IP:   net.IPv4(10, 0, 0, 5),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
		},
		Mounts: []domain.Mount{
			{
				Device:     "/dev/vda",
				MountPoint: "/",
				FSType:     "ext4",
				Options:    []string{"rw"},
			},
			{
				Device:     "tmpfs",
				MountPoint: "/tmp",
				FSType:     "tmpfs",
				Options:    []string{"size=1G", "mode=1777"},
			},
		},
		Processes: []domain.Process{
			{
				Path: "/bin/systemd",
				Args: []string{"--system"},
				Env:  []string{"PATH=/usr/local/bin:/usr/bin:/bin"},
				Dir:  "/",
				UID:  0,
			},
			{
				Path: "/usr/bin/app",
				Args: []string{"--config", "/etc/app.conf", "--verbose"},
				Env:  []string{"PATH=/usr/bin", "APP_MODE=production", "LOG_LEVEL=info"},
				Dir:  "/opt/app",
				UID:  1001,
			},
		},
	}

	tmpDir := t.TempDir()
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customInitPath := filepath.Join(tmpDir, "roundtrip-init.cpio.gz")
	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add all configuration
	for _, net := range originalConfig.Networking {
		builder.AddNetworkInterface(net)
	}
	for _, mnt := range originalConfig.Mounts {
		builder.AddMount(mnt)
	}
	for _, proc := range originalConfig.Processes {
		builder.AddProcess(proc)
	}

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Extract and compare
	loadedConfig := extractConfigFromInitrd(t, customInitPath)

	// Compare networking
	require.Len(t, loadedConfig.Networking, len(originalConfig.Networking))
	for i := range originalConfig.Networking {
		assert.Equal(t, originalConfig.Networking[i].Device, loadedConfig.Networking[i].Device)
		assert.Equal(t, originalConfig.Networking[i].Host, loadedConfig.Networking[i].Host)
		assert.Equal(t, originalConfig.Networking[i].IP.IP.String(), loadedConfig.Networking[i].IP.IP.String())
		assert.Equal(t, originalConfig.Networking[i].DisableIPV6, loadedConfig.Networking[i].DisableIPV6)
	}

	// Compare mounts
	require.Len(t, loadedConfig.Mounts, len(originalConfig.Mounts))
	for i := range originalConfig.Mounts {
		assert.Equal(t, originalConfig.Mounts[i], loadedConfig.Mounts[i])
	}

	// Compare processes
	require.Len(t, loadedConfig.Processes, len(originalConfig.Processes))
	for i := range originalConfig.Processes {
		assert.Equal(t, originalConfig.Processes[i], loadedConfig.Processes[i])
	}
}

// TestIntegration_InitContextCancellation tests that Init respects context cancellation
func TestIntegration_InitContextCancellation(t *testing.T) {

	t.Run("immediate cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		init := NewInit(ctx, slog.Default())
		require.NotNil(t, init)

		// The context should already be canceled
		assert.Error(t, init.ctx.Err())
	})

	t.Run("timeout expiry", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		init := NewInit(ctx, slog.Default())
		require.NotNil(t, init)

		// Wait for timeout
		time.Sleep(20 * time.Millisecond)
		assert.Error(t, init.ctx.Err())
	})
}

// TestIntegration_LargeConfiguration tests handling of large configurations
func TestIntegration_LargeConfiguration(t *testing.T) {

	tmpDir := t.TempDir()
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customInitPath := filepath.Join(tmpDir, "large-init.cpio.gz")
	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add many processes
	numProcesses := 50
	for i := 0; i < numProcesses; i++ {
		builder.AddProcess(domain.Process{
			Path: "/bin/sh",
			Args: []string{"-c", "echo process " + string(rune('0'+i))},
			Dir:  "/",
			UID:  uint64(i),
		})
	}

	// Add many mounts
	numMounts := 20
	for i := 0; i < numMounts; i++ {
		builder.AddMount(domain.Mount{
			Device:     "/dev/vd" + string(rune('a'+i)),
			MountPoint: "/mnt/disk" + string(rune('0'+i)),
			FSType:     "ext4",
		})
	}

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Verify
	config := extractConfigFromInitrd(t, customInitPath)
	assert.Len(t, config.Processes, numProcesses)
	assert.Len(t, config.Mounts, numMounts)
}

// TestIntegration_FSShare tests FSShare configuration in initrd
func TestIntegration_FSShare(t *testing.T) {
	tmpDir := t.TempDir()

	// Create base initrd
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customInitPath := filepath.Join(tmpDir, "fsshare-init.cpio.gz")
	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add a FSShare
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/workspace",
		MountTag:      "workspace",
		MountPoint:    "/mnt/workspace",
		ReadOnly:      false,
		SecurityModel: "mapped-xattr",
	})

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Verify configuration
	config := extractConfigFromInitrd(t, customInitPath)

	require.Len(t, config.Mounts, 1, "should have one mount")
	mount := config.Mounts[0]
	assert.Equal(t, "workspace", mount.Device, "device should be mount tag")
	assert.Equal(t, "/mnt/workspace", mount.MountPoint)
	assert.Equal(t, "9p", mount.FSType, "fstype should be 9p")
	assert.Contains(t, mount.Options, "trans=virtio")
	assert.Contains(t, mount.Options, "version=9p2000.L")
	assert.NotContains(t, mount.Options, "ro", "should not have ro option for writable share")
}

// TestIntegration_MultipleFSShares tests multiple FSShares in initrd
func TestIntegration_MultipleFSShares(t *testing.T) {
	tmpDir := t.TempDir()

	// Create base initrd
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customInitPath := filepath.Join(tmpDir, "multi-fsshare-init.cpio.gz")
	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add multiple FSShares
	shares := []domain.FSShare{
		{
			HostPath:      "/host/workspace",
			MountTag:      "workspace",
			MountPoint:    "/mnt/workspace",
			ReadOnly:      false,
			SecurityModel: "mapped-xattr",
		},
		{
			HostPath:      "/host/data",
			MountTag:      "data",
			MountPoint:    "/mnt/data",
			ReadOnly:      true,
			SecurityModel: "mapped-file",
		},
		{
			HostPath:      "/host/config",
			MountTag:      "config",
			MountPoint:    "/etc/config",
			ReadOnly:      true,
			SecurityModel: "none",
		},
	}

	for _, share := range shares {
		builder.AddFSShare(share)
	}

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Verify configuration
	config := extractConfigFromInitrd(t, customInitPath)

	require.Len(t, config.Mounts, 3, "should have three mounts")

	// Verify first share (writable)
	assert.Equal(t, "workspace", config.Mounts[0].Device)
	assert.Equal(t, "/mnt/workspace", config.Mounts[0].MountPoint)
	assert.Equal(t, "9p", config.Mounts[0].FSType)
	assert.NotContains(t, config.Mounts[0].Options, "ro")

	// Verify second share (read-only)
	assert.Equal(t, "data", config.Mounts[1].Device)
	assert.Equal(t, "/mnt/data", config.Mounts[1].MountPoint)
	assert.Equal(t, "9p", config.Mounts[1].FSType)
	assert.Contains(t, config.Mounts[1].Options, "ro")

	// Verify third share (read-only)
	assert.Equal(t, "config", config.Mounts[2].Device)
	assert.Equal(t, "/etc/config", config.Mounts[2].MountPoint)
	assert.Equal(t, "9p", config.Mounts[2].FSType)
	assert.Contains(t, config.Mounts[2].Options, "ro")
}

// TestIntegration_MixedMountsAndFSShares tests mixing regular mounts with FSShares
func TestIntegration_MixedMountsAndFSShares(t *testing.T) {
	tmpDir := t.TempDir()

	// Create base initrd
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customInitPath := filepath.Join(tmpDir, "mixed-init.cpio.gz")
	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add regular mounts
	builder.AddMount(domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/",
		FSType:     "ext4",
		Options:    []string{"rw"},
	})

	// Add FSShare
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/workspace",
		MountTag:      "workspace",
		MountPoint:    "/mnt/workspace",
		ReadOnly:      false,
		SecurityModel: "mapped-xattr",
	})

	// Add another regular mount
	builder.AddMount(domain.Mount{
		Device:     "tmpfs",
		MountPoint: "/tmp",
		FSType:     "tmpfs",
		Options:    []string{"size=100m"},
	})

	// Add another FSShare
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/data",
		MountTag:      "data",
		MountPoint:    "/mnt/data",
		ReadOnly:      true,
		SecurityModel: "mapped-xattr",
	})

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Verify configuration
	config := extractConfigFromInitrd(t, customInitPath)

	require.Len(t, config.Mounts, 4, "should have four mounts")

	// Verify regular ext4 mount
	assert.Equal(t, "/dev/vda", config.Mounts[0].Device)
	assert.Equal(t, "ext4", config.Mounts[0].FSType)

	// Verify first 9p mount from FSShare
	assert.Equal(t, "workspace", config.Mounts[1].Device)
	assert.Equal(t, "9p", config.Mounts[1].FSType)
	assert.Contains(t, config.Mounts[1].Options, "trans=virtio")

	// Verify tmpfs mount
	assert.Equal(t, "tmpfs", config.Mounts[2].Device)
	assert.Equal(t, "tmpfs", config.Mounts[2].FSType)

	// Verify second 9p mount from FSShare
	assert.Equal(t, "data", config.Mounts[3].Device)
	assert.Equal(t, "9p", config.Mounts[3].FSType)
	assert.Contains(t, config.Mounts[3].Options, "ro")
}

// TestIntegration_CompleteSystemWithFSShares tests a complete system configuration
// including network, mounts, FSShares, and processes
func TestIntegration_CompleteSystemWithFSShares(t *testing.T) {
	tmpDir := t.TempDir()

	// Create base initrd
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customInitPath := filepath.Join(tmpDir, "complete-init.cpio.gz")
	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add network configuration
	builder.AddNetworkInterface(domain.NetworkInterface{
		Device: "eth0",
		Host:   "complete-test",
		IP: net.IPNet{
			IP:   net.IPv4(10, 0, 2, 15),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		DNS:         net.IPv4(8, 8, 8, 8),
		Gateway:     net.IPv4(10, 0, 2, 2),
		DisableIPV6: true,
	})

	// Add regular mounts
	builder.AddMount(domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/",
		FSType:     "ext4",
		Options:    []string{"rw"},
	})

	// Add FSShares
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/workspace",
		MountTag:      "workspace",
		MountPoint:    "/mnt/workspace",
		ReadOnly:      false,
		SecurityModel: "mapped-xattr",
	})

	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/config",
		MountTag:      "config",
		MountPoint:    "/etc/app/config",
		ReadOnly:      true,
		SecurityModel: "mapped-xattr",
	})

	// Add processes
	builder.AddProcess(domain.Process{
		Path: "/bin/ls",
		Args: []string{"-la", "/mnt/workspace"},
		Dir:  "/",
		UID:  0,
	})

	builder.AddProcess(domain.Process{
		Path: "/usr/bin/app",
		Args: []string{"--config", "/etc/app/config/app.conf"},
		Dir:  "/opt/app",
		UID:  1000,
	})

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Verify configuration
	config := extractConfigFromInitrd(t, customInitPath)

	// Verify networking
	require.Len(t, config.Networking, 1)
	assert.Equal(t, "complete-test", config.Networking[0].Host)

	// Verify mounts (1 regular + 2 FSShares)
	require.Len(t, config.Mounts, 3)
	assert.Equal(t, "/dev/vda", config.Mounts[0].Device)
	assert.Equal(t, "ext4", config.Mounts[0].FSType)
	assert.Equal(t, "workspace", config.Mounts[1].Device)
	assert.Equal(t, "9p", config.Mounts[1].FSType)
	assert.Equal(t, "config", config.Mounts[2].Device)
	assert.Equal(t, "9p", config.Mounts[2].FSType)
	assert.Contains(t, config.Mounts[2].Options, "ro")

	// Verify processes
	require.Len(t, config.Processes, 2)
	assert.Equal(t, "/bin/ls", config.Processes[0].Path)
	assert.Equal(t, "/usr/bin/app", config.Processes[1].Path)
}

// Helper functions

// createBaseInitrd creates a minimal base initrd for testing
func createBaseInitrd(t *testing.T, path string) {
	t.Helper()

	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	gzWriter := gzip.NewWriter(f)
	cpioWriter := cpio.Newc.Writer(gzWriter)

	// Add a minimal file structure
	records := []struct {
		name    string
		content []byte
		mode    uint64
	}{
		{"/bin", nil, 0755 | cpio.S_IFDIR},
		{"/etc", nil, 0755 | cpio.S_IFDIR},
		{"/tmp", nil, 0777 | cpio.S_IFDIR},
		{"/etc/test.txt", []byte("test"), 0644},
	}

	for _, rec := range records {
		var reader io.ReaderAt
		size := uint64(0)
		if rec.content != nil {
			reader = bytes.NewReader(rec.content)
			size = uint64(len(rec.content))
		}

		cpioRec := cpio.Record{
			ReaderAt: reader,
			Info: cpio.Info{
				Name:     rec.name,
				Mode:     rec.mode,
				FileSize: size,
			},
		}

		require.NoError(t, cpioWriter.WriteRecord(cpioRec))
	}

	require.NoError(t, cpio.WriteTrailer(cpioWriter))
	require.NoError(t, gzWriter.Close())
}

// extractConfigFromInitrd extracts and parses the config from an initrd
func extractConfigFromInitrd(t *testing.T, path string) domain.InitConfig {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	gzReader, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer func() { _ = gzReader.Close() }()

	allData, err := io.ReadAll(gzReader)
	require.NoError(t, err)

	archiveReader := cpio.Newc.Reader(bytes.NewReader(allData))
	archive, err := cpio.ArchiveFromReader(archiveReader)
	require.NoError(t, err)

	// Find and read the config file
	// CPIO may strip leading slashes
	configPaths := []string{domain.InitConfigPath, domain.InitConfigPath[1:]}
	reader := archive.Reader()
	for {
		rec, err := reader.ReadRecord()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		// Check if this is the config file (with or without leading /)
		isConfigFile := false
		for _, path := range configPaths {
			if rec.Name == path {
				isConfigFile = true
				break
			}
		}

		if isConfigFile && rec.ReaderAt != nil {
			data := make([]byte, rec.FileSize)
			_, err := rec.ReadAt(data, 0)
			require.NoError(t, err)

			var config domain.InitConfig
			require.NoError(t, json.Unmarshal(data, &config))
			return config
		}
	}

	t.Fatal("config file not found in initrd")
	return domain.InitConfig{}
}

// TestIntegration_ChrootConfiguration tests that chroot configuration is properly
// stored and retrieved from the initrd
func TestIntegration_ChrootConfiguration(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Create a base initrd
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	// Step 2: Build custom initrd with chroot process
	customInitPath := filepath.Join(tmpDir, "custom-init.cpio.gz")

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add process with chroot
	expectedProc := domain.Process{
		Path:   "/bin/sh",
		Args:   []string{"-c", "echo test"},
		Env:    []string{"PATH=/bin"},
		Dir:    "/",
		Chroot: "/mnt/rootfs",
		UID:    0,
	}
	builder.AddProcess(expectedProc)

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Step 3: Extract and verify the configuration
	config := extractConfigFromInitrd(t, customInitPath)

	// Verify process configuration includes chroot
	require.Len(t, config.Processes, 1)
	assert.Equal(t, expectedProc.Path, config.Processes[0].Path)
	assert.Equal(t, expectedProc.Args, config.Processes[0].Args)
	assert.Equal(t, expectedProc.Chroot, config.Processes[0].Chroot)
	assert.Equal(t, expectedProc.UID, config.Processes[0].UID)

	t.Logf("Chroot process configured: Path=%s, Chroot=%s",
		config.Processes[0].Path,
		config.Processes[0].Chroot)
}

// TestIntegration_ChrootWithUIDDrop tests configuration of chroot with UID drop
func TestIntegration_ChrootWithUIDDrop(t *testing.T) {
	tmpDir := t.TempDir()
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	customInitPath := filepath.Join(tmpDir, "custom-init.cpio.gz")

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add process with chroot and UID drop
	expectedProc := domain.Process{
		Path:   "/usr/bin/id",
		Args:   []string{"-u"},
		Dir:    "/",
		Chroot: "/mnt/rootfs",
		UID:    1000, // Drop to non-root after chroot
	}
	builder.AddProcess(expectedProc)

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Extract and verify
	config := extractConfigFromInitrd(t, customInitPath)

	require.Len(t, config.Processes, 1)
	assert.Equal(t, "/mnt/rootfs", config.Processes[0].Chroot)
	assert.Equal(t, uint64(1000), config.Processes[0].UID)

	t.Logf("Chroot with UID drop configured: Chroot=%s, UID=%d",
		config.Processes[0].Chroot,
		config.Processes[0].UID)
}

// TestIntegration_MultipleProcessesWithChroot tests multiple processes,
// some with chroot and some without
func TestIntegration_MultipleProcessesWithChroot(t *testing.T) {
	tmpDir := t.TempDir()
	baseInitPath := filepath.Join(tmpDir, "base-init.cpio.gz")
	createBaseInitrd(t, baseInitPath)

	customInitPath := filepath.Join(tmpDir, "custom-init.cpio.gz")

	baseFile, err := os.Open(baseInitPath)
	require.NoError(t, err)
	defer func() { _ = baseFile.Close() }()

	baseGz, err := gzip.NewReader(baseFile)
	require.NoError(t, err)
	defer func() { _ = baseGz.Close() }()

	baseData, err := io.ReadAll(baseGz)
	require.NoError(t, err)

	customFile, err := os.Create(customInitPath)
	require.NoError(t, err)
	defer func() { _ = customFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseData), customFile)
	require.NoError(t, err)

	// Add process without chroot (runs in initrd environment)
	builder.AddProcess(domain.Process{
		Path: "/bin/ls",
		Args: []string{"-la", "/"},
		Dir:  "/",
		UID:  0,
	})

	// Add process with chroot (runs in Docker filesystem)
	builder.AddProcess(domain.Process{
		Path:   "/bin/sh",
		Args:   []string{"-c", "ls /"},
		Dir:    "/",
		Chroot: "/mnt/rootfs",
		UID:    0,
	})

	// Add another process with chroot and UID drop
	builder.AddProcess(domain.Process{
		Path:   "/usr/bin/python3",
		Args:   []string{"/app/main.py"},
		Dir:    "/app",
		Chroot: "/mnt/rootfs",
		UID:    1000,
	})

	require.NoError(t, builder.Close())
	_ = customFile.Close()

	// Extract and verify
	config := extractConfigFromInitrd(t, customInitPath)

	require.Len(t, config.Processes, 3)

	// Verify first process (no chroot)
	assert.Equal(t, "/bin/ls", config.Processes[0].Path)
	assert.Equal(t, "", config.Processes[0].Chroot)

	// Verify second process (with chroot)
	assert.Equal(t, "/bin/sh", config.Processes[1].Path)
	assert.Equal(t, "/mnt/rootfs", config.Processes[1].Chroot)
	assert.Equal(t, uint64(0), config.Processes[1].UID)

	// Verify third process (with chroot and UID drop)
	assert.Equal(t, "/usr/bin/python3", config.Processes[2].Path)
	assert.Equal(t, "/mnt/rootfs", config.Processes[2].Chroot)
	assert.Equal(t, uint64(1000), config.Processes[2].UID)

	t.Logf("Multiple processes configured successfully:")
	for i, proc := range config.Processes {
		t.Logf("  Process %d: Path=%s, Chroot=%s, UID=%d",
			i+1, proc.Path, proc.Chroot, proc.UID)
	}
}
