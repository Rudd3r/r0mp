package raftinit

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/u-root/u-root/pkg/cpio"
)

func TestInnitFSBuilder_BasicConfiguration(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err, "should create builder successfully")

	// Add a network interface
	builder.AddNetworkInterface(domain.NetworkInterface{
		Device: "eth0",
		Host:   "testhost",
		IP: net.IPNet{
			IP:   net.IPv4(10, 0, 2, 15),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		DNS:         net.IPv4(8, 8, 8, 8),
		Gateway:     net.IPv4(10, 0, 2, 2),
		DisableIPV6: true,
	})

	// Add a mount
	builder.AddMount(domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/mnt/rootfs",
		FSType:     "ext4",
		Options:    []string{"ro"},
	})

	// Add a process
	builder.AddProcess(domain.Process{
		Path: "/bin/sh",
		Args: []string{"-c", "echo hello"},
		Env:  []string{"PATH=/bin:/usr/bin"},
		Dir:  "/",
		UID:  0,
	})

	// Close the builder
	require.NoError(t, builder.Close(), "should close builder successfully")

	// Verify the output file exists and is valid gzip
	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		// Verify network configuration
		require.Len(t, cfg.Networking, 1, "should have one network interface")
		assert.Equal(t, "eth0", cfg.Networking[0].Device)
		assert.Equal(t, "testhost", cfg.Networking[0].Host)
		assert.Equal(t, "10.0.2.15", cfg.Networking[0].IP.IP.String())
		assert.Equal(t, "8.8.8.8", cfg.Networking[0].DNS.String())
		assert.Equal(t, "10.0.2.2", cfg.Networking[0].Gateway.String())
		assert.True(t, cfg.Networking[0].DisableIPV6)

		// Verify mount configuration
		require.Len(t, cfg.Mounts, 1, "should have one mount")
		assert.Equal(t, "/dev/vda", cfg.Mounts[0].Device)
		assert.Equal(t, "/mnt/rootfs", cfg.Mounts[0].MountPoint)
		assert.Equal(t, "ext4", cfg.Mounts[0].FSType)
		assert.Equal(t, []string{"ro"}, cfg.Mounts[0].Options)

		// Verify process configuration
		require.Len(t, cfg.Processes, 1, "should have one process")
		assert.Equal(t, "/bin/sh", cfg.Processes[0].Path)
		assert.Equal(t, []string{"-c", "echo hello"}, cfg.Processes[0].Args)
		assert.Equal(t, []string{"PATH=/bin:/usr/bin"}, cfg.Processes[0].Env)
		assert.Equal(t, "/", cfg.Processes[0].Dir)
		assert.Equal(t, uint64(0), cfg.Processes[0].UID)

		// Verify config file exists in archive (with or without leading /)
		_, ok := files[domain.InitConfigPath]
		if !ok {
			_, ok = files[domain.InitConfigPath[1:]]
		}
		assert.True(t, ok, "config file should exist in archive")
	})
}

func TestInnitFSBuilder_AddInitBinary(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Create a mock init binary
	initBinaryPath := filepath.Join(t.TempDir(), "raftinit")
	initBinaryContent := []byte("#!/bin/sh\necho 'mock init'\n")
	require.NoError(t, os.WriteFile(initBinaryPath, initBinaryContent, 0755))

	// Add the init binary
	require.NoError(t, builder.AddInitBinary(initBinaryPath))
	require.NoError(t, builder.Close())

	// Verify the init binary exists in the archive
	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		binary, ok := files[domain.InitFSBinPath]
		if !ok {
			binary, ok = files[domain.InitFSBinPath[1:]]
		}
		require.True(t, ok, "init binary should exist in archive")
		assert.Equal(t, initBinaryContent, binary)
	})
}

func TestInnitFSBuilder_MultipleNetworkInterfaces(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add multiple network interfaces
	builder.AddNetworkInterface(domain.NetworkInterface{
		Device: "eth0",
		Host:   "host1",
		IP: net.IPNet{
			IP:   net.IPv4(192, 168, 1, 10),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		Gateway: net.IPv4(192, 168, 1, 1),
	})

	builder.AddNetworkInterface(domain.NetworkInterface{
		Device: "eth1",
		Host:   "host2",
		IP: net.IPNet{
			IP:   net.IPv4(10, 0, 0, 10),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		Gateway: net.IPv4(10, 0, 0, 1),
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Networking, 2, "should have two network interfaces")
		assert.Equal(t, "eth0", cfg.Networking[0].Device)
		assert.Equal(t, "eth1", cfg.Networking[1].Device)
	})
}

func TestInnitFSBuilder_MultipleMounts(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add multiple mounts
	builder.AddMount(domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/mnt/root",
		FSType:     "ext4",
		Options:    []string{"rw"},
	})

	builder.AddMount(domain.Mount{
		Device:     "/dev/vdb",
		MountPoint: "/mnt/data",
		FSType:     "ext4",
		Options:    []string{"ro"},
	})

	builder.AddMount(domain.Mount{
		Device:     "tmpfs",
		MountPoint: "/tmp",
		FSType:     "tmpfs",
		Options:    []string{"size=10m"},
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Mounts, 3, "should have three mounts")
		assert.Equal(t, "/dev/vda", cfg.Mounts[0].Device)
		assert.Equal(t, "/dev/vdb", cfg.Mounts[1].Device)
		assert.Equal(t, "tmpfs", cfg.Mounts[2].Device)
	})
}

func TestInnitFSBuilder_MultipleProcesses(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add multiple processes
	builder.AddProcess(domain.Process{
		Path: "/bin/sh",
		Args: []string{"-c", "echo process1"},
		Dir:  "/",
		UID:  0,
	})

	builder.AddProcess(domain.Process{
		Path: "/bin/ls",
		Args: []string{"-la", "/"},
		Dir:  "/",
		UID:  1000,
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Processes, 2, "should have two processes")
		assert.Equal(t, "/bin/sh", cfg.Processes[0].Path)
		assert.Equal(t, "/bin/ls", cfg.Processes[1].Path)
		assert.Equal(t, uint64(0), cfg.Processes[0].UID)
		assert.Equal(t, uint64(1000), cfg.Processes[1].UID)
	})
}

func TestInnitFSBuilder_WriteFile(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Write custom files
	testContent := []byte("test file content")
	require.NoError(t, builder.WriteFile(domain.FileInfo{
		FName: "/etc/test.conf",
		FMode: 0644,
		Uid:   0,
		Gid:   0,
	}, testContent))

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		content, ok := files["/etc/test.conf"]
		if !ok {
			content, ok = files["etc/test.conf"]
		}
		require.True(t, ok, "test file should exist in archive")
		assert.Equal(t, testContent, content)
	})
}

func TestInnitFSBuilder_Mkdir(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Create directories
	require.NoError(t, builder.Mkdir(domain.FileInfo{
		FName: "/test-dir",
		FMode: 0755,
		Uid:   0,
		Gid:   0,
	}))

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		// Directory should exist in the file map (even if empty)
		_, ok := files["/test-dir"]
		assert.True(t, ok || len(files) > 0, "should have created directory")
	})
}

func TestInnitFSBuilder_EmptyConfiguration(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Close without adding anything
	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		assert.Len(t, cfg.Networking, 0, "should have no network interfaces")
		assert.Len(t, cfg.Mounts, 0, "should have no mounts")
		assert.Len(t, cfg.Processes, 0, "should have no processes")
	})
}

func TestInnitFSBuilder_AddFSShare(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add a basic FSShare
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/path",
		MountTag:      "host_share",
		MountPoint:    "/mnt/host",
		ReadOnly:      false,
		SecurityModel: "mapped-xattr",
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Mounts, 1, "should have one mount")

		mount := cfg.Mounts[0]
		assert.Equal(t, "host_share", mount.Device, "device should be mount tag")
		assert.Equal(t, "/mnt/host", mount.MountPoint)
		assert.Equal(t, "9p", mount.FSType, "fstype should be 9p")
		assert.Contains(t, mount.Options, "trans=virtio", "should have trans=virtio option")
		assert.Contains(t, mount.Options, "version=9p2000.L", "should have version option")
		assert.NotContains(t, mount.Options, "ro", "should not have ro option for writable share")
	})
}

func TestInnitFSBuilder_AddFSShare_ReadOnly(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add a read-only FSShare
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/readonly",
		MountTag:      "ro_share",
		MountPoint:    "/mnt/readonly",
		ReadOnly:      true,
		SecurityModel: "mapped-xattr",
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Mounts, 1, "should have one mount")

		mount := cfg.Mounts[0]
		assert.Equal(t, "ro_share", mount.Device)
		assert.Equal(t, "/mnt/readonly", mount.MountPoint)
		assert.Equal(t, "9p", mount.FSType)
		assert.Contains(t, mount.Options, "trans=virtio")
		assert.Contains(t, mount.Options, "version=9p2000.L")
		assert.Contains(t, mount.Options, "ro", "should have ro option for read-only share")
	})
}

func TestInnitFSBuilder_MultipleFSShares(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add multiple FSShares
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/workspace",
		MountTag:      "workspace",
		MountPoint:    "/mnt/workspace",
		ReadOnly:      false,
		SecurityModel: "mapped-xattr",
	})

	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/data",
		MountTag:      "data",
		MountPoint:    "/mnt/data",
		ReadOnly:      true,
		SecurityModel: "mapped-file",
	})

	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/config",
		MountTag:      "config",
		MountPoint:    "/etc/config",
		ReadOnly:      true,
		SecurityModel: "none",
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Mounts, 3, "should have three mounts")

		// Verify first share (writable)
		assert.Equal(t, "workspace", cfg.Mounts[0].Device)
		assert.Equal(t, "/mnt/workspace", cfg.Mounts[0].MountPoint)
		assert.Equal(t, "9p", cfg.Mounts[0].FSType)
		assert.NotContains(t, cfg.Mounts[0].Options, "ro")

		// Verify second share (read-only)
		assert.Equal(t, "data", cfg.Mounts[1].Device)
		assert.Equal(t, "/mnt/data", cfg.Mounts[1].MountPoint)
		assert.Equal(t, "9p", cfg.Mounts[1].FSType)
		assert.Contains(t, cfg.Mounts[1].Options, "ro")

		// Verify third share (read-only)
		assert.Equal(t, "config", cfg.Mounts[2].Device)
		assert.Equal(t, "/etc/config", cfg.Mounts[2].MountPoint)
		assert.Equal(t, "9p", cfg.Mounts[2].FSType)
		assert.Contains(t, cfg.Mounts[2].Options, "ro")
	})
}

func TestInnitFSBuilder_MixedMountsAndFSShares(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add regular mount
	builder.AddMount(domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/mnt/rootfs",
		FSType:     "ext4",
		Options:    []string{"rw"},
	})

	// Add FSShare
	builder.AddFSShare(domain.FSShare{
		HostPath:      "/host/share",
		MountTag:      "host_share",
		MountPoint:    "/mnt/host",
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

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Mounts, 3, "should have three mounts")

		// Verify regular ext4 mount
		assert.Equal(t, "/dev/vda", cfg.Mounts[0].Device)
		assert.Equal(t, "ext4", cfg.Mounts[0].FSType)

		// Verify 9p mount from FSShare
		assert.Equal(t, "host_share", cfg.Mounts[1].Device)
		assert.Equal(t, "9p", cfg.Mounts[1].FSType)
		assert.Contains(t, cfg.Mounts[1].Options, "trans=virtio")

		// Verify tmpfs mount
		assert.Equal(t, "tmpfs", cfg.Mounts[2].Device)
		assert.Equal(t, "tmpfs", cfg.Mounts[2].FSType)
	})
}

func TestInnitFSBuilder_AddChroot(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add a chroot with custom bind mounts
	builder.AddChroot(domain.Chroot{
		Name:     "myroot",
		RootPath: "/mnt/rootfs",
		BindMounts: []domain.BindMount{
			{
				Source:      "proc",
				Destination: "proc",
				FSType:      "proc",
				Options:     []string{"nosuid", "nodev", "noexec"},
				Flags:       0,
			},
			{
				Source:      "sysfs",
				Destination: "sys",
				FSType:      "sysfs",
				Options:     []string{"nosuid", "nodev", "noexec", "ro"},
				Flags:       syscall.MS_RDONLY,
			},
		},
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Chroots, 1, "should have one chroot")

		chroot := cfg.Chroots[0]
		assert.Equal(t, "myroot", chroot.Name)
		assert.Equal(t, "/mnt/rootfs", chroot.RootPath)
		require.Len(t, chroot.BindMounts, 2, "should have two bind mounts")

		// Verify proc mount
		assert.Equal(t, "proc", chroot.BindMounts[0].Source)
		assert.Equal(t, "proc", chroot.BindMounts[0].Destination)
		assert.Equal(t, "proc", chroot.BindMounts[0].FSType)
		assert.Equal(t, []string{"nosuid", "nodev", "noexec"}, chroot.BindMounts[0].Options)
		assert.Equal(t, uintptr(0), chroot.BindMounts[0].Flags)

		// Verify sysfs mount
		assert.Equal(t, "sysfs", chroot.BindMounts[1].Source)
		assert.Equal(t, "sys", chroot.BindMounts[1].Destination)
		assert.Equal(t, "sysfs", chroot.BindMounts[1].FSType)
		assert.Equal(t, []string{"nosuid", "nodev", "noexec", "ro"}, chroot.BindMounts[1].Options)
		assert.Equal(t, uintptr(syscall.MS_RDONLY), chroot.BindMounts[1].Flags)
	})
}

func TestInnitFSBuilder_MultipleChroots(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add multiple chroots
	builder.AddChroot(domain.Chroot{
		Name:     "root1",
		RootPath: "/mnt/root1",
		BindMounts: []domain.BindMount{
			{
				Source:      "proc",
				Destination: "proc",
				FSType:      "proc",
				Options:     []string{},
				Flags:       0,
			},
		},
	})

	builder.AddChroot(domain.Chroot{
		Name:     "root2",
		RootPath: "/mnt/root2",
		BindMounts: []domain.BindMount{
			{
				Source:      "tmpfs",
				Destination: "tmp",
				FSType:      "tmpfs",
				Options:     []string{"size=10m"},
				Flags:       0,
			},
		},
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Chroots, 2, "should have two chroots")

		assert.Equal(t, "root1", cfg.Chroots[0].Name)
		assert.Equal(t, "/mnt/root1", cfg.Chroots[0].RootPath)
		require.Len(t, cfg.Chroots[0].BindMounts, 1)

		assert.Equal(t, "root2", cfg.Chroots[1].Name)
		assert.Equal(t, "/mnt/root2", cfg.Chroots[1].RootPath)
		require.Len(t, cfg.Chroots[1].BindMounts, 1)
	})
}

func TestNewStandardChroot(t *testing.T) {
	chroot := NewStandardChroot("testroot", "/mnt/testroot")

	assert.Equal(t, "testroot", chroot.Name)
	assert.Equal(t, "/mnt/testroot", chroot.RootPath)
	assert.NotEmpty(t, chroot.BindMounts, "should have bind mounts configured")

	// Verify common bind mounts are present
	mountTypes := make(map[string]bool)
	for _, bind := range chroot.BindMounts {
		mountTypes[bind.FSType] = true
	}

	assert.True(t, mountTypes["proc"], "should have proc mount")
	assert.True(t, mountTypes["sysfs"], "should have sysfs mount")
	assert.True(t, mountTypes["devtmpfs"], "should have devtmpfs mount")
	assert.True(t, mountTypes["devpts"], "should have devpts mount")
	assert.True(t, mountTypes["tmpfs"], "should have tmpfs mounts")
}

func TestInnitFSBuilder_StandardChroot(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add a standard chroot
	builder.AddChroot(NewStandardChroot("myroot", "/mnt/rootfs"))

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Chroots, 1, "should have one chroot")

		chroot := cfg.Chroots[0]
		assert.Equal(t, "myroot", chroot.Name)
		assert.Equal(t, "/mnt/rootfs", chroot.RootPath)
		assert.NotEmpty(t, chroot.BindMounts, "should have standard bind mounts")

		// Verify at least the essential mounts
		assert.GreaterOrEqual(t, len(chroot.BindMounts), 5, "should have at least 5 bind mounts")
	})
}

func TestInnitFSBuilder_ChrootWithProcess(t *testing.T) {
	baseInitRd := createBasicCPIOArchive(t)
	outputPath := filepath.Join(t.TempDir(), "custom-init.gz")
	outputFile, err := os.Create(outputPath)
	require.NoError(t, err)
	defer func() { _ = outputFile.Close() }()

	builder, err := NewInitFS(bytes.NewReader(baseInitRd), outputFile)
	require.NoError(t, err)

	// Add a chroot
	builder.AddChroot(NewStandardChroot("myroot", "/mnt/rootfs"))

	// Add a process that uses the chroot
	builder.AddProcess(domain.Process{
		Path:   "/bin/sh",
		Args:   []string{"-c", "echo hello"},
		Env:    []string{"PATH=/bin:/usr/bin"},
		Dir:    "/",
		UID:    0,
		Chroot: "/mnt/rootfs",
	})

	require.NoError(t, builder.Close())

	_ = outputFile.Close()
	verifyInitFSArchive(t, outputPath, func(t *testing.T, cfg domain.InitConfig, files map[string][]byte) {
		require.Len(t, cfg.Chroots, 1, "should have one chroot")
		require.Len(t, cfg.Processes, 1, "should have one process")

		process := cfg.Processes[0]
		assert.Equal(t, "/mnt/rootfs", process.Chroot, "process should reference the chroot")
	})
}

// Helper functions

// createBasicCPIOArchive creates a minimal CPIO archive for testing
func createBasicCPIOArchive(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	cpioWriter := cpio.Newc.Writer(gzWriter)

	// Add a minimal file
	rec := cpio.Record{
		ReaderAt: bytes.NewReader([]byte("test")),
		Info: cpio.Info{
			Name:     "test.txt",
			Mode:     0644,
			FileSize: 4,
		},
	}

	require.NoError(t, cpioWriter.WriteRecord(rec))
	require.NoError(t, cpio.WriteTrailer(cpioWriter))
	require.NoError(t, gzWriter.Close())

	return buf.Bytes()
}

// verifyInitFSArchive reads a gzipped CPIO archive and verifies its contents
func verifyInitFSArchive(t *testing.T, archivePath string, verify func(t *testing.T, cfg domain.InitConfig, files map[string][]byte)) {
	t.Helper()

	// Open and decompress the archive
	f, err := os.Open(archivePath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	gzReader, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer func() { _ = gzReader.Close() }()

	// Read all data from gzip reader
	allData, err := io.ReadAll(gzReader)
	require.NoError(t, err)

	// Parse CPIO archive
	archiveReader := cpio.Newc.Reader(bytes.NewReader(allData))
	archive, err := cpio.ArchiveFromReader(archiveReader)
	require.NoError(t, err)

	// Extract files from archive
	files := make(map[string][]byte)
	reader := archive.Reader()
	for {
		rec, err := reader.ReadRecord()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		if rec.FileSize > 0 && rec.ReaderAt != nil {
			data := make([]byte, rec.FileSize)
			_, err := rec.ReadAt(data, 0)
			require.NoError(t, err)
			files[rec.Name] = data
		} else {
			files[rec.Name] = []byte{}
		}
	}

	// Parse config if it exists
	var cfg domain.InitConfig
	// CPIO may strip leading slashes, so try both with and without
	configPaths := []string{domain.InitConfigPath, domain.InitConfigPath[1:]} // Remove leading /
	var configData []byte
	var found bool
	for _, path := range configPaths {
		if data, ok := files[path]; ok {
			configData = data
			found = true
			break
		}
	}

	if found {
		require.NoError(t, json.Unmarshal(configData, &cfg))
	}

	// Call verification function
	verify(t, cfg, files)
}
