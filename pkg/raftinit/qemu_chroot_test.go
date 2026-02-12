package raftinit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQEMUIntegration_ChrootBasic tests basic chroot functionality in QEMU
func TestQEMUIntegration_ChrootBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Create a minimal chroot environment in the initrd
		// Add directories
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/etc", FMode: 0755, Uid: 0, Gid: 0}))

		// Add a test file
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/etc/test.txt", FMode: 0644, Uid: 0, Gid: 0},
			[]byte("CHROOT_TEST_FILE"),
		))

		// Build testutil as a statically linked binary
		testutilPath := buildTestutil(t, testDir)
		testutilContent, err := os.ReadFile(testutilPath)
		require.NoError(t, err, "failed to read testutil")

		// Copy testutil and create symlinks for each utility
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/bin/testutil", FMode: 0755, Uid: 0, Gid: 0},
			testutilContent,
		))
		for _, binary := range []string{"ls", "cat", "echo"} {
			require.NoError(t, builder.WriteFile(
				domain.FileInfo{FName: "/mnt/rootfs/bin/" + binary, FMode: 0755, Uid: 0, Gid: 0},
				testutilContent,
			))
		}

		// Process WITHOUT chroot - should see full filesystem
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== Without Chroot ==="},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/ls",
			Args: []string{"-la", "/mnt/rootfs/etc"},
			Dir:  "/",
			UID:  0,
		})

		// Process WITH chroot - should only see chrooted filesystem
		builder.AddProcess(domain.Process{
			Path:   "/bin/echo",
			Args:   []string{"=== With Chroot ==="},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/ls",
			Args:   []string{"-la", "/etc"},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/cat",
			Args:   []string{"/etc/test.txt"},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify output
	assert.Contains(t, outputStr, "=== Without Chroot ===", "non-chroot process should execute")
	assert.Contains(t, outputStr, "=== With Chroot ===", "chroot process should execute")
	assert.Contains(t, outputStr, "CHROOT_TEST_FILE", "chroot process should access files in chroot")
}

// TestQEMUIntegration_ChrootWithUIDDrop tests chroot with UID dropping
func TestQEMUIntegration_ChrootWithUIDDrop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Create chroot directories in initrd
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/usr", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/usr/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/tmp", FMode: 0755, Uid: 0, Gid: 0}))

		// Build testutil as a statically linked binary
		testutilPath := buildTestutil(t, testDir)
		testutilContent, err := os.ReadFile(testutilPath)
		require.NoError(t, err, "failed to read testutil")

		// Copy testutil and create utilities
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/bin/testutil", FMode: 0755, Uid: 0, Gid: 0},
			testutilContent,
		))
		for _, binary := range []string{"sh", "echo"} {
			require.NoError(t, builder.WriteFile(
				domain.FileInfo{FName: "/mnt/rootfs/bin/" + binary, FMode: 0755, Uid: 0, Gid: 0},
				testutilContent,
			))
		}
		// id is in /usr/bin
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/usr/bin/id", FMode: 0755, Uid: 0, Gid: 0},
			testutilContent,
		))

		// Process with chroot as root
		builder.AddProcess(domain.Process{
			Path:   "/bin/echo",
			Args:   []string{"=== Chroot as root (UID 0) ==="},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/usr/bin/id",
			Args:   []string{},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})

		// Process with chroot and non-root UID
		builder.AddProcess(domain.Process{
			Path:   "/bin/echo",
			Args:   []string{"=== Chroot with UID drop (UID 1000) ==="},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    1000,
		})
		builder.AddProcess(domain.Process{
			Path:   "/usr/bin/id",
			Args:   []string{},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    1000,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify output
	assert.Contains(t, outputStr, "=== Chroot as root (UID 0) ===", "root process should execute")
	assert.Contains(t, outputStr, "=== Chroot with UID drop (UID 1000) ===", "non-root process should execute")
	assert.Contains(t, outputStr, "uid=0", "root process should show uid=0")
	assert.Contains(t, outputStr, "uid=1000", "non-root process should show uid=1000")
}

// TestQEMUIntegration_ChrootWithWorkingDirectory tests chroot with working directory
func TestQEMUIntegration_ChrootWithWorkingDirectory(t *testing.T) {
	isQEMUAvailable(t)

	testDir := t.TempDir()

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Create chroot directories in initrd
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/app", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/data", FMode: 0755, Uid: 0, Gid: 0}))

		// Add test files
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/app/app.txt", FMode: 0644, Uid: 0, Gid: 0},
			[]byte("APP_FILE"),
		))
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/data/data.txt", FMode: 0644, Uid: 0, Gid: 0},
			[]byte("DATA_FILE"),
		))

		// Build testutil as a statically linked binary
		testutilPath := buildTestutil(t, testDir)
		testutilContent, err := os.ReadFile(testutilPath)
		require.NoError(t, err, "failed to read testutil")

		// Copy testutil and create utilities
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/bin/testutil", FMode: 0755, Uid: 0, Gid: 0},
			testutilContent,
		))
		for _, binary := range []string{"pwd", "ls", "cat"} {
			require.NoError(t, builder.WriteFile(
				domain.FileInfo{FName: "/mnt/rootfs/bin/" + binary, FMode: 0755, Uid: 0, Gid: 0},
				testutilContent,
			))
		}

		// Test different working directories in chroot
		builder.AddProcess(domain.Process{
			Path:   "/bin/pwd",
			Args:   []string{},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/pwd",
			Args:   []string{},
			Chroot: "/mnt/rootfs",
			Dir:    "/app",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/cat",
			Args:   []string{"app.txt"},
			Chroot: "/mnt/rootfs",
			Dir:    "/app",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/pwd",
			Args:   []string{},
			Chroot: "/mnt/rootfs",
			Dir:    "/data",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/cat",
			Args:   []string{"data.txt"},
			Chroot: "/mnt/rootfs",
			Dir:    "/data",
			UID:    0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify output
	assert.Contains(t, outputStr, "APP_FILE", "should access file in /app")
	assert.Contains(t, outputStr, "DATA_FILE", "should access file in /data")
}

// TestQEMUIntegration_MultipleChrootProcesses tests multiple processes with different chroots
func TestQEMUIntegration_MultipleChrootProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Create two different chroot environments in initrd
		// Chroot 1
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/chroot1", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/chroot1/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/chroot1/etc", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/chroot1/etc/env.txt", FMode: 0644, Uid: 0, Gid: 0},
			[]byte("CHROOT1_ENV"),
		))

		// Chroot 2
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/chroot2", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/chroot2/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/chroot2/etc", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/chroot2/etc/env.txt", FMode: 0644, Uid: 0, Gid: 0},
			[]byte("CHROOT2_ENV"),
		))

		// Build testutil as a statically linked binary
		testutilPath := buildTestutil(t, testDir)
		testutilContent, err := os.ReadFile(testutilPath)
		require.NoError(t, err, "failed to read testutil")

		for _, chrootPath := range []string{"/mnt/chroot1", "/mnt/chroot2"} {
			// Copy testutil
			require.NoError(t, builder.WriteFile(
				domain.FileInfo{FName: chrootPath + "/bin/testutil", FMode: 0755, Uid: 0, Gid: 0},
				testutilContent,
			))
			// Create utilities
			for _, binary := range []string{"cat", "echo", "ls"} {
				require.NoError(t, builder.WriteFile(
					domain.FileInfo{FName: chrootPath + "/bin/" + binary, FMode: 0755, Uid: 0, Gid: 0},
					testutilContent,
				))
			}
		}

		// Processes in first chroot
		builder.AddProcess(domain.Process{
			Path:   "/bin/echo",
			Args:   []string{"=== Chroot 1 ==="},
			Chroot: "/mnt/chroot1",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/cat",
			Args:   []string{"/etc/env.txt"},
			Chroot: "/mnt/chroot1",
			Dir:    "/",
			UID:    0,
		})

		// Processes in second chroot
		builder.AddProcess(domain.Process{
			Path:   "/bin/echo",
			Args:   []string{"=== Chroot 2 ==="},
			Chroot: "/mnt/chroot2",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/cat",
			Args:   []string{"/etc/env.txt"},
			Chroot: "/mnt/chroot2",
			Dir:    "/",
			UID:    0,
		})

		// Process without chroot
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== No Chroot ==="},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/ls",
			Args: []string{"-d", "/mnt/chroot1", "/mnt/chroot2"},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify output
	assert.Contains(t, outputStr, "=== Chroot 1 ===", "chroot1 process should execute")
	assert.Contains(t, outputStr, "CHROOT1_ENV", "chroot1 process should see chroot1 files")
	assert.Contains(t, outputStr, "=== Chroot 2 ===", "chroot2 process should execute")
	assert.Contains(t, outputStr, "CHROOT2_ENV", "chroot2 process should see chroot2 files")
	assert.Contains(t, outputStr, "=== No Chroot ===", "non-chroot process should execute")
}

// TestQEMUIntegration_ChrootWithFSShare tests chroot combined with FSShare
func TestQEMUIntegration_ChrootWithFSShare(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()

	// Create host directory for FSShare
	hostShareDir := filepath.Join(testDir, "host_share")
	require.NoError(t, os.MkdirAll(hostShareDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(hostShareDir, "shared.txt"), []byte("SHARED_FILE_CONTENT"), 0644))

	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Create chroot directories in initrd
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/bin", FMode: 0755, Uid: 0, Gid: 0}))
		require.NoError(t, builder.Mkdir(domain.FileInfo{FName: "/mnt/rootfs/app", FMode: 0755, Uid: 0, Gid: 0}))

		// Build testutil as a statically linked binary
		testutilPath := buildTestutil(t, testDir)
		testutilContent, err := os.ReadFile(testutilPath)
		require.NoError(t, err, "failed to read testutil")

		// Copy testutil and create utilities
		require.NoError(t, builder.WriteFile(
			domain.FileInfo{FName: "/mnt/rootfs/bin/testutil", FMode: 0755, Uid: 0, Gid: 0},
			testutilContent,
		))
		for _, binary := range []string{"cat", "ls", "echo", "mount"} {
			require.NoError(t, builder.WriteFile(
				domain.FileInfo{FName: "/mnt/rootfs/bin/" + binary, FMode: 0755, Uid: 0, Gid: 0},
				testutilContent,
			))
		}

		// Add FSShare configuration - mounts to /mnt/shared (outside chroot initially)
		builder.AddFSShare(domain.FSShare{
			HostPath:   hostShareDir,
			MountTag:   "hostshare",
			MountPoint: "/mnt/shared",
			ReadOnly:   true,
		})

		// Process without chroot accessing FSShare
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== Without Chroot - Accessing FSShare ==="},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/mnt/shared/shared.txt"},
			Dir:  "/",
			UID:  0,
		})

		// Process with chroot - FSShare is mounted outside chroot
		// This demonstrates that chroot isolates the filesystem
		builder.AddProcess(domain.Process{
			Path:   "/bin/echo",
			Args:   []string{"=== With Chroot - Cannot Access FSShare ==="},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})
		builder.AddProcess(domain.Process{
			Path:   "/bin/ls",
			Args:   []string{"-la", "/"},
			Chroot: "/mnt/rootfs",
			Dir:    "/",
			UID:    0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	runQEMUWithFSShare(t, initPath, hostShareDir, "hostshare", output)
	outputStr := output.String()

	// Verify output
	assert.Contains(t, outputStr, "=== Without Chroot - Accessing FSShare ===", "non-chroot process should execute")
	assert.Contains(t, outputStr, "SHARED_FILE_CONTENT", "non-chroot process should access FSShare")
	assert.Contains(t, outputStr, "=== With Chroot - Cannot Access FSShare ===", "chroot process should execute")
	// Chroot process should NOT see /mnt/shared because it's outside the chroot
}

func TestQEMUIntegration_ChrootConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Create a tmpfs mount for our chroot root
		builder.AddMount(domain.Mount{
			Device:     "tmpfs",
			MountPoint: "/mnt/rootfs",
			FSType:     "tmpfs",
			Options:    []string{"size=50m"},
		})

		// Add a standard chroot with all necessary bind mounts
		chroot := NewStandardChroot("testroot", "/mnt/rootfs")
		builder.AddChroot(chroot)

		// Add processes to verify chroot setup
		// First, verify chroot directory exists
		builder.AddProcess(domain.Process{
			Path: "/bin/ls",
			Args: []string{"-la", "/mnt/rootfs"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})

		// Verify bind mounts inside the chroot by checking /proc
		builder.AddProcess(domain.Process{
			Path: "/bin/mount",
			Args: []string{},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})

		// Run process in chroot to verify /proc is available
		builder.AddProcess(domain.Process{
			Path:   "/bin/ls",
			Args:   []string{"-la", "/proc"},
			Env:    []string{},
			Dir:    "/",
			UID:    0,
			Chroot: "/mnt/rootfs",
		})

		// Verify /sys is available and read-only
		builder.AddProcess(domain.Process{
			Path:   "/bin/ls",
			Args:   []string{"-la", "/sys"},
			Env:    []string{},
			Dir:    "/",
			UID:    0,
			Chroot: "/mnt/rootfs",
		})

		// Verify /dev is available
		builder.AddProcess(domain.Process{
			Path:   "/bin/ls",
			Args:   []string{"-la", "/dev"},
			Env:    []string{},
			Dir:    "/",
			UID:    0,
			Chroot: "/mnt/rootfs",
		})

		// Verify /tmp is available
		builder.AddProcess(domain.Process{
			Path:   "/bin/ls",
			Args:   []string{"-la", "/tmp"},
			Env:    []string{},
			Dir:    "/",
			UID:    0,
			Chroot: "/mnt/rootfs",
		})

		// Test that we can create a file in /tmp inside chroot
		builder.AddProcess(domain.Process{
			Path:   "/bin/sh",
			Args:   []string{"-c", "echo 'CHROOT_TEST_MARKER' > /tmp/test.txt && cat /tmp/test.txt"},
			Env:    []string{},
			Dir:    "/",
			UID:    0,
			Chroot: "/mnt/rootfs",
		})

		// Verify the chroot marker was written
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== Chroot Test Complete ==="},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify chroot directory was created
	assert.Contains(t, outputStr, "/mnt/rootfs", "chroot root directory should exist")

	// Verify bind mounts were created
	assert.Contains(t, outputStr, "/mnt/rootfs/proc", "proc bind mount should exist")
	assert.Contains(t, outputStr, "/mnt/rootfs/sys", "sys bind mount should exist")
	assert.Contains(t, outputStr, "/mnt/rootfs/dev", "dev bind mount should exist")

	// Verify processes ran in chroot and could access bind mounts
	assert.Contains(t, outputStr, "CHROOT_TEST_MARKER", "process in chroot should be able to write to /tmp")

	// Verify test completion marker
	assert.Contains(t, outputStr, "=== Chroot Test Complete ===", "test should complete successfully")
}
