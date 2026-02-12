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

func TestQEMUIntegration_FSShare(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()

	// Create a host directory with test files
	hostShareDir := filepath.Join(testDir, "host_share")
	require.NoError(t, os.MkdirAll(hostShareDir, 0755))

	// Create test files in the host share directory
	testFile1 := filepath.Join(hostShareDir, "test1.txt")
	require.NoError(t, os.WriteFile(testFile1, []byte("Hello from host file 1\n"), 0644))

	testFile2 := filepath.Join(hostShareDir, "test2.txt")
	require.NoError(t, os.WriteFile(testFile2, []byte("Hello from host file 2\n"), 0644))

	// Create a subdirectory with another file
	subDir := filepath.Join(hostShareDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	testFile3 := filepath.Join(subDir, "test3.txt")
	require.NoError(t, os.WriteFile(testFile3, []byte("Hello from subdirectory\n"), 0644))

	// Build initrd with FSShare configuration
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Add FSShare
		builder.AddFSShare(domain.FSShare{
			HostPath:      hostShareDir,
			MountTag:      "host_share",
			MountPoint:    "/mnt/host",
			ReadOnly:      false,
			SecurityModel: "mapped-xattr",
		})

		// Add processes to verify the mount and access files
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== Testing 9P Mount ==="},
			Dir:  "/",
			UID:  0,
		})

		// List the mounted directory
		builder.AddProcess(domain.Process{
			Path: "/bin/ls",
			Args: []string{"-la", "/mnt/host"},
			Dir:  "/",
			UID:  0,
		})

		// Read test file 1
		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/mnt/host/test1.txt"},
			Dir:  "/",
			UID:  0,
		})

		// Read test file 2
		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/mnt/host/test2.txt"},
			Dir:  "/",
			UID:  0,
		})

		// List subdirectory
		builder.AddProcess(domain.Process{
			Path: "/bin/ls",
			Args: []string{"-la", "/mnt/host/subdir"},
			Dir:  "/",
			UID:  0,
		})

		// Read file from subdirectory
		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/mnt/host/subdir/test3.txt"},
			Dir:  "/",
			UID:  0,
		})

		// Verify mount is present
		builder.AddProcess(domain.Process{
			Path: "/bin/mount",
			Args: []string{},
			Dir:  "/",
			UID:  0,
		})

		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== 9P Test Complete ==="},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	// Configure QEMU with FSShare
	output := &bytes.Buffer{}
	runQEMUWithFSShare(t, initPath, hostShareDir, "host_share", output)
	outputStr := output.String()

	// Verify mount succeeded
	assert.Contains(t, outputStr, "=== Testing 9P Mount ===", "test should start")
	assert.Contains(t, outputStr, "/mnt/host", "mount point should appear")

	// Verify files are visible
	assert.Contains(t, outputStr, "test1.txt", "test1.txt should be listed")
	assert.Contains(t, outputStr, "test2.txt", "test2.txt should be listed")
	assert.Contains(t, outputStr, "subdir", "subdir should be listed")

	// Verify file contents are readable
	assert.Contains(t, outputStr, "Hello from host file 1", "test1.txt content should be readable")
	assert.Contains(t, outputStr, "Hello from host file 2", "test2.txt content should be readable")
	assert.Contains(t, outputStr, "Hello from subdirectory", "test3.txt content should be readable")

	// Verify 9p mount in mount table
	assert.Contains(t, outputStr, "9p", "9p filesystem should be mounted")
	assert.Contains(t, outputStr, "host_share", "mount tag should appear in mount table")

	assert.Contains(t, outputStr, "=== 9P Test Complete ===", "test should complete")
}

func TestQEMUIntegration_MultipleFSShares(t *testing.T) {
	isQEMUAvailable(t)

	testDir := t.TempDir()

	// Create multiple host directories
	workspaceDir := filepath.Join(testDir, "workspace")
	require.NoError(t, os.MkdirAll(workspaceDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(workspaceDir, "code.txt"), []byte("workspace code\n"), 0644))

	dataDir := filepath.Join(testDir, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "data.txt"), []byte("data content\n"), 0644))

	configDir := filepath.Join(testDir, "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "app.conf"), []byte("config=value\n"), 0644))

	// Build initrd with multiple FSShares
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		builder.AddFSShare(domain.FSShare{
			HostPath:      workspaceDir,
			MountTag:      "workspace",
			MountPoint:    "/mnt/workspace",
			ReadOnly:      false,
			SecurityModel: "mapped-xattr",
		})

		builder.AddFSShare(domain.FSShare{
			HostPath:      dataDir,
			MountTag:      "data",
			MountPoint:    "/mnt/data",
			ReadOnly:      true,
			SecurityModel: "mapped-xattr",
		})

		builder.AddFSShare(domain.FSShare{
			HostPath:      configDir,
			MountTag:      "config",
			MountPoint:    "/etc/app",
			ReadOnly:      true,
			SecurityModel: "mapped-xattr",
		})

		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== Testing Multiple 9P Mounts ==="},
			Dir:  "/",
			UID:  0,
		})

		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/mnt/workspace/code.txt"},
			Dir:  "/",
			UID:  0,
		})

		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/mnt/data/data.txt"},
			Dir:  "/",
			UID:  0,
		})

		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/etc/app/app.conf"},
			Dir:  "/",
			UID:  0,
		})

		builder.AddProcess(domain.Process{
			Path: "/bin/mount",
			Args: []string{},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	runQEMUWithMultipleFSShares(t, initPath, []fsShareConfig{
		{hostPath: workspaceDir, tag: "workspace"},
		{hostPath: dataDir, tag: "data"},
		{hostPath: configDir, tag: "config"},
	}, output)
	outputStr := output.String()

	// Verify all shares are accessible
	assert.Contains(t, outputStr, "workspace code", "workspace share should be readable")
	assert.Contains(t, outputStr, "data content", "data share should be readable")
	assert.Contains(t, outputStr, "config=value", "config share should be readable")

	// Verify all mount tags appear in mount table
	assert.Contains(t, outputStr, "workspace", "workspace mount tag should appear")
	assert.Contains(t, outputStr, "data", "data mount tag should appear")
	assert.Contains(t, outputStr, "config", "config mount tag should appear")
}
