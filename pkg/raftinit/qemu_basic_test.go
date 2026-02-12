package raftinit

import (
	"bytes"
	"net"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestQEMUIntegration_ProcessExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Add test processes
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"TEST_PROCESS_OUTPUT_1"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"TEST_PROCESS_OUTPUT_2"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/pwd",
			Args: []string{},
			Env:  []string{},
			Dir:  "/tmp",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/sh",
			Args: []string{"-c", "echo $TEST_VAR"},
			Env:  []string{"TEST_VAR=hello_world"},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify process execution
	assert.Contains(t, outputStr, "TEST_PROCESS_OUTPUT_1", "first process should execute")
	assert.Contains(t, outputStr, "TEST_PROCESS_OUTPUT_2", "second process should execute")
	assert.Contains(t, outputStr, "/tmp", "process should run in specified directory")
	assert.Contains(t, outputStr, "hello_world", "environment variables should be passed")
}

func TestQEMUIntegration_MountConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Add tmpfs mount
		builder.AddMount(domain.Mount{
			Device:     "tmpfs",
			MountPoint: "/mnt/test",
			FSType:     "tmpfs",
			Options:    []string{"size=10m"},
		})

		// Add processes to verify mount
		builder.AddProcess(domain.Process{
			Path: "/bin/mount",
			Args: []string{},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/df",
			Args: []string{"-h"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/ls",
			Args: []string{"-la", "/mnt/test"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify mount configuration
	assert.Contains(t, outputStr, "/mnt/test", "mount point should exist")
	assert.Contains(t, outputStr, "tmpfs", "tmpfs should be mounted")
}

func TestQEMUIntegration_ComplexConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping QEMU integration test in short mode")
	}
	isQEMUAvailable(t)

	testDir := t.TempDir()
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Network configuration
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "complex-test",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 25),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(8, 8, 8, 8),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Mount configuration
		builder.AddMount(domain.Mount{
			Device:     "tmpfs",
			MountPoint: "/tmp",
			FSType:     "tmpfs",
			Options:    []string{"size=20m"},
		})

		// Multiple processes
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== System Information ==="},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/hostname",
			Args: []string{},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/sbin/ip",
			Args: []string{"addr"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/mount",
			Args: []string{},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/echo",
			Args: []string{"=== Test Complete ==="},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify all components
	assert.Contains(t, outputStr, "complex-test", "hostname should be set")
	assert.Contains(t, outputStr, "10.0.2.25", "IP address should be configured")
	assert.Contains(t, outputStr, "/tmp", "tmpfs mount should exist")
	assert.Contains(t, outputStr, "=== System Information ===", "first marker should appear")
	assert.Contains(t, outputStr, "=== Test Complete ===", "last marker should appear")
}
