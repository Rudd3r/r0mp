package raftinit

import (
	"bytes"
	"net"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestQEMUIntegration_NetworkConfiguration(t *testing.T) {
	isQEMUAvailable(t)

	// Setup test environment
	testDir := t.TempDir()
	initPath := buildAndCreateInitrd(t, testDir, func(builder *InnitFSBuilder) error {
		// Configure network
		builder.AddNetworkInterface(domain.NetworkInterface{
			Device: "eth0",
			Host:   "testhost",
			IP: net.IPNet{
				IP:   net.IPv4(10, 0, 2, 20),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			DNS:         net.IPv4(10, 0, 2, 3),
			Gateway:     net.IPv4(10, 0, 2, 2),
			DisableIPV6: true,
		})

		// Add processes to verify network configuration
		builder.AddProcess(domain.Process{
			Path: "/bin/hostname",
			Args: []string{},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/sbin/ip",
			Args: []string{"addr", "show", "eth0"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/sbin/ip",
			Args: []string{"route"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})
		builder.AddProcess(domain.Process{
			Path: "/bin/cat",
			Args: []string{"/etc/resolv.conf"},
			Env:  []string{},
			Dir:  "/",
			UID:  0,
		})

		return nil
	})

	// Run QEMU and capture output
	output := &bytes.Buffer{}
	_, _ = runQEMU(t, initPath, output)
	outputStr := output.String()

	// Verify network configuration
	assert.Contains(t, outputStr, "testhost", "hostname should be set")
	assert.Contains(t, outputStr, "10.0.2.20", "IP address should be configured")
	assert.Contains(t, outputStr, "10.0.2.2", "gateway should be configured")
	assert.Contains(t, outputStr, "nameserver 10.0.2.3", "DNS should be configured")
}
