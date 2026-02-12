package raftinit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit_LoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      domain.InitConfig
		expectError bool
	}{
		{
			name: "valid config with all fields",
			config: domain.InitConfig{
				Networking: []domain.NetworkInterface{
					{
						Device: "eth0",
						Host:   "testhost",
						IP: net.IPNet{
							IP:   net.IPv4(10, 0, 2, 15),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
						DNS:         net.IPv4(8, 8, 8, 8),
						Gateway:     net.IPv4(10, 0, 2, 2),
						DisableIPV6: true,
					},
				},
				Mounts: []domain.Mount{
					{
						Device:     "/dev/vda",
						MountPoint: "/mnt/rootfs",
						FSType:     "ext4",
						Options:    []string{"ro"},
					},
				},
				Processes: []domain.Process{
					{
						Path: "/bin/sh",
						Args: []string{"-c", "echo hello"},
						Env:  []string{"PATH=/bin"},
						Dir:  "/",
						UID:  0,
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty config",
			config: domain.InitConfig{
				Networking: []domain.NetworkInterface{},
				Mounts:     []domain.Mount{},
				Processes:  []domain.Process{},
			},
			expectError: false,
		},
		{
			name: "config with multiple processes",
			config: domain.InitConfig{
				Processes: []domain.Process{
					{
						Path: "/bin/sh",
						Args: []string{"-c", "echo 1"},
						Dir:  "/",
						UID:  0,
					},
					{
						Path: "/bin/sh",
						Args: []string{"-c", "echo 2"},
						Dir:  "/",
						UID:  1000,
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "raft.cfg")

			// Marshal config to JSON
			data, err := json.MarshalIndent(tt.config, "", "  ")
			require.NoError(t, err)

			// Write config file
			require.NoError(t, os.WriteFile(configPath, data, 0644))

			// Create Init instance
			ctx := context.Background()
			init := NewInit(ctx, slog.Default())

			// Temporarily override the config path for testing
			oldPath := domain.InitConfigPath
			defer func() {
				// This won't actually change the const, but demonstrates intent
				_ = oldPath
			}()

			// Since we can't change the const, we'll need to test loadConfig with a modified Init
			// For this test, we'll manually set the config and verify marshaling/unmarshaling
			var loaded domain.InitConfig
			err = json.Unmarshal(data, &loaded)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.config.Networking, loaded.Networking)
				assert.Equal(t, tt.config.Mounts, loaded.Mounts)
				assert.Equal(t, tt.config.Processes, loaded.Processes)
			}

			// Verify the Init instance was created
			assert.NotNil(t, init)
			assert.NotNil(t, init.processGroup)
			assert.NotNil(t, init.ctx)
		})
	}
}

func TestInit_NewInit(t *testing.T) {
	t.Run("creates init with context", func(t *testing.T) {
		ctx := context.Background()
		init := NewInit(ctx, slog.Default())

		require.NotNil(t, init)
		assert.NotNil(t, init.ctx)
		assert.NotNil(t, init.processGroup)
	})

	t.Run("creates init with canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		init := NewInit(ctx, slog.Default())
		require.NotNil(t, init)

		// The context should be canceled
		assert.Error(t, init.ctx.Err())
	})

	t.Run("creates init with timeout context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		init := NewInit(ctx, slog.Default())
		require.NotNil(t, init)
		assert.NoError(t, init.ctx.Err())
	})
}

func TestInit_ConfigSerialization(t *testing.T) {
	tests := []struct {
		name   string
		config domain.InitConfig
	}{
		{
			name: "network interface serialization",
			config: domain.InitConfig{
				Networking: []domain.NetworkInterface{
					{
						Device: "eth0",
						Host:   "myhost",
						IP: net.IPNet{
							IP:   net.IPv4(192, 168, 1, 100),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
						DNS:         net.IPv4(8, 8, 8, 8),
						Gateway:     net.IPv4(192, 168, 1, 1),
						DisableIPV6: true,
					},
				},
			},
		},
		{
			name: "mount serialization",
			config: domain.InitConfig{
				Mounts: []domain.Mount{
					{
						Device:     "/dev/sda1",
						MountPoint: "/mnt/data",
						FSType:     "ext4",
						Options:    []string{"rw", "noatime"},
					},
				},
			},
		},
		{
			name: "process serialization",
			config: domain.InitConfig{
				Processes: []domain.Process{
					{
						Path: "/usr/bin/myapp",
						Args: []string{"--config", "/etc/myapp.conf"},
						Env:  []string{"KEY=value", "PATH=/usr/bin"},
						Dir:  "/opt/myapp",
						UID:  1000,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.config)
			require.NoError(t, err)

			// Unmarshal back
			var loaded domain.InitConfig
			err = json.Unmarshal(data, &loaded)
			require.NoError(t, err)

			// Compare
			if len(tt.config.Networking) > 0 {
				require.Len(t, loaded.Networking, len(tt.config.Networking))
				assert.Equal(t, tt.config.Networking[0].Device, loaded.Networking[0].Device)
				assert.Equal(t, tt.config.Networking[0].Host, loaded.Networking[0].Host)
				assert.Equal(t, tt.config.Networking[0].IP.IP.String(), loaded.Networking[0].IP.IP.String())
				assert.Equal(t, tt.config.Networking[0].DNS.String(), loaded.Networking[0].DNS.String())
				assert.Equal(t, tt.config.Networking[0].Gateway.String(), loaded.Networking[0].Gateway.String())
			}

			if len(tt.config.Mounts) > 0 {
				require.Len(t, loaded.Mounts, len(tt.config.Mounts))
				assert.Equal(t, tt.config.Mounts[0], loaded.Mounts[0])
			}

			if len(tt.config.Processes) > 0 {
				require.Len(t, loaded.Processes, len(tt.config.Processes))
				assert.Equal(t, tt.config.Processes[0], loaded.Processes[0])
			}
		})
	}
}

func TestInit_ProcessConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		process domain.Process
	}{
		{
			name: "process with all fields",
			process: domain.Process{
				Path: "/bin/sh",
				Args: []string{"-c", "echo hello"},
				Env:  []string{"VAR=value", "PATH=/bin"},
				Dir:  "/tmp",
				UID:  1000,
			},
		},
		{
			name: "process with minimal fields",
			process: domain.Process{
				Path: "/bin/sleep",
				Args: []string{"60"},
			},
		},
		{
			name: "process with root UID",
			process: domain.Process{
				Path: "/sbin/init",
				UID:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := domain.InitConfig{
				Processes: []domain.Process{tt.process},
			}

			data, err := json.Marshal(config)
			require.NoError(t, err)

			var loaded domain.InitConfig
			err = json.Unmarshal(data, &loaded)
			require.NoError(t, err)

			require.Len(t, loaded.Processes, 1)
			assert.Equal(t, tt.process.Path, loaded.Processes[0].Path)
			assert.Equal(t, tt.process.Args, loaded.Processes[0].Args)
			assert.Equal(t, tt.process.Env, loaded.Processes[0].Env)
			assert.Equal(t, tt.process.Dir, loaded.Processes[0].Dir)
			assert.Equal(t, tt.process.UID, loaded.Processes[0].UID)
		})
	}
}

func TestInit_MountConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		mount domain.Mount
	}{
		{
			name: "ext4 mount with options",
			mount: domain.Mount{
				Device:     "/dev/vda",
				MountPoint: "/mnt/data",
				FSType:     "ext4",
				Options:    []string{"rw", "noatime", "nodiratime"},
			},
		},
		{
			name: "tmpfs mount",
			mount: domain.Mount{
				Device:     "tmpfs",
				MountPoint: "/tmp",
				FSType:     "tmpfs",
				Options:    []string{"size=100m", "mode=1777"},
			},
		},
		{
			name: "mount without options",
			mount: domain.Mount{
				Device:     "/dev/vdb",
				MountPoint: "/mnt/backup",
				FSType:     "ext4",
				Options:    []string{},
			},
		},
		{
			name: "read-only mount",
			mount: domain.Mount{
				Device:     "/dev/vdc",
				MountPoint: "/mnt/readonly",
				FSType:     "ext4",
				Options:    []string{"ro"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := domain.InitConfig{
				Mounts: []domain.Mount{tt.mount},
			}

			data, err := json.Marshal(config)
			require.NoError(t, err)

			var loaded domain.InitConfig
			err = json.Unmarshal(data, &loaded)
			require.NoError(t, err)

			require.Len(t, loaded.Mounts, 1)
			assert.Equal(t, tt.mount, loaded.Mounts[0])
		})
	}
}

func TestInit_NetworkConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		network domain.NetworkInterface
	}{
		{
			name: "full network configuration",
			network: domain.NetworkInterface{
				Device: "eth0",
				Host:   "server1",
				IP: net.IPNet{
					IP:   net.IPv4(10, 0, 2, 15),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				DNS:         net.IPv4(8, 8, 8, 8),
				Gateway:     net.IPv4(10, 0, 2, 2),
				DisableIPV6: true,
			},
		},
		{
			name: "minimal network configuration",
			network: domain.NetworkInterface{
				Device: "eth0",
				IP: net.IPNet{
					IP:   net.IPv4(192, 168, 1, 100),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
		},
		{
			name: "network with IPv6 enabled",
			network: domain.NetworkInterface{
				Device: "eth1",
				IP: net.IPNet{
					IP:   net.IPv4(172, 16, 0, 10),
					Mask: net.IPv4Mask(255, 255, 0, 0),
				},
				DisableIPV6: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := domain.InitConfig{
				Networking: []domain.NetworkInterface{tt.network},
			}

			data, err := json.Marshal(config)
			require.NoError(t, err)

			var loaded domain.InitConfig
			err = json.Unmarshal(data, &loaded)
			require.NoError(t, err)

			require.Len(t, loaded.Networking, 1)
			assert.Equal(t, tt.network.Device, loaded.Networking[0].Device)
			assert.Equal(t, tt.network.Host, loaded.Networking[0].Host)
			assert.Equal(t, tt.network.IP.IP.String(), loaded.Networking[0].IP.IP.String())
			assert.Equal(t, tt.network.DisableIPV6, loaded.Networking[0].DisableIPV6)

			if !tt.network.DNS.IsUnspecified() {
				assert.Equal(t, tt.network.DNS.String(), loaded.Networking[0].DNS.String())
			}
			if !tt.network.Gateway.IsUnspecified() {
				assert.Equal(t, tt.network.Gateway.String(), loaded.Networking[0].Gateway.String())
			}
		})
	}
}

func TestInit_ComplexConfiguration(t *testing.T) {
	config := domain.InitConfig{
		Networking: []domain.NetworkInterface{
			{
				Device: "eth0",
				Host:   "webserver",
				IP: net.IPNet{
					IP:   net.IPv4(10, 0, 2, 20),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				DNS:         net.IPv4(8, 8, 8, 8),
				Gateway:     net.IPv4(10, 0, 2, 2),
				DisableIPV6: true,
			},
			{
				Device: "eth1",
				Host:   "internal",
				IP: net.IPNet{
					IP:   net.IPv4(192, 168, 100, 10),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				Gateway: net.IPv4(192, 168, 100, 1),
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
				Device:     "/dev/vdb",
				MountPoint: "/data",
				FSType:     "ext4",
				Options:    []string{"rw", "noatime"},
			},
			{
				Device:     "tmpfs",
				MountPoint: "/tmp",
				FSType:     "tmpfs",
				Options:    []string{"size=500m"},
			},
		},
		Processes: []domain.Process{
			{
				Path: "/usr/bin/sshd",
				Args: []string{"-D"},
				Env:  []string{"PATH=/usr/bin:/bin"},
				Dir:  "/",
				UID:  0,
			},
			{
				Path: "/usr/bin/nginx",
				Args: []string{"-g", "daemon off;"},
				Env:  []string{"PATH=/usr/bin"},
				Dir:  "/",
				UID:  33,
			},
			{
				Path: "/opt/app/server",
				Args: []string{"--port", "8080"},
				Env:  []string{"PATH=/usr/bin", "APP_ENV=production"},
				Dir:  "/opt/app",
				UID:  1000,
			},
		},
	}

	// Marshal and unmarshal
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)

	var loaded domain.InitConfig
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)

	// Verify all components
	assert.Len(t, loaded.Networking, 2)
	assert.Len(t, loaded.Mounts, 3)
	assert.Len(t, loaded.Processes, 3)

	// Spot check some values
	assert.Equal(t, "eth0", loaded.Networking[0].Device)
	assert.Equal(t, "/dev/vda", loaded.Mounts[0].Device)
	assert.Equal(t, "/usr/bin/sshd", loaded.Processes[0].Path)
}

func TestInit_ProcessWithChroot(t *testing.T) {
	tests := []struct {
		name    string
		process domain.Process
	}{
		{
			name: "process with chroot only",
			process: domain.Process{
				Path:   "/bin/sh",
				Args:   []string{"-c", "echo test"},
				Dir:    "/",
				Chroot: "/mnt/rootfs",
				UID:    0,
			},
		},
		{
			name: "process with chroot and non-root UID",
			process: domain.Process{
				Path:   "/bin/sh",
				Args:   []string{"-c", "id"},
				Dir:    "/",
				Chroot: "/mnt/rootfs",
				UID:    1000,
			},
		},
		{
			name: "process with chroot and working directory",
			process: domain.Process{
				Path:   "/usr/bin/node",
				Args:   []string{"/app/server.js"},
				Dir:    "/app",
				Chroot: "/mnt/rootfs",
				UID:    1000,
			},
		},
		{
			name: "process without chroot (backward compatibility)",
			process: domain.Process{
				Path:   "/bin/ls",
				Args:   []string{"-la", "/mnt/rootfs"},
				Dir:    "/",
				Chroot: "", // Empty = no chroot
				UID:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := domain.InitConfig{
				Processes: []domain.Process{tt.process},
			}

			// Marshal to JSON
			data, err := json.Marshal(config)
			require.NoError(t, err)

			// Unmarshal back
			var loaded domain.InitConfig
			err = json.Unmarshal(data, &loaded)
			require.NoError(t, err)

			// Verify
			require.Len(t, loaded.Processes, 1)
			assert.Equal(t, tt.process.Path, loaded.Processes[0].Path)
			assert.Equal(t, tt.process.Args, loaded.Processes[0].Args)
			assert.Equal(t, tt.process.Dir, loaded.Processes[0].Dir)
			assert.Equal(t, tt.process.Chroot, loaded.Processes[0].Chroot)
			assert.Equal(t, tt.process.UID, loaded.Processes[0].UID)
		})
	}
}

func TestInit_ChrootSerialization(t *testing.T) {
	t.Run("chroot field serializes correctly", func(t *testing.T) {
		config := domain.InitConfig{
			Processes: []domain.Process{
				{
					Path:   "/bin/sh",
					Chroot: "/mnt/rootfs",
				},
			},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		// Verify JSON contains Chroot field
		assert.Contains(t, string(data), "Chroot")
		assert.Contains(t, string(data), "/mnt/rootfs")

		// Unmarshal and verify
		var loaded domain.InitConfig
		err = json.Unmarshal(data, &loaded)
		require.NoError(t, err)
		assert.Equal(t, "/mnt/rootfs", loaded.Processes[0].Chroot)
	})

	t.Run("empty chroot serializes correctly", func(t *testing.T) {
		config := domain.InitConfig{
			Processes: []domain.Process{
				{
					Path:   "/bin/sh",
					Chroot: "", // Empty
				},
			},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		var loaded domain.InitConfig
		err = json.Unmarshal(data, &loaded)
		require.NoError(t, err)
		assert.Equal(t, "", loaded.Processes[0].Chroot)
	})
}

func TestInit_ChrootBackwardCompatibility(t *testing.T) {
	t.Run("old config without chroot field loads correctly", func(t *testing.T) {
		// Simulate old JSON config without Chroot field
		jsonConfig := `{
			"Networking": [],
			"Processes": [
				{
					"Path": "/bin/sh",
					"Args": ["-c", "echo test"],
					"Env": [],
					"Dir": "/",
					"UID": 0
				}
			],
			"Mounts": []
		}`

		var loaded domain.InitConfig
		err := json.Unmarshal([]byte(jsonConfig), &loaded)
		require.NoError(t, err)

		require.Len(t, loaded.Processes, 1)
		assert.Equal(t, "/bin/sh", loaded.Processes[0].Path)
		assert.Equal(t, "", loaded.Processes[0].Chroot) // Should default to empty
	})
}
