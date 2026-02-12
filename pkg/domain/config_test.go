package domain

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultConfig(t *testing.T) {
	t.Run("creates config with default values", func(t *testing.T) {
		config := NewDefaultConfig()

		require.NotNil(t, config)
		assert.NotEmpty(t, config.CacheDir)
		assert.NotEmpty(t, config.ConfigDir)
		assert.NotEmpty(t, config.DataDir)
		assert.Equal(t, slog.LevelInfo, config.LogLevel)
		assert.Equal(t, int64(DefaultVolumeSizeBytes), config.DefaultVolumeSizeBytes)
		assert.Equal(t, uint(DefaultCpuCount), config.DefaultCpuCount)
		assert.Equal(t, DefaultMemorySize, config.DefaultMemorySize)
		assert.Equal(t, DefaultImage, config.DefaultImage)
		assert.False(t, config.Help)
	})

	t.Run("qemu path is set if available", func(t *testing.T) {
		config := NewDefaultConfig()

		// QemuPath might be empty if QEMU is not installed, which is fine
		// We just verify the field exists
		_ = config.QemuPath
	})

	t.Run("creates different instances", func(t *testing.T) {
		config1 := NewDefaultConfig()
		config2 := NewDefaultConfig()

		// Should be different pointers
		assert.NotSame(t, config1, config2)

		// But same values
		assert.Equal(t, config1.DefaultCpuCount, config2.DefaultCpuCount)
		assert.Equal(t, config1.DefaultMemorySize, config2.DefaultMemorySize)
	})
}

func TestConfigLoad(t *testing.T) {
	t.Run("creates config file if not exists", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &Config{}
		err := config.Load(tmpDir)
		require.NoError(t, err)

		// Verify config file was created
		cfgPath := filepath.Join(tmpDir, "config.json")
		assert.FileExists(t, cfgPath)

		// Verify config has default values
		assert.Equal(t, tmpDir, config.ConfigDir)
		assert.Equal(t, int64(DefaultVolumeSizeBytes), config.DefaultVolumeSizeBytes)
		assert.Equal(t, uint(DefaultCpuCount), config.DefaultCpuCount)
	})

	t.Run("loads existing config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.json")

		// Create a custom config file
		customConfig := &Config{
			QemuPath:               "/custom/qemu",
			CacheDir:               "/custom/cache",
			ConfigDir:              tmpDir,
			DataDir:                "/custom/data",
			LogLevel:               slog.LevelDebug,
			DefaultVolumeSizeBytes: 2048,
			DefaultCpuCount:        4,
			DefaultMemorySize:      "1G",
			DefaultImage:           "ubuntu:latest",
		}
		data, err := json.MarshalIndent(customConfig, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(cfgPath, data, 0600)
		require.NoError(t, err)

		// Load the config
		config := &Config{}
		err = config.Load(tmpDir)
		require.NoError(t, err)

		// Verify loaded values
		assert.Equal(t, "/custom/qemu", config.QemuPath)
		assert.Equal(t, "/custom/cache", config.CacheDir)
		assert.Equal(t, "/custom/data", config.DataDir)
		assert.Equal(t, slog.LevelDebug, config.LogLevel)
		assert.Equal(t, int64(2048), config.DefaultVolumeSizeBytes)
		assert.Equal(t, uint(4), config.DefaultCpuCount)
		assert.Equal(t, "1G", config.DefaultMemorySize)
		assert.Equal(t, "ubuntu:latest", config.DefaultImage)
	})

	t.Run("uses default config dir if empty", func(t *testing.T) {
		config := &Config{}
		err := config.Load("")

		// Should succeed and use default config dir
		require.NoError(t, err)
		assert.NotEmpty(t, config.ConfigDir)
	})

	t.Run("returns error if config path is a directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a directory with the config file name
		configAsDir := filepath.Join(tmpDir, "config.json")
		err := os.Mkdir(configAsDir, 0755)
		require.NoError(t, err)

		config := &Config{}
		err = config.Load(tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config file path is a directory")
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.json")

		// Write invalid JSON
		err := os.WriteFile(cfgPath, []byte("not valid json {{{"), 0600)
		require.NoError(t, err)

		config := &Config{}
		err = config.Load(tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal config file")
	})

	t.Run("loads environment variables after file", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Set environment variable
		originalEnv := os.Getenv(EnvMemorySize)
		defer func() {
			if originalEnv != "" {
				_ = os.Setenv(EnvMemorySize, originalEnv)
			} else {
				_ = os.Unsetenv(EnvMemorySize)
			}
		}()

		err := os.Setenv(EnvMemorySize, "2G")
		require.NoError(t, err)

		config := &Config{}
		err = config.Load(tmpDir)
		require.NoError(t, err)

		// Environment variable should override file value
		assert.Equal(t, "2G", config.DefaultMemorySize)
	})
}

func TestConfigLoadEnv(t *testing.T) {
	// Helper to save and restore env vars
	saveEnv := func(keys ...string) map[string]string {
		saved := make(map[string]string)
		for _, key := range keys {
			saved[key] = os.Getenv(key)
		}
		return saved
	}

	restoreEnv := func(saved map[string]string) {
		for key, val := range saved {
			if val != "" {
				_ = os.Setenv(key, val)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}

	t.Run("loads all environment variables", func(t *testing.T) {
		saved := saveEnv(
			EnvQemuPath, EnvCacheDir, EnvConfigDir, EnvDataDir,
			EnvVolumeSize, EnvCPUCount, EnvMemorySize, EnvImage, EnvLogLevel,
		)
		defer restoreEnv(saved)

		// Set all environment variables
		_ = os.Setenv(EnvQemuPath, "/test/qemu")
		_ = os.Setenv(EnvCacheDir, "/test/cache")
		_ = os.Setenv(EnvConfigDir, "/test/config")
		_ = os.Setenv(EnvDataDir, "/test/data")
		_ = os.Setenv(EnvVolumeSize, "2048")
		_ = os.Setenv(EnvCPUCount, "8")
		_ = os.Setenv(EnvMemorySize, "4G")
		_ = os.Setenv(EnvImage, "custom:image")
		_ = os.Setenv(EnvLogLevel, "DEBUG")

		config := NewDefaultConfig()
		err := config.loadEnv()
		require.NoError(t, err)

		assert.Equal(t, "/test/qemu", config.QemuPath)
		assert.Equal(t, "/test/cache", config.CacheDir)
		assert.Equal(t, "/test/config", config.ConfigDir)
		assert.Equal(t, "/test/data", config.DataDir)
		assert.Equal(t, int64(2048), config.DefaultVolumeSizeBytes)
		assert.Equal(t, uint(8), config.DefaultCpuCount)
		assert.Equal(t, "4G", config.DefaultMemorySize)
		assert.Equal(t, "custom:image", config.DefaultImage)
		assert.Equal(t, slog.LevelDebug, config.LogLevel)
	})

	t.Run("preserves defaults when env vars not set", func(t *testing.T) {
		saved := saveEnv(
			EnvQemuPath, EnvCacheDir, EnvVolumeSize, EnvCPUCount, EnvMemorySize,
		)
		defer restoreEnv(saved)

		// Unset all env vars
		_ = os.Unsetenv(EnvQemuPath)
		_ = os.Unsetenv(EnvCacheDir)
		_ = os.Unsetenv(EnvVolumeSize)
		_ = os.Unsetenv(EnvCPUCount)
		_ = os.Unsetenv(EnvMemorySize)

		config := NewDefaultConfig()
		originalVolumeSize := config.DefaultVolumeSizeBytes
		originalCpuCount := config.DefaultCpuCount
		originalMemorySize := config.DefaultMemorySize

		err := config.loadEnv()
		require.NoError(t, err)

		// Should keep original values
		assert.Equal(t, originalVolumeSize, config.DefaultVolumeSizeBytes)
		assert.Equal(t, originalCpuCount, config.DefaultCpuCount)
		assert.Equal(t, originalMemorySize, config.DefaultMemorySize)
	})

	t.Run("returns error for invalid volume size", func(t *testing.T) {
		saved := saveEnv(EnvVolumeSize)
		defer restoreEnv(saved)

		_ = os.Setenv(EnvVolumeSize, "not-a-number")

		config := NewDefaultConfig()
		err := config.loadEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid value for VolumeSize")
	})

	t.Run("returns error for invalid CPU count", func(t *testing.T) {
		saved := saveEnv(EnvCPUCount)
		defer restoreEnv(saved)

		_ = os.Setenv(EnvCPUCount, "invalid")

		config := NewDefaultConfig()
		err := config.loadEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid value for CpuCount")
	})

	t.Run("returns error for invalid log level", func(t *testing.T) {
		saved := saveEnv(EnvLogLevel)
		defer restoreEnv(saved)

		_ = os.Setenv(EnvLogLevel, "INVALID_LEVEL")

		config := NewDefaultConfig()
		err := config.loadEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("accepts valid log levels", func(t *testing.T) {
		saved := saveEnv(EnvLogLevel)
		defer restoreEnv(saved)

		testCases := []struct {
			envValue      string
			expectedLevel slog.Level
		}{
			{"DEBUG", slog.LevelDebug},
			{"INFO", slog.LevelInfo},
			{"WARN", slog.LevelWarn},
			{"ERROR", slog.LevelError},
		}

		for _, tc := range testCases {
			t.Run(tc.envValue, func(t *testing.T) {
				_ = os.Setenv(EnvLogLevel, tc.envValue)

				config := NewDefaultConfig()
				err := config.loadEnv()
				require.NoError(t, err)
				assert.Equal(t, tc.expectedLevel, config.LogLevel)
			})
		}
	})

	t.Run("handles negative values for volume size", func(t *testing.T) {
		saved := saveEnv(EnvVolumeSize)
		defer restoreEnv(saved)

		_ = os.Setenv(EnvVolumeSize, "-1000")

		config := NewDefaultConfig()
		err := config.loadEnv()
		require.NoError(t, err)

		// Should parse as negative (though probably not desired in practice)
		assert.Equal(t, int64(-1000), config.DefaultVolumeSizeBytes)
	})

	t.Run("handles large values for CPU count", func(t *testing.T) {
		saved := saveEnv(EnvCPUCount)
		defer restoreEnv(saved)

		_ = os.Setenv(EnvCPUCount, "128")

		config := NewDefaultConfig()
		err := config.loadEnv()
		require.NoError(t, err)
		assert.Equal(t, uint(128), config.DefaultCpuCount)
	})
}

func TestQemuPath(t *testing.T) {
	t.Run("returns env variable if set", func(t *testing.T) {
		saved := os.Getenv(EnvQemuPath)
		defer func() {
			if saved != "" {
				_ = os.Setenv(EnvQemuPath, saved)
			} else {
				_ = os.Unsetenv(EnvQemuPath)
			}
		}()

		customPath := "/custom/path/to/qemu"
		_ = os.Setenv(EnvQemuPath, customPath)

		path, err := QemuPath()
		require.NoError(t, err)
		assert.Equal(t, customPath, path)
	})

	t.Run("searches for qemu command based on architecture", func(t *testing.T) {
		saved := os.Getenv(EnvQemuPath)
		defer func() {
			if saved != "" {
				_ = os.Setenv(EnvQemuPath, saved)
			} else {
				_ = os.Unsetenv(EnvQemuPath)
			}
		}()

		// Unset env var to test lookup
		_ = os.Unsetenv(EnvQemuPath)

		path, err := QemuPath()

		// May or may not find QEMU depending on system
		if err == nil {
			assert.NotEmpty(t, path)

			// Check that it matches expected architecture
			switch runtime.GOARCH {
			case "amd64":
				assert.Contains(t, path, "qemu-system-x86_64")
			case "arm64":
				assert.Contains(t, path, "qemu-system-aarch64")
			}
		} else {
			// QEMU not installed, which is fine for testing
			t.Logf("QEMU not found on system (expected in CI): %v", err)
		}
	})

	t.Run("returns different commands for different architectures", func(t *testing.T) {
		// This test documents the architecture-specific behavior
		saved := os.Getenv(EnvQemuPath)
		defer func() {
			if saved != "" {
				_ = os.Setenv(EnvQemuPath, saved)
			} else {
				_ = os.Unsetenv(EnvQemuPath)
			}
		}()

		_ = os.Unsetenv(EnvQemuPath)

		// Just verify the function completes without panic
		_, _ = QemuPath()

		// Document expected behavior
		switch runtime.GOARCH {
		case "amd64":
			t.Log("On amd64, expects qemu-system-x86_64")
		case "arm64":
			t.Log("On arm64, expects qemu-system-aarch64")
		default:
			t.Logf("On %s, no qemu command defined", runtime.GOARCH)
		}
	})
}

func TestConfigConstants(t *testing.T) {
	t.Run("app name is set", func(t *testing.T) {
		assert.Equal(t, "r0mp", AppName)
	})

	t.Run("default values are reasonable", func(t *testing.T) {
		assert.Equal(t, int64(1*1024*1024*1024), int64(DefaultVolumeSizeBytes))
		assert.Equal(t, 2, DefaultCpuCount)
		assert.Equal(t, "512m", DefaultMemorySize)
		assert.Equal(t, "alpine:latest", DefaultImage)
	})

	t.Run("environment variable names are consistent", func(t *testing.T) {
		assert.Equal(t, "R0MP_QEMU_PATH", EnvQemuPath)
		assert.Equal(t, "R0MP_LOG_LEVEL", EnvLogLevel)
		assert.Equal(t, "R0MP_CACHE_DIR", EnvCacheDir)
		assert.Equal(t, "R0MP_CONFIG_DIR", EnvConfigDir)
		assert.Equal(t, "R0MP_DATA_DIR", EnvDataDir)
		assert.Equal(t, "R0MP_DEFAULT_VOLUME_SIZE", EnvVolumeSize)
		assert.Equal(t, "R0MP_DEFAULT_CPU_COUNT", EnvCPUCount)
		assert.Equal(t, "R0MP_DEFAULT_MEMORY_SIZE", EnvMemorySize)
		assert.Equal(t, "R0MP_DEFAULT_IMAGE", EnvImage)
		assert.Equal(t, "R0MP_SECRET_STORE_PASSWORD", EnvSecretStorePassword)
	})
}

func TestConfigJSON(t *testing.T) {
	t.Run("marshals to JSON correctly", func(t *testing.T) {
		config := &Config{
			QemuPath:               "/usr/bin/qemu",
			CacheDir:               "/cache",
			ConfigDir:              "/config",
			DataDir:                "/data",
			LogLevel:               slog.LevelInfo,
			DefaultVolumeSizeBytes: 1024,
			DefaultCpuCount:        4,
			DefaultMemorySize:      "1G",
			DefaultImage:           "test:image",
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify we can unmarshal it back
		var loaded Config
		err = json.Unmarshal(data, &loaded)
		require.NoError(t, err)

		assert.Equal(t, config.QemuPath, loaded.QemuPath)
		assert.Equal(t, config.CacheDir, loaded.CacheDir)
		assert.Equal(t, config.DefaultCpuCount, loaded.DefaultCpuCount)
	})

	t.Run("omits InsecureSecretStorePassword if empty", func(t *testing.T) {
		config := &Config{
			QemuPath:                    "/usr/bin/qemu",
			InsecureSecretStorePassword: "",
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		// Should not contain the field
		assert.NotContains(t, string(data), "InsecureSecretStorePassword")
	})

	t.Run("includes InsecureSecretStorePassword if set", func(t *testing.T) {
		config := &Config{
			QemuPath:                    "/usr/bin/qemu",
			InsecureSecretStorePassword: "test-password",
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		// Should contain the field
		assert.Contains(t, string(data), "InsecureSecretStorePassword")
		assert.Contains(t, string(data), "test-password")
	})

	t.Run("omits Help field from JSON", func(t *testing.T) {
		config := &Config{
			QemuPath: "/usr/bin/qemu",
			Help:     true,
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		// Help field should not be in JSON (json:"-" tag)
		assert.NotContains(t, string(data), "Help")
	})
}

func TestConfigSave(t *testing.T) {
	t.Run("saves config with all fields", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &Config{
			QemuPath:               "/usr/bin/qemu",
			CacheDir:               "/cache",
			ConfigDir:              tmpDir,
			DataDir:                "/data",
			LogLevel:               slog.LevelInfo,
			DefaultVolumeSizeBytes: 1024,
			DefaultCpuCount:        4,
			DefaultMemorySize:      "1G",
			DefaultImage:           "test:image",
		}

		err := config.Save()
		require.NoError(t, err)

		// Verify file was created
		cfgPath := filepath.Join(tmpDir, "config.json")
		assert.FileExists(t, cfgPath)

		// Load it back and verify
		loaded := &Config{}
		data, err := os.ReadFile(cfgPath)
		require.NoError(t, err)
		err = json.Unmarshal(data, loaded)
		require.NoError(t, err)

		assert.Equal(t, config.QemuPath, loaded.QemuPath)
		assert.Equal(t, config.CacheDir, loaded.CacheDir)
		assert.Equal(t, config.DefaultCpuCount, loaded.DefaultCpuCount)
	})

	t.Run("saves InsecureSecretStorePassword if set", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &Config{
			ConfigDir:                   tmpDir,
			InsecureSecretStorePassword: "test-password-123",
		}

		err := config.Save()
		require.NoError(t, err)

		// Load and verify password is saved
		cfgPath := filepath.Join(tmpDir, "config.json")
		data, err := os.ReadFile(cfgPath)
		require.NoError(t, err)

		// Verify JSON contains the password
		assert.Contains(t, string(data), "InsecureSecretStorePassword")
		assert.Contains(t, string(data), "test-password-123")

		// Verify it loads back correctly
		loaded := &Config{}
		err = json.Unmarshal(data, loaded)
		require.NoError(t, err)
		assert.Equal(t, "test-password-123", loaded.InsecureSecretStorePassword)
	})

	t.Run("returns error if ConfigDir not set", func(t *testing.T) {
		config := &Config{}
		err := config.Save()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config directory not set")
	})

	t.Run("file has secure permissions", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &Config{
			ConfigDir: tmpDir,
		}

		err := config.Save()
		require.NoError(t, err)

		cfgPath := filepath.Join(tmpDir, "config.json")
		info, err := os.Stat(cfgPath)
		require.NoError(t, err)

		// Should have 0600 permissions
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})
}

func TestSetInsecurePassword(t *testing.T) {
	t.Run("sets both InsecureSecretStorePassword and internal password", func(t *testing.T) {
		config := &Config{}
		config.SetInsecurePassword("test-password")

		assert.Equal(t, "test-password", config.InsecureSecretStorePassword)
		assert.Equal(t, "test-password", config.SecretStorePassword())
		assert.True(t, config.HasSecretStorePassword())
	})

	t.Run("can be saved and loaded", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &Config{
			ConfigDir: tmpDir,
		}
		config.SetInsecurePassword("saved-password")

		err := config.Save()
		require.NoError(t, err)

		// Load it back
		loaded := &Config{}
		err = loaded.Load(tmpDir)
		require.NoError(t, err)

		// Should have the password loaded
		assert.Equal(t, "saved-password", loaded.InsecureSecretStorePassword)
		assert.Equal(t, "saved-password", loaded.SecretStorePassword())
	})
}

func TestConfigLoadIntegration(t *testing.T) {
	t.Run("complete config lifecycle", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Save environment state
		saved := make(map[string]string)
		envVars := []string{EnvQemuPath, EnvMemorySize, EnvCPUCount}
		for _, key := range envVars {
			saved[key] = os.Getenv(key)
		}
		defer func() {
			for key, val := range saved {
				if val != "" {
					_ = os.Setenv(key, val)
				} else {
					_ = os.Unsetenv(key)
				}
			}
		}()

		// Set some env vars
		_ = os.Setenv(EnvMemorySize, "8G")
		_ = os.Setenv(EnvCPUCount, "16")

		// First load creates config file with defaults
		config1 := &Config{}
		err := config1.Load(tmpDir)
		require.NoError(t, err)

		// Verify env vars were applied
		assert.Equal(t, "8G", config1.DefaultMemorySize)
		assert.Equal(t, uint(16), config1.DefaultCpuCount)

		// Modify and save
		config1.DefaultImage = "custom:image"
		cfgPath := filepath.Join(tmpDir, "config.json")
		data, err := json.MarshalIndent(config1, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(cfgPath, data, 0600)
		require.NoError(t, err)

		// Second load should read the modified file
		config2 := &Config{}
		err = config2.Load(tmpDir)
		require.NoError(t, err)

		// Verify custom value from file
		assert.Equal(t, "custom:image", config2.DefaultImage)

		// Env vars still override
		assert.Equal(t, "8G", config2.DefaultMemorySize)
		assert.Equal(t, uint(16), config2.DefaultCpuCount)
	})

	t.Run("file permissions are secure", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &Config{}
		err := config.Load(tmpDir)
		require.NoError(t, err)

		cfgPath := filepath.Join(tmpDir, "config.json")
		info, err := os.Stat(cfgPath)
		require.NoError(t, err)

		// Config file should be created with 0600 permissions
		mode := info.Mode()
		assert.Equal(t, os.FileMode(0600), mode.Perm())
	})
}
