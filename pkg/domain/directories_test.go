package domain

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCacheDir(t *testing.T) {
	t.Run("returns valid cache directory", func(t *testing.T) {
		dir, err := UserCacheDir()
		require.NoError(t, err)
		assert.NotEmpty(t, dir)
		assert.Contains(t, dir, AppName)
	})

	t.Run("respects XDG_CACHE_HOME on linux", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("skipping linux-specific test")
		}

		// Save original value
		originalXDG := os.Getenv("XDG_CACHE_HOME")
		defer func() {
			if originalXDG != "" {
				_ = os.Setenv("XDG_CACHE_HOME", originalXDG)
			} else {
				_ = os.Unsetenv("XDG_CACHE_HOME")
			}
		}()

		// Set custom XDG_CACHE_HOME
		customCache := "/tmp/test-cache"
		require.NoError(t, os.Setenv("XDG_CACHE_HOME", customCache))

		dir, err := UserCacheDir()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(customCache, AppName), dir)
	})

	t.Run("falls back to HOME on linux when XDG_CACHE_HOME unset", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("skipping linux-specific test")
		}

		// Save original value
		originalXDG := os.Getenv("XDG_CACHE_HOME")
		defer func() {
			if originalXDG != "" {
				_ = os.Setenv("XDG_CACHE_HOME", originalXDG)
			}
		}()

		// Unset XDG_CACHE_HOME
		require.NoError(t, os.Unsetenv("XDG_CACHE_HOME"))

		dir, err := UserCacheDir()
		require.NoError(t, err)

		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, ".cache", AppName)
		assert.Equal(t, expected, dir)
	})

	t.Run("uses Library/Caches on darwin", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("skipping darwin-specific test")
		}

		dir, err := UserCacheDir()
		require.NoError(t, err)

		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, "Library", "Caches", AppName)
		assert.Equal(t, expected, dir)
	})

	t.Run("uses LocalAppData on windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("skipping windows-specific test")
		}

		dir, err := UserCacheDir()
		require.NoError(t, err)

		localAppData := os.Getenv("LocalAppData")
		expected := filepath.Join(localAppData, AppName, "cache")
		assert.Equal(t, expected, dir)
	})
}

func TestUserConfigDir(t *testing.T) {
	t.Run("returns valid config directory", func(t *testing.T) {
		dir, err := UserConfigDir()
		require.NoError(t, err)
		assert.NotEmpty(t, dir)
		assert.Contains(t, dir, AppName)
	})

	t.Run("respects XDG_CONFIG_HOME on linux", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("skipping linux-specific test")
		}

		// Save original value
		originalXDG := os.Getenv("XDG_CONFIG_HOME")
		defer func() {
			if originalXDG != "" {
				_ = os.Setenv("XDG_CONFIG_HOME", originalXDG)
			} else {
				_ = os.Unsetenv("XDG_CONFIG_HOME")
			}
		}()

		// Set custom XDG_CONFIG_HOME
		customConfig := "/tmp/test-config"
		require.NoError(t, os.Setenv("XDG_CONFIG_HOME", customConfig))

		dir, err := UserConfigDir()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(customConfig, AppName), dir)
	})

	t.Run("falls back to HOME on linux when XDG_CONFIG_HOME unset", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("skipping linux-specific test")
		}

		// Save original value
		originalXDG := os.Getenv("XDG_CONFIG_HOME")
		defer func() {
			if originalXDG != "" {
				_ = os.Setenv("XDG_CONFIG_HOME", originalXDG)
			}
		}()

		// Unset XDG_CONFIG_HOME
		require.NoError(t, os.Unsetenv("XDG_CONFIG_HOME"))

		dir, err := UserConfigDir()
		require.NoError(t, err)

		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, ".config", AppName)
		assert.Equal(t, expected, dir)
	})

	t.Run("uses Library/Application Support on darwin", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("skipping darwin-specific test")
		}

		dir, err := UserConfigDir()
		require.NoError(t, err)

		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, "Library", "Application Support", AppName)
		assert.Equal(t, expected, dir)
	})

	t.Run("uses LocalAppData on windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("skipping windows-specific test")
		}

		dir, err := UserConfigDir()
		require.NoError(t, err)

		localAppData := os.Getenv("LocalAppData")
		expected := filepath.Join(localAppData, AppName, "config")
		assert.Equal(t, expected, dir)
	})
}

func TestUserDataDir(t *testing.T) {
	t.Run("returns valid data directory", func(t *testing.T) {
		dir, err := UserDataDir()
		require.NoError(t, err)
		assert.NotEmpty(t, dir)
		assert.Contains(t, dir, AppName)
	})

	t.Run("respects XDG_DATA_HOME on linux", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("skipping linux-specific test")
		}

		// Save original value
		originalXDG := os.Getenv("XDG_DATA_HOME")
		defer func() {
			if originalXDG != "" {
				_ = os.Setenv("XDG_DATA_HOME", originalXDG)
			} else {
				_ = os.Unsetenv("XDG_DATA_HOME")
			}
		}()

		// Set custom XDG_DATA_HOME
		customData := "/tmp/test-data"
		require.NoError(t, os.Setenv("XDG_DATA_HOME", customData))

		dir, err := UserDataDir()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(customData, AppName), dir)
	})

	t.Run("falls back to HOME on linux when XDG_DATA_HOME unset", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("skipping linux-specific test")
		}

		// Save original value
		originalXDG := os.Getenv("XDG_DATA_HOME")
		defer func() {
			if originalXDG != "" {
				_ = os.Setenv("XDG_DATA_HOME", originalXDG)
			}
		}()

		// Unset XDG_DATA_HOME
		require.NoError(t, os.Unsetenv("XDG_DATA_HOME"))

		dir, err := UserDataDir()
		require.NoError(t, err)

		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, ".local", "state", AppName)
		assert.Equal(t, expected, dir)
	})

	t.Run("uses Library/Application Support on darwin", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("skipping darwin-specific test")
		}

		dir, err := UserDataDir()
		require.NoError(t, err)

		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, "Library", "Application Support", AppName)
		assert.Equal(t, expected, dir)
	})

	t.Run("uses LocalAppData on windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("skipping windows-specific test")
		}

		dir, err := UserDataDir()
		require.NoError(t, err)

		localAppData := os.Getenv("LocalAppData")
		expected := filepath.Join(localAppData, AppName, "data")
		assert.Equal(t, expected, dir)
	})
}

func TestEnsureDir(t *testing.T) {
	t.Run("creates directory if not exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "test", "nested", "dir")

		err := EnsureDir(testDir)
		require.NoError(t, err)

		// Check directory exists
		info, err := os.Stat(testDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("succeeds if directory already exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "existing")

		// Create directory first
		err := os.Mkdir(testDir, 0755)
		require.NoError(t, err)

		// Should not error on existing directory
		err = EnsureDir(testDir)
		require.NoError(t, err)
	})

	t.Run("returns error for invalid path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping permission test on windows")
		}

		// Try to create directory with invalid characters (null byte)
		invalidDir := "/tmp/test\x00invalid"
		err := EnsureDir(invalidDir)
		assert.Error(t, err)
	})
}

func TestDirectoryConsistency(t *testing.T) {
	t.Run("cache and config directories are different", func(t *testing.T) {
		cacheDir, err := UserCacheDir()
		require.NoError(t, err)

		configDir, err := UserConfigDir()
		require.NoError(t, err)

		// On most systems they should be different paths
		// Exception: on macOS, both config and data use same base directory
		if runtime.GOOS != "darwin" {
			assert.NotEqual(t, cacheDir, configDir)
		}
	})

	t.Run("subsequent calls return same directory", func(t *testing.T) {
		dir1, err := UserCacheDir()
		require.NoError(t, err)

		dir2, err := UserCacheDir()
		require.NoError(t, err)

		assert.Equal(t, dir1, dir2)
	})
}
