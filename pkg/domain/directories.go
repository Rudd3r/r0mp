package domain

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// UserCacheDir returns the default cache directory for the application.
// It follows platform-specific conventions:
//   - Linux/Unix: $XDG_CACHE_HOME/r0mp or $HOME/.cache/r0mp
//   - macOS: $HOME/Library/Caches/r0mp
//   - Windows: %LocalAppData%\r0mp\cache
func UserCacheDir() (string, error) {
	if cacheDir := os.Getenv(EnvCacheDir); cacheDir != "" {
		return cacheDir, nil
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("LocalAppData")
		if base == "" {
			return "", fmt.Errorf("%%LocalAppData%% is not defined")
		}
		return filepath.Join(base, AppName, "cache"), nil

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Caches", AppName), nil

	default: // Linux and other Unix-like systems
		if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
			return filepath.Join(xdgCache, AppName), nil
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, ".cache", AppName), nil
	}
}

// UserConfigDir returns the default configuration directory for the application.
// It follows platform-specific conventions:
//   - Linux/Unix: $XDG_CONFIG_HOME/r0mp or $HOME/.config/r0mp
//   - macOS: $HOME/Library/Application Support/r0mp
//   - Windows: %LocalAppData%\r0mp\config
func UserConfigDir() (string, error) {
	if configDir := os.Getenv(EnvConfigDir); configDir != "" {
		return configDir, nil
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("LocalAppData")
		if base == "" {
			return "", fmt.Errorf("%%LocalAppData%% is not defined")
		}
		return filepath.Join(base, AppName, "config"), nil

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", AppName), nil

	default: // Linux and other Unix-like systems
		if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
			return filepath.Join(xdgConfig, AppName), nil
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, ".config", AppName), nil
	}
}

// UserDataDir returns the default data directory for the application.
// It follows platform-specific conventions:
//   - Linux/Unix: $XDG_DATA_HOME/r0mp or $HOME/.local/share/r0mp
//   - macOS: $HOME/Library/Application Support/r0mp
//   - Windows: %LocalAppData%\r0mp\data
func UserDataDir() (string, error) {
	if dataDir := os.Getenv(EnvDataDir); dataDir != "" {
		return dataDir, nil
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("LocalAppData")
		if base == "" {
			return "", fmt.Errorf("%%LocalAppData%% is not defined")
		}
		return filepath.Join(base, AppName, "data"), nil

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", AppName), nil

	default: // Linux and other Unix-like systems
		if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
			return filepath.Join(xdgData, AppName), nil
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, ".local", "state", AppName), nil
	}
}

// EnsureDir ensures that the specified directory exists, creating it if necessary.
// It creates all parent directories as needed with permissions 0755.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	return nil
}
