package domain

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
)

const (
	AppName = "r0mp"

	DefaultVolumeSizeBytes = 1 * 1024 * 1024 * 1024
	DefaultCpuCount        = 2
	DefaultMemorySize      = "512m"
	DefaultImage           = "alpine:latest"

	EnvQemuPath            = "R0MP_QEMU_PATH"
	EnvLogLevel            = "R0MP_LOG_LEVEL"
	EnvCacheDir            = "R0MP_CACHE_DIR"
	EnvConfigDir           = "R0MP_CONFIG_DIR"
	EnvDataDir             = "R0MP_DATA_DIR"
	EnvVolumeSize          = "R0MP_DEFAULT_VOLUME_SIZE"
	EnvCPUCount            = "R0MP_DEFAULT_CPU_COUNT"
	EnvMemorySize          = "R0MP_DEFAULT_MEMORY_SIZE"
	EnvImage               = "R0MP_DEFAULT_IMAGE"
	EnvSecretStorePassword = "R0MP_SECRET_STORE_PASSWORD"
)

type Config struct {
	QemuPath                    string
	CacheDir                    string
	ConfigDir                   string
	DataDir                     string
	LogLevel                    slog.Level
	DefaultVolumeSizeBytes      int64
	DefaultCpuCount             uint
	DefaultMemorySize           string
	DefaultImage                string
	InsecureSecretStorePassword string `json:",omitempty"`

	Help                bool `json:"-"`
	secretStorePassword string
}

func (c *Config) SecretStorePassword() string {
	return c.secretStorePassword
}

// SetSecretStorePassword sets the secret store password directly
func (c *Config) SetSecretStorePassword(password string) {
	c.secretStorePassword = password
}

// SetInsecurePassword sets the insecure secret store password field
// This also sets the internal password field for immediate use
func (c *Config) SetInsecurePassword(password string) {
	c.InsecureSecretStorePassword = password
	c.secretStorePassword = password
}

// HasSecretStorePassword returns true if a secret store password is configured
func (c *Config) HasSecretStorePassword() bool {
	return c.secretStorePassword != ""
}

func NewDefaultConfig() *Config {
	cacheDir, _ := UserCacheDir()
	configDir, _ := UserConfigDir()
	dataDir, _ := UserDataDir()
	qemuPath, _ := QemuPath()
	return &Config{
		QemuPath:               qemuPath,
		CacheDir:               cacheDir,
		ConfigDir:              configDir,
		DataDir:                dataDir,
		LogLevel:               slog.LevelInfo,
		DefaultVolumeSizeBytes: DefaultVolumeSizeBytes,
		DefaultCpuCount:        DefaultCpuCount,
		DefaultMemorySize:      DefaultMemorySize,
		DefaultImage:           DefaultImage,
	}
}

func (c *Config) Load(configDir string) error {
	*c = *NewDefaultConfig()
	if configDir == "" {
		configDir, _ = UserConfigDir()
	}
	if configDir == "" {
		return fmt.Errorf("failed to determine config directory")
	}
	c.ConfigDir = configDir
	err := EnsureDir(c.ConfigDir)
	cfgPath := filepath.Join(c.ConfigDir, "config.json")
	if err != nil {
		return fmt.Errorf("failed to ensure config dir: %w", err)
	}
	if cfgFileInfo, err := os.Stat(cfgPath); err == nil && cfgFileInfo.IsDir() {
		return fmt.Errorf("config file path is a directory")
	} else if err == nil {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		if err = json.Unmarshal(data, c); err != nil {
			return fmt.Errorf("failed to unmarshal config file: %w", err)
		}
	} else if os.IsNotExist(err) {
		// Create initial config file
		if err := c.Save(); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("failed to stat config path: %w", err)
	}

	return c.loadEnv()
}

// Save writes the config to disk
func (c *Config) Save() error {
	if c.ConfigDir == "" {
		return fmt.Errorf("config directory not set")
	}
	
	if err := EnsureDir(c.ConfigDir); err != nil {
		return fmt.Errorf("failed to ensure config dir: %w", err)
	}
	
	cfgPath := filepath.Join(c.ConfigDir, "config.json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err = os.WriteFile(cfgPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

func (c *Config) loadEnv() error {
	if qemuPath := os.Getenv(EnvQemuPath); qemuPath != "" {
		c.QemuPath = qemuPath
	}
	if cacheDir := os.Getenv(EnvCacheDir); cacheDir != "" {
		c.CacheDir = cacheDir
	}
	if configDir := os.Getenv(EnvConfigDir); configDir != "" {
		c.ConfigDir = configDir
	}
	if dataDir := os.Getenv(EnvDataDir); dataDir != "" {
		c.DataDir = dataDir
	}
	if volumeSize := os.Getenv(EnvVolumeSize); volumeSize != "" {
		sizeBytes, err := strconv.ParseInt(volumeSize, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid value for VolumeSize: %s", volumeSize)
		}
		c.DefaultVolumeSizeBytes = sizeBytes
	}
	if cpuCount := os.Getenv(EnvCPUCount); cpuCount != "" {
		cpuInt, err := strconv.ParseInt(cpuCount, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid value for CpuCount: %s", cpuCount)
		}
		c.DefaultCpuCount = uint(cpuInt)
	}
	if memorySize := os.Getenv(EnvMemorySize); memorySize != "" {
		c.DefaultMemorySize = memorySize
	}
	if image := os.Getenv(EnvImage); image != "" {
		c.DefaultImage = image
	}
	// Order of precedence for secret store password:
	// 1. Environment variable (highest priority)
	// 2. Config value (InsecureSecretStorePassword)
	// 3. Keyring (lowest priority)
	if pass := os.Getenv(EnvSecretStorePassword); pass != "" {
		c.secretStorePassword = pass
	} else if c.InsecureSecretStorePassword != "" {
		c.secretStorePassword = c.InsecureSecretStorePassword
	} else {
		// Try to get from keyring as last resort
		// We don't return an error here because the password might be set up later
		// or during first-time setup
		c.secretStorePassword = ""
	}
	if logLevel := os.Getenv(EnvLogLevel); logLevel != "" {
		if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
			return fmt.Errorf("invalid log level: %w", err)
		}
	}
	return nil
}

func QemuPath() (string, error) {
	if qemuPath := os.Getenv(EnvQemuPath); qemuPath != "" {
		return qemuPath, nil
	}
	var qemuCommandName string
	switch runtime.GOARCH {
	case "amd64":
		qemuCommandName = "qemu-system-x86_64"
	case "arm64":
		qemuCommandName = "qemu-system-aarch64"
	}
	return exec.LookPath(qemuCommandName)
}
