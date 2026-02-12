package domain

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Ports struct {
	HostPort  uint64
	HostIP    string
	GuestPort uint64
	GuestIP   string
}

type QemuConfig struct {
	Raft   *Raft
	Logger *slog.Logger
	Stderr io.Writer
}

func (c *QemuConfig) Valid() error {
	if c.Raft.QemuPath == "" {
		return fmt.Errorf("QemuPath is required")
	}
	if !filepath.IsAbs(c.Raft.QemuPath) {
		path, err := exec.LookPath(c.Raft.QemuPath)
		if err != nil {
			return fmt.Errorf("QEMU binary not found: %w", err)
		}
		c.Raft.QemuPath = path
	}
	_, err := os.Stat(c.Raft.QemuPath)
	if err != nil {
		return fmt.Errorf("QEMU binary not accessible: %w", err)
	}

	if c.Raft.Memory == "" {
		return fmt.Errorf("memory is required")
	}
	if err := validateMemoryFormat(c.Raft.Memory); err != nil {
		return fmt.Errorf("invalid Memory format: %w", err)
	}

	// Validate port ranges (1024-65535 for unprivileged ports)
	for i, port := range c.Raft.Ports {
		if port.HostPort < 1024 {
			return fmt.Errorf("port %d: HostPort %d is below 1024 (requires admin privileges)", i, port.HostPort)
		}
		if port.HostPort > 65535 {
			return fmt.Errorf("port %d: HostPort %d is above 65535 (invalid)", i, port.HostPort)
		}
		if port.GuestPort < 1 || port.GuestPort > 65535 {
			return fmt.Errorf("port %d: GuestPort %d is invalid (must be 1-65535)", i, port.GuestPort)
		}
	}

	// Validate FSShares
	for i, share := range c.Raft.FSShares {
		if err := validateFSShare(i, &share); err != nil {
			return err
		}
	}

	if c.Stderr == nil {
		return fmt.Errorf("stderr is required")
	}

	if c.Raft.KernelPath == "" {
		return fmt.Errorf("KernelPath is required")
	}
	if c.Raft.InitPath == "" {
		return fmt.Errorf("InitPath is required")
	}

	return nil
}

func validateMemoryFormat(mem string) error {
	if len(mem) < 2 {
		return fmt.Errorf("memory string too short: %s", mem)
	}

	suffix := mem[len(mem)-1]

	validSuffixes := "MGKTmgkt"
	if !strings.ContainsRune(validSuffixes, rune(suffix)) {
		return fmt.Errorf("invalid suffix '%c', must be one of: M, G, K, T", suffix)
	}

	numPart := mem[:len(mem)-1]
	_, err := strconv.ParseUint(numPart, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid numeric value '%s': %w", numPart, err)
	}

	return nil
}

func validateFSShare(index int, share *FSShare) error {
	if share.HostPath == "" {
		return fmt.Errorf("FSShare %d: HostPath is required", index)
	}

	// Check if host path exists
	if _, err := os.Stat(share.HostPath); err != nil {
		return fmt.Errorf("FSShare %d: HostPath '%s' is not accessible: %w", index, share.HostPath, err)
	}

	if share.MountTag == "" {
		return fmt.Errorf("FSShare %d: MountTag is required", index)
	}

	// Validate mount tag (alphanumeric and underscores only)
	if !isValidMountTag(share.MountTag) {
		return fmt.Errorf("FSShare %d: MountTag '%s' is invalid (must contain only alphanumeric characters and underscores)", index, share.MountTag)
	}

	if share.MountPoint == "" {
		return fmt.Errorf("FSShare %d: MountPoint is required", index)
	}

	if !filepath.IsAbs(share.MountPoint) {
		return fmt.Errorf("FSShare %d: MountPoint '%s' must be an absolute path", index, share.MountPoint)
	}

	// Set default security model if not specified
	if share.SecurityModel == "" {
		share.SecurityModel = "mapped-xattr"
	}

	// Validate security model
	validModels := map[string]bool{
		"passthrough":  true,
		"mapped-xattr": true,
		"mapped-file":  true,
		"none":         true,
	}
	if !validModels[share.SecurityModel] {
		return fmt.Errorf("FSShare %d: SecurityModel '%s' is invalid (must be one of: passthrough, mapped-xattr, mapped-file, none)", index, share.SecurityModel)
	}

	return nil
}

func isValidMountTag(tag string) bool {
	if tag == "" {
		return false
	}
	for _, c := range tag {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
