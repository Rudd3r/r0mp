package raftinit

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/u-root/u-root/pkg/cpio"
)

type InnitFSBuilder struct {
	initFS *cpio.Archive
	cfg    domain.InitConfig
	f      io.WriteCloser
}

func NewInitFS(baseInitF io.ReaderAt, outF io.WriteCloser) (*InnitFSBuilder, error) {
	initFS, err := cpio.ArchiveFromReader(cpio.Newc.Reader(baseInitF))
	if err != nil {
		return nil, fmt.Errorf("cpio.Reader.ArchiveFromReader: %v", err)
	}
	return &InnitFSBuilder{
		initFS: initFS,
		f:      gzip.NewWriter(outF),
	}, nil
}

func (i *InnitFSBuilder) AddNetworkInterface(n domain.NetworkInterface) {
	i.cfg.Networking = append(i.cfg.Networking, n)
}

func (i *InnitFSBuilder) AddDNSConfig(n domain.DNSServer) {
	i.cfg.DNSServer = &n
}

func (i *InnitFSBuilder) AddProcess(p domain.Process) {
	i.cfg.Processes = append(i.cfg.Processes, p)
}

func (i *InnitFSBuilder) AddMount(m domain.Mount) {
	i.cfg.Mounts = append(i.cfg.Mounts, m)
}

func (i *InnitFSBuilder) AddDiskFormat(d domain.DiskFormat) {
	i.cfg.DiskFormats = append(i.cfg.DiskFormats, d)
}

func (i *InnitFSBuilder) AddFSShare(share domain.FSShare) {
	mount := domain.Mount{
		Device:     share.MountTag,
		MountPoint: share.MountPoint,
		FSType:     "9p",
		Options:    []string{"trans=virtio", "version=9p2000.L"},
	}
	if share.ReadOnly {
		mount.Options = append(mount.Options, "ro")
	}
	i.cfg.Mounts = append(i.cfg.Mounts, mount)
}

func (i *InnitFSBuilder) ConfigureSSHServer(ssh *domain.SSHServer) {
	i.cfg.SSHServer = ssh
}

func (i *InnitFSBuilder) SetCACert(caCert []byte) {
	i.cfg.CACert = caCert
}

func (i *InnitFSBuilder) SetCACertPaths(paths []string) {
	i.cfg.CACertPaths = paths
}

func (i *InnitFSBuilder) AddCACertPath(path string) {
	i.cfg.CACertPaths = append(i.cfg.CACertPaths, path)
}

func (i *InnitFSBuilder) AddChroot(c domain.Chroot) {
	i.cfg.Chroots = append(i.cfg.Chroots, c)
}

func (i *InnitFSBuilder) AddInitBinary(initBinaryPath string) error {
	data, err := os.ReadFile(initBinaryPath)
	if err != nil {
		return fmt.Errorf("read init binary: %w", err)
	}
	return i.WriteFile(domain.FileInfo{FName: domain.InitFSBinPath, FMode: 0500, Uid: 0, Gid: 0}, data)
}

func (i *InnitFSBuilder) Close() error {
	cfgBytes, err := json.MarshalIndent(i.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %v", err)
	}
	if err = i.WriteFile(domain.FileInfo{FName: domain.InitConfigPath, FMode: 0400, Uid: 0, Gid: 0}, cfgBytes); err != nil {
		return fmt.Errorf("writing config: %v", err)
	}
	if err = cpio.Passthrough(i.initFS.Reader(), cpio.Newc.Writer(i.f)); err != nil {
		return fmt.Errorf("writing raftinit files: %v", err)
	}
	return i.f.Close()
}

func (i *InnitFSBuilder) Mkdir(info domain.FileInfo) error {
	return i.initFS.WriteRecord(cpio.Record{
		Info: cpio.Info{
			Mode: uint64(cpio.S_IFDIR | info.FMode.Perm()&^cpio.S_IFMT),
			UID:  uint64(info.Uid),
			GID:  uint64(info.Gid),
			Name: info.FName,
		},
	})
}

func (i *InnitFSBuilder) WriteFile(info domain.FileInfo, contents []byte) error {
	return i.initFS.WriteRecord(cpio.Record{
		ReaderAt: bytes.NewReader(contents),
		Info: cpio.Info{
			Mode:     uint64(cpio.S_IFREG | info.FMode.Perm()),
			UID:      uint64(info.Uid),
			GID:      uint64(info.Gid),
			FileSize: uint64(len(contents)),
			Name:     info.FName,
		},
	})
}

func (i *InnitFSBuilder) Symlink(target, linkname string, info domain.FileInfo) error {
	// Symlinks traditionally use 0777 permissions, though on Linux the permissions
	// are largely ignored (access is determined by the target file).
	// We use 0755 to follow the principle of least privilege.
	mode := info.FMode
	if mode == 0 {
		mode = 0755
	}
	return i.initFS.WriteRecord(cpio.Record{
		ReaderAt: bytes.NewReader([]byte(target)),
		Info: cpio.Info{
			Mode:     uint64(cpio.S_IFLNK | mode.Perm()),
			UID:      uint64(info.Uid),
			GID:      uint64(info.Gid),
			FileSize: uint64(len(target)),
			Name:     linkname,
		},
	})
}

// NewStandardChroot creates a chroot configuration with common Linux bind mounts
// required for a working environment. This includes /proc, /sys, /dev, /dev/pts,
// /dev/shm, and /tmp.
func NewStandardChroot(name, rootPath string) domain.Chroot {
	return domain.Chroot{
		Name:     name,
		RootPath: rootPath,
		BindMounts: []domain.BindMount{
			{
				Source:      "proc",
				Destination: "proc",
				FSType:      "proc",
				Options:     []string{},
				Flags:       syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC,
			},
			{
				Source:      "sysfs",
				Destination: "sys",
				FSType:      "sysfs",
				Options:     []string{},
				Flags:       syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_RDONLY,
			},
			{
				Source:      "devtmpfs",
				Destination: "dev",
				FSType:      "devtmpfs",
				Options:     []string{},
				Flags:       syscall.MS_NOSUID,
			},
			{
				Source:      "devpts",
				Destination: "dev/pts",
				FSType:      "devpts",
				Options:     []string{"newinstance", "ptmxmode=0666"},
				Flags:       syscall.MS_NOSUID | syscall.MS_NOEXEC,
			},
			{
				Source:      "tmpfs",
				Destination: "dev/shm",
				FSType:      "tmpfs",
				Options:     []string{},
				Flags:       syscall.MS_NOSUID | syscall.MS_NODEV,
			},
			{
				Source:      "tmpfs",
				Destination: "tmp",
				FSType:      "tmpfs",
				Options:     []string{},
				Flags:       syscall.MS_NOSUID | syscall.MS_NODEV,
			},
		},
	}
}
