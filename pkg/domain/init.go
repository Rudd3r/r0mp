package domain

import "net"

type InitConfig struct {
	Networking      []NetworkInterface
	Processes       []Process
	Mounts          []Mount
	DiskFormats     []DiskFormat
	Chroots         []Chroot
	SSHServer       *SSHServer
	DNSServer       *DNSServer
	ResourceMonitor *ResourceMonitor
	CACert          []byte   // CA certificate in PEM format for SSL/TLS trust
	CACertPaths     []string // Paths where CA cert should be installed (default: /etc/ssl/certs/ca-certificates.crt)
}

type Process struct {
	Path   string   // Executable path (relative to Chroot if set)
	Args   []string // Command arguments
	Env    []string // Environment variables
	Dir    string   // Working directory (relative to Chroot if set)
	UID    uint64   // User ID to run as (0 = root)
	Chroot string   // Root directory for the process
}

type NetworkInterface struct {
	Device      string
	Host        string
	IP          net.IPNet
	DNS         net.IP
	Gateway     net.IP
	DisableIPV6 bool
}

type Mount struct {
	Device     string
	MountPoint string
	FSType     string
	Options    []string
}

type Chroot struct {
	Name       string      // Name identifier for the chroot
	RootPath   string      // Root directory path for the chroot (e.g., "/mnt/rootfs")
	BindMounts []BindMount // Bind mounts to set up within the chroot
}

type BindMount struct {
	Source      string   // Source path (outside the chroot)
	Destination string   // Destination path (relative to chroot root)
	FSType      string   // Filesystem type (e.g., "proc", "sysfs", "devtmpfs", "tmpfs", "none" for bind)
	Options     []string // Mount options (e.g., "nosuid", "nodev", "noexec")
	Flags       uintptr  // Mount flags (e.g., syscall.MS_BIND, syscall.MS_RDONLY)
}

type DiskFormat struct {
	Device string // Device to format (e.g., "/dev/vda")
	FSType string // Filesystem type (e.g., "ext4")
	Label  string // Optional filesystem label
}

type FSShare struct {
	HostPath      string
	MountTag      string
	MountPoint    string
	ReadOnly      bool
	SecurityModel string
}

type SSHServer struct {
	Enabled        bool
	Addr           string
	Port           int
	HostKey        []byte              // PEM-encoded private key (RSA, ECDSA, or Ed25519)
	AuthorizedKeys map[string][]string // username -> array of authorized public keys
	PasswordAuth   map[string]string   // username -> password
	Shell          string
	Env            []string
}

type DNSServer struct {
	Enabled  bool
	Addr     string
	Port     int
	Mappings []DNSMapping
}

type DNSMapping struct {
	Pattern string // Domain pattern (supports wildcards like *.google.com, *.com, or *)
	IP      net.IP // IP address to respond with for matching domains
}

type ResourceMonitor struct {
	Enabled      bool
	IntervalSecs int
	HTTPAddr     string
}
