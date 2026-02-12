package raftinit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Rudd3r/r0mp/pkg/dns"
	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/resourcemonitor"
	pkgssh "github.com/Rudd3r/r0mp/pkg/ssh"
	"golang.org/x/sync/errgroup"
)

type Init struct {
	cfg                 domain.InitConfig
	ctx                 context.Context
	log                 *slog.Logger
	mtx                 *sync.Mutex
	chrootStatus        map[string]bool
	processGroup        *errgroup.Group
	sshServer           *pkgssh.SSHServer
	dnsServer           *dns.Server
	resourceMonitor     *resourcemonitor.Monitor
	resourceMonitorHTTP *resourcemonitor.HTTPServer
}

func NewInit(ctx context.Context, log *slog.Logger) *Init {
	i := &Init{log: log, mtx: &sync.Mutex{}, chrootStatus: make(map[string]bool)}
	i.processGroup, i.ctx = errgroup.WithContext(ctx)
	return i
}

func (i *Init) loadConfig() error {
	data, err := os.ReadFile(domain.InitConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	err = json.Unmarshal(data, &i.cfg)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	return nil
}

func (i *Init) formatDisks() error {
	// Format each configured disk
	for _, d := range i.cfg.DiskFormats {
		i.log.Info("formatting disk", "device", d.Device, "fstype", d.FSType, "label", d.Label)
		if err := i.formatDisk(d); err != nil {
			return fmt.Errorf("failed to format %s: %w", d.Device, err)
		}
	}
	return nil
}

func (i *Init) formatDisk(d domain.DiskFormat) error {
	// Build mkfs command based on filesystem type
	var cmd *exec.Cmd
	switch d.FSType {
	case "ext4", "ext3", "ext2":
		args := []string{"-t", d.FSType}
		if d.Label != "" {
			args = append(args, "-L", d.Label)
		}
		args = append(args, d.Device)
		cmd = exec.CommandContext(i.ctx, "/bin/mke2fs", args...)
	default:
		return fmt.Errorf("unsupported filesystem type: %s", d.FSType)
	}

	i.log.Info("running mkfs command", "cmd", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs failed: %w (output: %s)", err, string(output))
	}

	i.log.Info("formatted disk", "device", d.Device, "output", string(output))
	return nil
}

func (i *Init) initializeMounts() error {
	// Mount each configured filesystem
	for _, m := range i.cfg.Mounts {
		i.log.Info("mounting filesystem", "device", m.Device, "mountpoint", m.MountPoint, "fstype", m.FSType)
		if err := i.mountFilesystem(m); err != nil {
			return fmt.Errorf("failed to mount %s: %w", m.Device, err)
		}
	}
	return nil
}

func (i *Init) mountFilesystem(m domain.Mount) error {
	// Create mount point if it doesn't exist
	if err := os.MkdirAll(m.MountPoint, 0755); err != nil {
		return fmt.Errorf("create mount point: %w", err)
	}

	// Build mount options
	options := uintptr(0)
	optionsStr := ""
	if len(m.Options) > 0 {
		optionsStr = strings.Join(m.Options, ",")
	}

	// Mount the filesystem using syscall.Mount
	if err := syscall.Mount(m.Device, m.MountPoint, m.FSType, options, optionsStr); err != nil {
		return fmt.Errorf("mount syscall: %w", err)
	}

	i.log.Info("mounted filesystem", "device", m.Device, "mountpoint", m.MountPoint)
	return nil
}

func (i *Init) initializeChroot(rootPath string) error {
	i.mtx.Lock()
	defer i.mtx.Unlock()

	if i.chrootStatus[rootPath] {
		return nil
	}

	// Set up each configured chroot
	for _, chroot := range i.cfg.Chroots {
		if chroot.RootPath != rootPath {
			continue
		}
		i.log.Info("initializing chroot", "name", chroot.Name, "rootpath", chroot.RootPath)
		if err := i.setupChroot(chroot); err != nil {
			return fmt.Errorf("failed to set up chroot %s: %w", chroot.Name, err)
		}
		i.chrootStatus[chroot.RootPath] = true
	}
	return nil
}

func (i *Init) setupChroot(chroot domain.Chroot) error {
	// Ensure the chroot root directory exists
	if err := os.MkdirAll(chroot.RootPath, 0755); err != nil {
		return fmt.Errorf("create chroot root directory: %w", err)
	}

	// Set up each bind mount
	for _, bind := range chroot.BindMounts {
		if err := i.setupBindMount(chroot.RootPath, bind); err != nil {
			return fmt.Errorf("failed to set up bind mount %s: %w", bind.Destination, err)
		}
	}

	if err := copyFile("/etc/hostname", filepath.Join(chroot.RootPath, "/etc/hostname")); err != nil {
		return fmt.Errorf("failed to copy /etc/hostname into chroot %s: %w", chroot.Name, err)
	}
	if err := copyFile("/etc/resolv.conf", filepath.Join(chroot.RootPath, "/etc/resolv.conf")); err != nil {
		return fmt.Errorf("failed to copy resolv.conf into chroot %s: %w", chroot.Name, err)
	}

	if err := i.installCACert(chroot.RootPath); err != nil {
		return fmt.Errorf("failed to install CA certificate into chroot %s: %w", chroot.Name, err)
	}

	i.log.Info("chroot initialized", "name", chroot.Name, "rootpath", chroot.RootPath, "bindmounts", len(chroot.BindMounts))
	return nil
}

func (i *Init) setupBindMount(chrootRoot string, bind domain.BindMount) error {
	// Build the full destination path
	destPath := filepath.Join(chrootRoot, bind.Destination)

	// Create the destination directory
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("create bind mount point: %w", err)
	}

	// Build mount options string
	optionsStr := ""
	if len(bind.Options) > 0 {
		optionsStr = strings.Join(bind.Options, ",")
	}

	i.log.Info("setting up bind mount",
		"source", bind.Source,
		"destination", destPath,
		"fstype", bind.FSType,
		"options", optionsStr,
		"flags", bind.Flags)

	// Mount the filesystem
	if err := syscall.Mount(bind.Source, destPath, bind.FSType, bind.Flags, optionsStr); err != nil {
		return fmt.Errorf("mount syscall: %w", err)
	}

	i.log.Info("bind mount created", "destination", destPath)
	return nil
}

func (i *Init) initializeNetwork() error {
	// Bring up loopback interface
	if err := i.configureInterface("lo", nil, nil, true); err != nil {
		return fmt.Errorf("failed to configure loopback interface: %w", err)
	}

	// Configure each network interface
	for _, n := range i.cfg.Networking {
		i.log.Info("initializing network", "device", n.Device, "ip", n.IP.String(), "gateway", n.Gateway.String())
		if err := i.configureInterface(n.Device, &n.IP, &n.Gateway, n.DisableIPV6); err != nil {
			return fmt.Errorf("failed to configure interface %s: %w", n.Device, err)
		}

		// Configure hostname if provided
		if n.Host != "" {
			if err := i.configureHostname(n.Host); err != nil {
				return fmt.Errorf("failed to configure hostname: %w", err)
			}
		}

		// Configure DNS if provided
		if !n.DNS.IsUnspecified() {
			if err := i.configureDNS(n.DNS); err != nil {
				return fmt.Errorf("failed to configure DNS: %w", err)
			}
		}
	}
	return nil
}

func (i *Init) configureInterface(device string, ipNet *net.IPNet, gateway *net.IP, disableIPV6 bool) error {
	_, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("get interface %s: %w", device, err)
	}

	// Bring interface up
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("create socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	// Set interface flags to UP
	var ifr struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}
	copy(ifr.Name[:], device)
	ifr.Flags = syscall.IFF_UP | syscall.IFF_RUNNING

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("set interface %s up: %w", device, errno)
	}

	i.log.Info("brought up interface", "device", device)

	// Configure IP address if provided
	if ipNet != nil {
		if err := i.addIPAddress(device, ipNet); err != nil {
			return fmt.Errorf("add IP address: %w", err)
		}
		i.log.Info("configured IP address", "device", device, "ip", ipNet.String())
	}

	// Add default gateway if provided
	if gateway != nil && !gateway.IsUnspecified() {
		if err := i.addDefaultRoute(*gateway); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
		i.log.Info("configured default gateway", "gateway", gateway.String())
	}

	// Disable IPv6 if requested
	if disableIPV6 {
		if err := i.disableIPv6(device); err != nil {
			i.log.Warn("failed to disable IPv6", "device", device, "error", err)
		} else {
			i.log.Info("disabled IPv6", "device", device)
		}
	}

	return nil
}

func (i *Init) addIPAddress(device string, ipNet *net.IPNet) error {
	// Use ip command to add address
	cmd := exec.CommandContext(i.ctx, "ip", "addr", "add", ipNet.String(), "dev", device)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr add: %w (output: %s)", err, string(output))
	}
	return nil
}

func (i *Init) addDefaultRoute(gateway net.IP) error {
	// Use ip command to add default route
	cmd := exec.CommandContext(i.ctx, "ip", "route", "add", "default", "via", gateway.String())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip route add: %w (output: %s)", err, string(output))
	}
	return nil
}

func (i *Init) disableIPv6(device string) error {
	// Write to sysctl to disable IPv6
	path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", device)
	if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
		return fmt.Errorf("write to %s: %w", path, err)
	}
	return nil
}

func (i *Init) configureHostname(hostname string) error {
	// Set the hostname using syscall
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}

	// Write to /etc/hostname for persistence
	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		i.log.Warn("failed to write /etc/hostname", "error", err)
	}

	// Update /etc/hosts with the hostname
	hostsEntry := fmt.Sprintf("127.0.1.1\t%s\n", hostname)
	hostsPath := "/etc/hosts"

	// Check if /etc/hosts exists and if hostname is already configured
	existingHosts, err := os.ReadFile(hostsPath)
	if err != nil && !os.IsNotExist(err) {
		i.log.Warn("failed to read /etc/hosts", "error", err)
	} else if !bytes.Contains(existingHosts, []byte(hostname)) {
		// Append the hostname entry
		f, err := os.OpenFile(hostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			i.log.Warn("failed to open /etc/hosts", "error", err)
		} else {
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString(hostsEntry); err != nil {
				i.log.Warn("failed to write to /etc/hosts", "error", err)
			}
		}
	}

	i.log.Info("configured hostname", "hostname", hostname)
	return nil
}

func (i *Init) configureDNS(dns net.IP) error {
	resolvConfPath := "/etc/resolv.conf"
	dnsEntry := fmt.Sprintf("nameserver %s\n", dns.String())
	dnsEntry = fmt.Sprintf("%soptions single-request timeout:1 attempts:2\n", dnsEntry)

	f, err := os.OpenFile(resolvConfPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open %s: %w", resolvConfPath, err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(dnsEntry); err != nil {
		return fmt.Errorf("write to %s: %w", resolvConfPath, err)
	}

	i.log.Info("configured DNS", "dns", dns.String())
	return nil
}

func (i *Init) startProcesses() {
	for _, process := range i.cfg.Processes {
		p := process // Capture loop variable
		i.processGroup.Go(func() error {
			return i.runProcess(p)
		})
	}
}

func (i *Init) runProcess(p domain.Process) error {
	i.log.Info("starting process", "path", p.Path, "args", p.Args, "dir", p.Dir, "uid", p.UID, "chroot", p.Chroot)
	defer func() {
		i.log.Info("process completed", "path", p.Path)
	}()

	cmd := exec.CommandContext(i.ctx, p.Path, p.Args...)
	cmd.Dir = p.Dir
	cmd.Env = p.Env

	// Set up SysProcAttr for chroot and/or UID
	if p.UID != 0 || p.Chroot != "" {
		cmd.SysProcAttr = &syscall.SysProcAttr{}

		// Set chroot if specified
		if p.Chroot != "" {
			if err := i.initializeChroot(p.Chroot); err != nil {
				i.log.Error("failed to initialize chroot", "error", err, "target", p.Chroot)
			}
			cmd.SysProcAttr.Chroot = p.Chroot
		}

		// Set UID if specified
		if p.UID != 0 {
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: uint32(p.UID),
			}
		}
	}

	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("create stderr pipe: %w", err)
	}

	eg, _ := errgroup.WithContext(i.ctx)
	eg.Go(func() error {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			i.log.Info("process output", "path", p.Path, "stream", "stdout", "line", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			// Log but don't return "file already closed" errors as they're expected
			// when the process exits before we finish reading
			i.log.Error("error reading stdout", "path", p.Path, "error", err)
		}
		return nil
	})
	eg.Go(func() error {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			i.log.Error("process output", "path", p.Path, "stream", "stderr", "line", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			// Log but don't return "file already closed" errors as they're expected
			// when the process exits before we finish reading
			i.log.Error("error reading stderr", "path", p.Path, "error", err)
		}
		return nil
	})

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	// Wait for pipe readers to finish first (they will finish when pipes close)
	_ = eg.Wait()

	// Then wait for the command to complete
	return cmd.Wait()
}

func (i *Init) initializeSSHServer() error {
	if i.cfg.SSHServer == nil || !i.cfg.SSHServer.Enabled {
		i.log.Info("SSH server not configured or disabled")
		return nil
	}

	i.log.Info("initializing SSH server", "addr", i.cfg.SSHServer.Addr, "port", i.cfg.SSHServer.Port)

	// Create SSH server from init config (handles all the boilerplate)
	var err error
	i.sshServer, err = pkgssh.NewSSHServerFromInit(i.ctx, i.log.With("component", "ssh"), i.cfg.SSHServer)
	if err != nil {
		return fmt.Errorf("failed to create SSH server: %w", err)
	}
	i.sshServer.RegisterEventCallback(func(e pkgssh.ServerEvent) {
		if e.Name == pkgssh.ServerEventFinalLayerWritten {
			if err := i.initializeChroot(e.Attributes["target"]); err != nil {
				i.log.Error("failed to initialize chroot", "error", err, "target", e.Attributes["target"])
			}
		}
	})
	i.sshServer.RegisterEventCallback(func(e pkgssh.ServerEvent) {
		if e.Name == pkgssh.ServerEventNewChrootSession {
			if err := i.initializeChroot(e.Attributes["target"]); err != nil {
				i.log.Error("failed to initialize chroot", "error", err, "target", e.Attributes["target"])
			}
		}
	})

	// Start SSH server in the process group
	i.processGroup.Go(func() error {
		i.log.Info("starting SSH server")
		if err := i.sshServer.Start(); err != nil {
			i.log.Error("SSH server error", "error", err)
			return fmt.Errorf("SSH server: %w", err)
		}
		return nil
	})

	return nil
}

func (i *Init) initializeDNSServer() error {
	if i.cfg.DNSServer == nil || !i.cfg.DNSServer.Enabled {
		i.log.Info("DNS server not configured or disabled")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", i.cfg.DNSServer.Addr, i.cfg.DNSServer.Port)
	i.log.Info("initializing DNS server", "addr", addr, "mappings", len(i.cfg.DNSServer.Mappings))

	i.dnsServer = dns.NewServer(i.ctx, i.log.With("component", "dns"), addr, i.cfg.DNSServer.Mappings)

	i.processGroup.Go(func() error {
		i.log.Info("starting DNS server")
		if err := i.dnsServer.Start(); err != nil {
			i.log.Error("DNS server error", "error", err)
			return fmt.Errorf("DNS server: %w", err)
		}
		return nil
	})

	return nil
}

func (i *Init) initializeResourceMonitor() error {
	if i.cfg.ResourceMonitor == nil || !i.cfg.ResourceMonitor.Enabled {
		i.log.Info("resource monitor not configured or disabled")
		return nil
	}

	interval := time.Duration(i.cfg.ResourceMonitor.IntervalSecs) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}

	httpAddr := ":8080"
	if i.cfg.ResourceMonitor.HTTPAddr != "" {
		httpAddr = i.cfg.ResourceMonitor.HTTPAddr
	}

	i.log.Info("initializing resource monitor", "interval", interval, "http_addr", httpAddr)

	i.resourceMonitor = resourcemonitor.NewMonitor(i.ctx, i.log.With("component", "resources"), interval)

	i.processGroup.Go(func() error {
		i.log.Info("starting resource monitor")
		if err := i.resourceMonitor.Start(); err != nil {
			if err == context.Canceled {
				return nil
			}
			i.log.Error("resource monitor error", "error", err)
			return fmt.Errorf("resource monitor: %w", err)
		}
		return nil
	})

	i.resourceMonitorHTTP = resourcemonitor.NewHTTPServer(i.ctx, i.log.With("component", "resources-http"), httpAddr, i.resourceMonitor)

	i.processGroup.Go(func() error {
		i.log.Info("starting resource monitor HTTP server")
		if err := i.resourceMonitorHTTP.Start(); err != nil {
			i.log.Error("resource monitor HTTP server error", "error", err)
			return fmt.Errorf("resource monitor HTTP: %w", err)
		}
		return nil
	})

	return nil
}

func (i *Init) installCACert(pathPrefix string) error {
	if len(i.cfg.CACert) == 0 {
		i.log.Info("no CA certificate configured")
		return nil
	}

	// Default paths if none specified
	paths := i.cfg.CACertPaths
	if len(paths) == 0 {
		paths = []string{"/etc/ssl/certs/ca-certificates.crt"}
	}

	var chrootPaths []string
	for _, chroot := range i.cfg.Chroots {
		for _, path := range paths {
			chrootPaths = append(chrootPaths, filepath.Join(chroot.RootPath, path))
		}
	}

	// Write the CA certificate to each configured path
	for _, caCertPath := range append(chrootPaths, paths...) {
		// Ensure the directory exists
		dir := filepath.Dir(caCertPath)
		dir = filepath.Join(pathPrefix, dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}

		// Write the CA certificate
		if err := os.WriteFile(caCertPath, i.cfg.CACert, 0644); err != nil {
			return fmt.Errorf("write CA certificate to %s: %w", caCertPath, err)
		}

		i.log.Info("installed CA certificate", "path", caCertPath, "size", len(i.cfg.CACert))
	}

	return nil
}

func (i *Init) Run() (err error) {
	defer func() {
		i.log.Info("init process shutting down", "err", err)
	}()
	if err := i.loadConfig(); err != nil {
		return err
	}
	if err := i.formatDisks(); err != nil {
		return err
	}
	if err := i.initializeMounts(); err != nil {
		return err
	}
	if err := i.installCACert(""); err != nil {
		return err
	}
	if err := i.initializeNetwork(); err != nil {
		return err
	}
	if err := i.initializeSSHServer(); err != nil {
		return err
	}
	if err := i.initializeDNSServer(); err != nil {
		return err
	}
	if err := i.initializeResourceMonitor(); err != nil {
		return err
	}
	i.startProcesses()
	return i.processGroup.Wait()
}

func copyFile(src, dst string) error {
	// Open source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer func() { _ = sourceFile.Close() }()

	// Create destination file
	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer func() { _ = destFile.Close() }()

	// Copy contents
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy: %w", err)
	}

	// Ensure all data is flushed to disk
	return destFile.Sync()
}
