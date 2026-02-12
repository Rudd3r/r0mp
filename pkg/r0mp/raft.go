package r0mp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/Rudd3r/r0mp/pkg/assets"
	"github.com/Rudd3r/r0mp/pkg/disk"
	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/proxy"
	"github.com/Rudd3r/r0mp/pkg/qemu"
	"github.com/Rudd3r/r0mp/pkg/raftinit"
	sshpkg "github.com/Rudd3r/r0mp/pkg/ssh"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

var (
	certPaths = []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/usr/local/share/ca-certificates/proxy.crt",
	}
)

type Raft struct {
	raftCfg   *domain.Raft
	log       *slog.Logger
	image     v1.Image
	policies  map[string]*domain.ProxyPolicy
	CertPEM   []byte
	KeyPEM    []byte
	signer    ssh.Signer
	ctx       context.Context
	sshClient *ssh.Client
	hostKey   ssh.PublicKey
}

func (s *Raft) Build() (err error) {

	clientSSHKey, err := s.raftCfg.GetSSHClientKey()
	if err != nil {
		return fmt.Errorf("failed to retrieve client key, %w", err)
	}
	s.signer, err = ssh.NewSignerFromKey(clientSSHKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key, %w", err)
	}

	if err = s.raftCfg.Save(); err != nil {
		return fmt.Errorf("could not save raft: %w", err)
	}
	if err = s.generateCA(); err != nil {
		return fmt.Errorf("could not create proxy: %w", err)
	}
	if err = s.ensureDisk(); err != nil {
		return fmt.Errorf("could not ensure disk: %w", err)
	}
	if err = s.ensureKernel(); err != nil {
		return fmt.Errorf("could not ensure kernel: %w", err)
	}
	if err = s.buildInit(); err != nil {
		return fmt.Errorf("could not build init: %w", err)
	}

	hostSSHKey, err := s.raftCfg.GetSSHHostKey()
	if err != nil {
		return fmt.Errorf("getting ssh host key: %w", err)
	}
	hostKey, err := ssh.NewSignerFromKey(hostSSHKey)
	if err != nil {
		return fmt.Errorf("could not parse server ssh public key: %w", err)
	}
	s.hostKey = hostKey.PublicKey()

	s.raftCfg.State = domain.RaftStateReady
	if err = s.raftCfg.Save(); err != nil {
		return fmt.Errorf("could not save raft: %w", err)
	}
	return nil
}

func (s *Raft) generateCA() error {
	cfg := &domain.ProxyConfig{
		Expire: time.Until(time.Now().AddDate(0, 0, 7)),
	}
	_, err := proxy.NewCertificateAuthority(s.log, cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy CA: %w", err)
	}
	s.CertPEM = slices.Clone(cfg.CertPEM)
	s.KeyPEM = slices.Clone(cfg.KeyPEM)
	return nil
}

func (s *Raft) ensureKernel() error {
	if f, err := os.Stat(s.raftCfg.KernelPath); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil && f.Mode().IsRegular() {
		return nil
	}
	kernelFile, err := os.Create(s.raftCfg.KernelPath)
	if err != nil {
		return err
	}
	defer func() { _ = kernelFile.Close() }()
	if _, err = io.Copy(kernelFile, assets.Kernel()); err != nil {
		return err
	}
	return nil
}

func (s *Raft) ensureDisk() error {
	if s.raftCfg.State != domain.RaftStateCreated {
		return nil
	}
	if err := disk.CreateSparse(s.raftCfg.DiskImagePath, s.raftCfg.VolumeSizeBytes); err != nil {
		return fmt.Errorf("could not create sparse disk, %w", err)
	}
	return nil
}

func (s *Raft) buildInit() error {
	initFile, err := os.OpenFile(s.raftCfg.InitPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("could not create init file, %w", err)
	}
	defer func() { _ = initFile.Close() }()

	initBuilder, err := raftinit.NewInitFS(assets.Initrd(), initFile)
	if err != nil {
		return fmt.Errorf("could not open init file, %w", err)
	}

	initBuilder.SetCACert(bytes.Clone(s.CertPEM))
	s.raftCfg.WithProxyCert(bytes.Clone(s.CertPEM))
	initBuilder.SetCACertPaths(certPaths)
	initBuilder.AddDNSConfig(domain.DNSServer{
		Enabled: true,
		Addr:    "0.0.0.0",
		Port:    53,
		Mappings: []domain.DNSMapping{
			{
				Pattern: "*",
				IP:      net.IPv4(127, 0, 0, 2)},
		},
	})

	if err = initBuilder.WriteFile(domain.FileInfo{FName: domain.InitFSBinPath, FMode: 0500, Uid: 0, Gid: 0}, assets.RaftInit()); err != nil {
		return fmt.Errorf("could not add init binary, %w", err)
	}
	if err = initBuilder.WriteFile(domain.FileInfo{FName: "/bin/e2fsck", FMode: 0500, Uid: 0, Gid: 0}, assets.E2fsck()); err != nil {
		return fmt.Errorf("could not add e2fsck binary, %w", err)
	}
	if err = initBuilder.WriteFile(domain.FileInfo{FName: "/bin/mke2fs", FMode: 0500, Uid: 0, Gid: 0}, assets.Mke2fs()); err != nil {
		return fmt.Errorf("could not add mke2fs binary, %w", err)
	}

	if s.raftCfg.State == domain.RaftStateCreated {
		initBuilder.AddDiskFormat(domain.DiskFormat{
			Device: "/dev/vda",
			FSType: "ext4",
			Label:  "rootfs",
		})
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("could not get free tcp port for ssh: %w", err)
	}
	s.raftCfg.WithSSHPort(uint64(listener.Addr().(*net.TCPAddr).Port))

	hostSSHKey, err := s.raftCfg.GetSSHHostKey()
	if err != nil {
		return fmt.Errorf("getting ssh host key: %w", err)
	}
	sshConfig := &domain.SSHServer{
		Enabled: true,
		Addr:    "0.0.0.0",
		Port:    domain.SSHServerGuestPort,
		AuthorizedKeys: map[string][]string{
			domain.SSHManagementUser: {string(ssh.MarshalAuthorizedKey(s.signer.PublicKey()))},
		},
		HostKey: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(hostSSHKey),
		}),
		Shell: "/bin/sh",
		Env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/root",
		},
	}
	initBuilder.ConfigureSSHServer(sshConfig)

	initBuilder.AddMount(domain.Mount{
		Device:     "/dev/vda",
		MountPoint: "/mnt/rootfs",
		FSType:     "ext4",
		Options:    []string{},
	})

	initBuilder.AddNetworkInterface(domain.NetworkInterface{
		Device: "eth0",
		Host:   s.raftCfg.Name,
		IP: net.IPNet{
			IP:   net.ParseIP(domain.GuestPrivateIP),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		DNS:         net.IPv4(127, 0, 0, 1),
		Gateway:     net.IPv4(10, 0, 2, 2),
		DisableIPV6: true,
	})

	if s.raftCfg.Image != "" {
		initBuilder.AddChroot(raftinit.NewStandardChroot(s.raftCfg.Image, "/mnt/rootfs"))
	}

	// Add FSShares for volume mounts
	for _, share := range s.raftCfg.FSShares {
		initBuilder.AddFSShare(share)
	}

	if err = initBuilder.Close(); err != nil {
		return fmt.Errorf("could not close builder, %w", err)
	}

	return nil
}

func (s *Raft) Start() error {

	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return fmt.Errorf("could not find qemu-system-x86_64, %w", err)
	}
	s.raftCfg.QemuPath = qemuPath

	config := domain.QemuConfig{
		Raft:   s.raftCfg,
		Stderr: &buff{out: os.Stderr},
	}
	vm, err := qemu.NewQEMU(s.ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create QEMU instance, %w", err)
	}
	vmErrChan := make(chan error, 1)
	go func() {
		vmErrChan <- vm.Run()
	}()
	s.raftCfg.State = domain.RaftStateStarting
	if err = s.raftCfg.Save(); err != nil {
		return fmt.Errorf("could not save raft: %w", err)
	}
	defer func() {
		s.raftCfg.Stopped = time.Now()
		s.raftCfg.State = domain.RaftStateStopped
		_ = s.raftCfg.Save()
	}()

	if err = s.waitForSSH(); err != nil {
		return fmt.Errorf("failed to connect to SSH, %w", err)
	}
	if err = s.writeImage(); err != nil {
		return fmt.Errorf("failed to write image, %w", err)
	}
	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- s.startEgressProxy()
	}()
	ingressProxyErrChan := make(chan error, 1)
	if len(s.raftCfg.IngressProxyPorts) > 0 {
		go func() {
			ingressProxyErrChan <- s.startIngresProxy()
		}()
	}

	s.raftCfg.Started = time.Now()
	s.raftCfg.State = domain.RaftStateRunning
	s.raftCfg.QemuPID = vm.PID()
	if err = s.raftCfg.Save(); err != nil {
		return fmt.Errorf("could not save raft: %w", err)
	}

	fmt.Printf(
		"\n"+
			"░█▀▄░█▀█░█▀▀░▀█▀░░░█▀▄░█▀▀░█▀█░█▀▄░█░█\n"+
			"░█▀▄░█▀█░█▀▀░░█░░░░█▀▄░█▀▀░█▀█░█░█░░█░\n"+
			"░▀░▀░▀░▀░▀░░░░▀░░░░▀░▀░▀▀▀░▀░▀░▀▀░░░▀░\n"+
			"\n"+
			"Name: %s\n"+
			"RaftID: %s\n"+
			"Raft PID: %d\n"+
			"Qemu PID: %d\n"+
			"\n",
		s.raftCfg.Name, s.raftCfg.RaftID, s.raftCfg.RaftPID, s.raftCfg.QemuPID,
	)

	select {
	case err = <-vmErrChan:
		if err != nil && s.ctx.Err() == nil {
			return err
		}
	case err = <-proxyErrChan:
		if err != nil && s.ctx.Err() == nil {
			return err
		}
	case err = <-ingressProxyErrChan:
		if err != nil && s.ctx.Err() == nil {
			return err
		}
	case <-s.ctx.Done():
	}

	return nil
}

func (s *Raft) startEgressProxy() error {
	egressProxy, err := proxy.NewServer(s.ctx, s.log, &domain.ProxyConfig{
		CertPEM: bytes.Clone(s.CertPEM),
		KeyPEM:  bytes.Clone(s.KeyPEM),
		Policy:  s.policies[s.raftCfg.EgressProxyPolicyName],
		Expire:  time.Hour * 24 * 365,
	})
	if err != nil {
		return fmt.Errorf("could not create egress proxy server, %w", err)
	}
	httpListener, err := s.sshClient.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: 80,
	})
	if err != nil {
		return fmt.Errorf("could not create ssh http listener, %w", err)
	}
	defer func() { _ = httpListener.Close() }()
	httpsListener, err := s.sshClient.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: 443,
	})
	if err != nil {
		return fmt.Errorf("could not create ssh https listener, %w", err)
	}
	defer func() { _ = httpsListener.Close() }()

	return egressProxy.Serve([]net.Listener{httpListener}, []net.Listener{httpsListener})
}

func (s *Raft) startIngresProxy() error {
	eg, _ := errgroup.WithContext(s.ctx)
	for _, port := range s.raftCfg.IngressProxyPorts {
		port := port
		eg.Go(func() error {
			ingressProxy, err := proxy.NewServer(s.ctx, s.log, &domain.ProxyConfig{
				CertPEM: bytes.Clone(s.CertPEM),
				KeyPEM:  bytes.Clone(s.KeyPEM),
				Policy:  s.policies[port.PolicyName],
				Expire:  time.Hour * 24 * 365,
			})
			if err != nil {
				return fmt.Errorf("could not create ingress proxy server host=%s, port=%d, %w", port.HostIP, port.HostPort, err)
			}
			transport := proxy.DefaultTransport()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.sshClient.DialContext(
					ctx,
					"tcp",
					net.JoinHostPort("127.0.0.1", strconv.FormatUint(port.GuestPort, 10)),
				)
			}
			ingressProxy.SetTransport(transport)

			listener, err := net.Listen("tcp", net.JoinHostPort(port.HostIP, strconv.FormatUint(port.HostPort, 10)))
			if err != nil {
				return fmt.Errorf("could not create ingress proxy listener host=%s, port=%d, %w", port.HostIP, port.HostPort, err)
			}

			switch port.Scheme {
			case "http", "":
				return ingressProxy.Serve([]net.Listener{listener}, nil)
			case "https":
				return ingressProxy.Serve(nil, []net.Listener{listener})
			default:
				return fmt.Errorf("unsupported scheme: %s", port.Scheme)
			}
		})
	}
	return eg.Wait()
}

func (s *Raft) writeImage() error {
	if s.image == nil {
		return nil
	}

	layers, err := s.image.Layers()
	if err != nil {
		return fmt.Errorf("could not get image layers, %w", err)
	}

	layerClient := sshpkg.NewLayerClient(s.sshClient, slog.Default())
	for i, layer := range layers {
		digest, _ := layer.Digest()
		size, _ := layer.Size()
		s.log.Info("streaming layer", "index", i+1, "total", len(layers), "digest", digest.String()[:16]+"...")
		err = func() error {
			reader, err := layer.Compressed()
			if err != nil {
				return fmt.Errorf("failed to get layer reader, %w", err)
			}
			defer func() { _ = reader.Close() }()

			if err := layerClient.WriteLayer("/mnt/rootfs", digest.String(), reader, size, i+1 == len(layers)); err != nil {
				return fmt.Errorf("failed to write layer, %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
		s.log.Info("wrote layer", "index", i+1, "total", len(layers), "digest", digest.String())
	}
	return nil
}

func (s *Raft) waitForSSH() error {
	config := &ssh.ClientConfig{
		User: domain.SSHManagementUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.signer),
		},
		HostKeyCallback: ssh.FixedHostKey(s.hostKey),
		Timeout:         2 * time.Second,
	}

	deadline := time.Now().Add(60 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for SSH")
			}
			var err error
			s.sshClient, err = ssh.Dial("tcp", fmt.Sprintf("localhost:%d", s.raftCfg.SSHServerPort.HostPort), config)
			if err == nil {
				return nil
			}
		}
	}
}

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

type buff struct {
	out io.Writer
}

func (b *buff) Write(p []byte) (n int, err error) {
	n, err = b.out.Write(ansiEscape.ReplaceAllFunc(p, func(i []byte) []byte {
		if bytes.Equal(i, []byte("\n")) {
			return i
		}
		return nil
	}))
	return n, err
}
