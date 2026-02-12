package r0mp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/image"
	"github.com/Rudd3r/r0mp/pkg/mcp"
	sshpkg "github.com/Rudd3r/r0mp/pkg/ssh"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type RegistryClient interface {
	Pull(ref string) (v1.Image, error)
	ListImages() ([]*image.ImageMetadata, error)
	RemoveImage(ref string) error
	ImportFromTar(tarPath string, ref string) (v1.Image, error)
	ImportMultipleFromTar(tarPath string) (map[string]v1.Image, error)
}

type Cove struct {
	ctx      context.Context
	cfg      *domain.Config
	log      *slog.Logger
	registry RegistryClient
	image    v1.Image
	unlocker domain.SecretReadWriter
	policy   domain.PolicyBuilder
}

func NewCove(ctx context.Context, log *slog.Logger, cfg *domain.Config, registry RegistryClient, unlocker domain.SecretReadWriter, policy domain.PolicyBuilder) *Cove {
	return &Cove{
		ctx:      ctx,
		cfg:      cfg,
		log:      log,
		registry: registry,
		unlocker: unlocker,
		policy:   policy,
	}
}

func (s *Cove) Run(cmd *domain.CommandRun) (err error) {
	s.unlocker.Reset()
	var raft *domain.Raft
	if cmd.Name != "" {
		rafts, err := s.Get(&domain.CommandGet{Names: []string{cmd.Name}})
		if err == nil {
			raft = rafts[0]
			if err := raft.Unlock(s.unlocker); err != nil {
				return fmt.Errorf("cannot unlock raft: %w", err)
			}
			fmt.Printf("Loaded raft: %s\n", raft.Name)
		}
	}

	raft, err = s.createOrUpdate(cmd, raft)
	if err != nil {
		return fmt.Errorf("building raft: %w", err)
	}

	policy, err := s.policy.Get(raft.EgressProxyPolicyName)
	if err != nil {
		return fmt.Errorf("getting policy: %w", err)
	}

	policies := map[string]*domain.ProxyPolicy{
		raft.EgressProxyPolicyName: policy,
	}
	for _, port := range raft.IngressProxyPorts {
		p, err := s.policy.Get(port.PolicyName)
		if err != nil {
			return fmt.Errorf("getting policy: %w", err)
		}
		policies[port.PolicyName] = p
	}

	vm := &Raft{
		raftCfg:  raft,
		log:      s.log,
		image:    s.image,
		policies: policies,
		ctx:      s.ctx,
	}
	if err := vm.Build(); err != nil {
		return fmt.Errorf("building VM: %w", err)
	}
	return vm.Start()
}

func (s *Cove) createOrUpdate(cmd *domain.CommandRun, raft *domain.Raft) (*domain.Raft, error) {
	if raft == nil {
		raft = domain.NewRaft()
		if err := raft.Unlock(s.unlocker); err != nil {
			return nil, fmt.Errorf("cannot unlock raft: %w", err)
		}

		// These values can only be set on creation
		if cmd.Name != "" {
			raft.WithName(cmd.Name)
		}
		if cmd.Image != "" {
			var err error
			s.image, err = s.registry.Pull(cmd.Image)
			if err != nil {
				return nil, fmt.Errorf("pull image failed: %w", err)
			}
			imgCfg, err := s.image.ConfigFile()
			if err != nil {
				return nil, fmt.Errorf("failed to get image config: %w", err)
			}
			imgSize, err := s.image.Size()
			if err != nil {
				return nil, fmt.Errorf("failed to get image size: %w", err)
			}
			if cmd.VolumeSizeBytes == 0 {
				cmd.VolumeSizeBytes = imgSize + domain.DefaultVolumeSizeBytes
			}
			if imgSize >= cmd.VolumeSizeBytes {
				return nil, fmt.Errorf("disk size too small for image: %d >= %d", imgSize, cmd.VolumeSizeBytes)
			}
			imgCfg.Config.Image = cmd.Image
			raft.WithImage(imgCfg)
		}
		if cmd.VolumeSizeBytes == 0 {
			cmd.VolumeSizeBytes = domain.DefaultVolumeSizeBytes
		}
		raft.WithVolumeSizeBytes(cmd.VolumeSizeBytes)
		raft.WithProxyPolicy("default")

		fmt.Printf("created raft: %s\n", raft.Name)
	} else {

		// These values are immutable
		if cmd.VolumeSizeBytes != 0 {
			return nil, fmt.Errorf("volume size cannot be changed")
		}
		if cmd.Image != "" && cmd.Image != domain.DefaultImage {
			return nil, fmt.Errorf("image cannot be changed")
		}
	}

	if cmd.Policy != "" {
		raft.WithProxyPolicy(cmd.Policy)
	} else if raft.EgressProxyPolicyName == "" {
		raft.WithProxyPolicy("default")
	}

	// These values are mutable
	if cmd.CPU != 0 || raft.CPU == 0 {
		if cmd.CPU == 0 {
			cmd.CPU = domain.DefaultCpuCount
		}
		raft.WithCPU(cmd.CPU)
	}
	if cmd.Memory != "" || raft.Memory == "" {
		if cmd.Memory == "" {
			cmd.Memory = domain.DefaultMemorySize
		}
		raft.WithMemory(cmd.Memory)
	}

	// Port mappings can be set/updated on each run
	if len(cmd.Ports) > 0 {
		raft.Ports = slices.Clone(cmd.Ports)
	}

	// Ingress proxy ports can be set/updated on each run
	if len(cmd.IngressProxyPorts) > 0 {
		raft.IngressProxyPorts = slices.Clone(cmd.IngressProxyPorts)
	}

	if len(cmd.Environment) > 0 {
		for k, v := range cmd.Environment {
			raft.SetEnv(k, v)
		}
	}

	// These are refreshed on each run
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	if err = raft.WithSSHClientKey(privateKey); err != nil {
		return nil, fmt.Errorf("storing SSH client key on raft: %w", err)
	}

	hostPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	if err = raft.WithSSHHostKey(hostPrivateKey); err != nil {
		return nil, fmt.Errorf("storing SSH host key on raft: %w", err)
	}

	// Process volume mounts
	if len(cmd.Volumes) > 0 {
		fsShares, err := parseVolumes(cmd.Volumes, raft.Image != "")
		if err != nil {
			return nil, fmt.Errorf("parsing volumes: %w", err)
		}
		raft.FSShares = fsShares
	}

	if err = raft.CreateRaftDirectory(s.cfg.DataDir); err != nil {
		return nil, fmt.Errorf("could not create raft directory: %w", err)
	}

	return raft, nil
}

// parseVolumes parses volume mount specifications and converts them to FSShares.
// Format: HOST_PATH:GUEST_PATH[:ro]
// If hasChroot is true, prepends /mnt/rootfs to guest paths, otherwise uses / as root.
func parseVolumes(volumes []string, hasChroot bool) ([]domain.FSShare, error) {
	var fsShares []domain.FSShare

	for i, vol := range volumes {
		parts := strings.Split(vol, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("invalid volume format: %s (expected HOST_PATH:GUEST_PATH[:ro])", vol)
		}

		hostPath := parts[0]
		guestPath := parts[1]
		readOnly := false

		if len(parts) == 3 {
			if parts[2] != "ro" {
				return nil, fmt.Errorf("invalid volume option: %s (only 'ro' is supported)", parts[2])
			}
			readOnly = true
		}

		// Validate paths
		if !filepath.IsAbs(hostPath) {
			return nil, fmt.Errorf("host path must be absolute: %s", hostPath)
		}
		if !filepath.IsAbs(guestPath) {
			return nil, fmt.Errorf("guest path must be absolute: %s", guestPath)
		}

		// Check if host path exists and is a directory
		info, err := os.Stat(hostPath)
		if err != nil {
			return nil, fmt.Errorf("host path does not exist: %s", hostPath)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("host path must be a directory: %s", hostPath)
		}

		// Adjust guest path based on chroot
		mountPoint := guestPath
		if hasChroot {
			// If we have a chroot, prepend /mnt/rootfs
			mountPoint = filepath.Join("/mnt/rootfs", guestPath)
		}

		// Generate a unique mount tag
		mountTag := fmt.Sprintf("vol%d", i)

		fsShares = append(fsShares, domain.FSShare{
			HostPath:      hostPath,
			MountTag:      mountTag,
			MountPoint:    mountPoint,
			ReadOnly:      readOnly,
			SecurityModel: "mapped-xattr",
		})
	}

	return fsShares, nil
}

// shellEscape escapes a string for safe use in a shell command.
// It wraps the string in single quotes and escapes any single quotes within it.
func shellEscape(arg string) string {
	// Replace each single quote with '\'' (end quote, escaped quote, start quote)
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

func shellEscCommand(command string, args []string) string {
	escapedArgs := make([]string, 0, len(args)+1)
	escapedArgs = append(escapedArgs, shellEscape(command))
	for _, arg := range args {
		escapedArgs = append(escapedArgs, shellEscape(arg))
	}
	return strings.Join(escapedArgs, " ")
}

func (s *Cove) Exec(cmd *domain.CommandExec) error {
	rafts, err := s.Get(&domain.CommandGet{Names: []string{cmd.Name}})
	if err != nil {
		return err
	}

	state, err := rafts[0].QueryState()
	if err != nil {
		return err
	}

	if state != domain.RaftStateRunning {
		return fmt.Errorf("raft is not running")
	}

	clientSSHKey, err := rafts[0].GetSSHClientKey()
	if err != nil {
		return fmt.Errorf("getting ssh client key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(clientSSHKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key, %w", err)
	}

	hostSSHKey, err := rafts[0].GetSSHHostKey()
	if err != nil {
		return fmt.Errorf("getting ssh host key: %w", err)
	}

	hostKey, err := ssh.NewSignerFromKey(hostSSHKey)
	if err != nil {
		return fmt.Errorf("could not parse server ssh public key: %w", err)
	}

	defer func() {
		_ = os.Stderr.Sync()
		_ = os.Stdout.Sync()
	}()

	env := rafts[0].GetEnvironment()
	if rafts[0].Image != "" && !cmd.NoChroot {
		env[sshpkg.EnvRaftChroot] = "/mnt/rootfs"
		env[sshpkg.EnvRaftUser] = rafts[0].User
	}
	for k, v := range cmd.Environment {
		env[k] = v
	}

	s.log.Debug("Executing", "command", shellEscape(cmd.Command))

	return sshpkg.Client(s.ctx, s.log, &domain.SSHClientConfig{
		User:            domain.SSHManagementUser,
		Host:            "127.0.0.1",
		Port:            int(rafts[0].SSHServerPort.HostPort),
		EnableTTY:       cmd.EnableTTY,
		Interactive:     cmd.Interactive,
		Detach:          cmd.Detach,
		EnvironmentVars: env,
		Command:         shellEscCommand(cmd.Command, cmd.Args),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Stderr:          os.Stderr,
		Stdout:          os.Stdout,
		Stdin:           os.Stdin,
	})
}

func (s *Cove) Get(cmd *domain.CommandGet) (rafts []*domain.Raft, err error) {
	if len(cmd.Names) == 0 {
		return rafts, nil
	}
	cmd.Names = slices.Compact(cmd.Names)
	if err = domain.EnsureDir(s.cfg.DataDir); err != nil {
		return nil, fmt.Errorf("getting user data dir: %w", err)
	}
	raftIDs, err := filepath.Glob(s.cfg.DataDir + "/*")
	if err != nil {
		return nil, err
	}
	for _, raftID := range raftIDs {
		raftID = filepath.Base(raftID)
		raft, err := domain.OpenRaft(filepath.Join(s.cfg.DataDir, raftID, "raft.json"))
		if err != nil {
			return nil, fmt.Errorf("opening raft raft: %w", err)
		}
		if !slices.ContainsFunc(cmd.Names, func(s string) bool { return raft.Name == s || raft.RaftID == s }) {
			continue
		}
		if err = raft.Unlock(s.unlocker); err != nil {
			return nil, fmt.Errorf("unlocking raft: %w", err)
		}
		_, err = raft.QueryState()
		if err != nil {
			return nil, fmt.Errorf("querying raft %s: %w", raftID, err)
		}
		cmd.Names = slices.DeleteFunc(cmd.Names, func(s string) bool { return raft.Name == s || raft.RaftID == s })
		cmd.Names = slices.Compact(cmd.Names)
		rafts = append(rafts, raft)
	}
	if len(cmd.Names) > 0 {
		for _, name := range cmd.Names {
			err = errors.Join(err, fmt.Errorf("could not find raft %q", name))
		}
		return nil, err
	}
	return rafts, nil
}

func (s *Cove) List(_ *domain.CommandList) (rafts []*domain.Raft, err error) {
	if err = domain.EnsureDir(s.cfg.DataDir); err != nil {
		return nil, fmt.Errorf("getting user data dir: %w", err)
	}
	raftIDs, err := filepath.Glob(s.cfg.DataDir + "/*")
	if err != nil {
		return nil, err
	}
	for i, raftID := range raftIDs {
		raftIDs[i] = filepath.Base(raftID)
	}
	return s.Get(&domain.CommandGet{Names: raftIDs})
}

func (s *Cove) MCP(cmd *domain.CommandMCP) (err error) {

	if len(cmd.Names) == 0 {
		return fmt.Errorf("must specify at least one raft")
	}

	rafts, err := s.List(nil)
	if err != nil {
		return fmt.Errorf("listing rafts: %w", err)
	}

	// Verify all specified rafts exist and are running
	allowedRafts := make(map[string]*domain.Raft)
	for _, name := range cmd.Names {
		i := slices.IndexFunc(rafts, func(raft *domain.Raft) bool {
			return raft.Name == name
		})
		if i < 0 {
			return fmt.Errorf("could not find raft %q", name)
		}
		if rafts[i].State != domain.RaftStateRunning {
			return fmt.Errorf("raft %q is not running", name)
		}
		allowedRafts[name] = rafts[i]
	}

	return (&mcp.Server{
		Names:        cmd.Names,
		Host:         cmd.Host,
		Port:         cmd.Port,
		StdIO:        cmd.StdIO,
		AllowedRafts: allowedRafts,
		Log:          s.log,
		CTX:          s.ctx,
	}).Start()
}

func (s *Cove) Remove(cmd *domain.CommandRemove) error {
	if err := domain.EnsureDir(s.cfg.DataDir); err != nil {
		return fmt.Errorf("getting user data dir: %w", err)
	}
	rafts, err := s.Get(&domain.CommandGet{Names: cmd.Names})
	if err != nil {
		return err
	}
	for _, raft := range rafts {
		if raft.State == domain.RaftStateStarting || raft.State == domain.RaftStateRunning {
			return fmt.Errorf("raft %q is running and must be stopped before removing", raft.Name)
		}
		err = os.RemoveAll(filepath.Join(s.cfg.DataDir, raft.RaftID))
		if err != nil {
			return fmt.Errorf("removing raft %s: %w", raft.RaftID, err)
		}
		fmt.Printf("raft %s removed\n", raft.RaftID)
	}
	return nil
}

func (s *Cove) ImagesList(_ *domain.CommandImagesList) ([]*image.ImageMetadata, error) {
	images, err := s.registry.ListImages()
	if err != nil {
		return nil, fmt.Errorf("listing images: %w", err)
	}
	return images, nil
}

func (s *Cove) ImagesRemove(cmd *domain.CommandImagesRemove) error {
	for _, ref := range cmd.References {
		err := s.registry.RemoveImage(ref)
		if err != nil {
			return fmt.Errorf("removing image %s: %w", ref, err)
		}
		fmt.Printf("image %s removed\n", ref)
	}
	return nil
}

func (s *Cove) ImagesImport(cmd *domain.CommandImagesImport) error {
	if cmd.All {
		// Import all images from the tar file
		images, err := s.registry.ImportMultipleFromTar(cmd.TarPath)
		if err != nil {
			return fmt.Errorf("importing images from tar: %w", err)
		}
		for ref := range images {
			fmt.Printf("imported image: %s\n", ref)
		}
		fmt.Printf("successfully imported %d image(s)\n", len(images))
	} else {
		// Import single image with specified reference
		if cmd.Reference == "" {
			return fmt.Errorf("reference must be specified when --all is not used")
		}
		_, err := s.registry.ImportFromTar(cmd.TarPath, cmd.Reference)
		if err != nil {
			return fmt.Errorf("importing image from tar: %w", err)
		}
		fmt.Printf("imported image: %s\n", cmd.Reference)
	}
	return nil
}

func (s *Cove) Stop(cmd *domain.CommandStop) error {
	rafts, err := s.Get(&domain.CommandGet{Names: cmd.Names})
	if err != nil {
		return err
	}
	for _, raft := range rafts {
		if raft.State != domain.RaftStateRunning {
			return fmt.Errorf("raft %q is not running (state: %s)", raft.Name, raft.State)
		}

		if raft.QemuPID == 0 {
			return fmt.Errorf("raft %q has no raft PID", raft.Name)
		}
		if raft.RaftPID == 0 {
			return fmt.Errorf("raft %q has no raft PID", raft.Name)
		}

		raftProcess, err := os.FindProcess(raft.RaftPID)
		if err != nil {
			return fmt.Errorf("finding process %d for raft %q: %w", raft.QemuPID, raft.Name, err)
		}
		if err := raftProcess.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("sending SIGTERM to raft %q (PID %d): %w", raft.Name, raft.RaftPID, err)
		}
		fmt.Printf("sent SIGTERM to raft %s (PID %d)\n", raft.Name, raft.RaftPID)

		qemuProcess, err := os.FindProcess(raft.QemuPID)
		if err != nil {
			continue
		}
		if err := qemuProcess.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("sending SIGTERM to raft qemu %q (PID %d): %w", raft.Name, raft.QemuPID, err)
		}
	}
	return nil
}

func (s *Cove) Kill(cmd *domain.CommandKill) error {
	rafts, err := s.Get(&domain.CommandGet{Names: cmd.Names})
	if err != nil {
		return err
	}
	for _, raft := range rafts {
		if raft.State != domain.RaftStateRunning {
			return fmt.Errorf("raft %q is not running (state: %s)", raft.Name, raft.State)
		}

		if raft.QemuPID == 0 {
			return fmt.Errorf("raft %q has no qemu PID", raft.Name)
		}
		if raft.RaftPID == 0 {
			return fmt.Errorf("raft %q has no raft PID", raft.Name)
		}

		qemuProcess, err := os.FindProcess(raft.QemuPID)
		if err != nil {
			return fmt.Errorf("finding qemu process %d for raft %q: %w", raft.QemuPID, raft.Name, err)
		}
		if err := qemuProcess.Signal(syscall.SIGKILL); err != nil {
			return fmt.Errorf("sending SIGKILL to raft qemu %q (PID %d): %w", raft.Name, raft.QemuPID, err)
		}

		process, err := os.FindProcess(raft.RaftPID)
		if err != nil {
			continue
		}
		if err := process.Signal(syscall.SIGKILL); err != nil {
			return fmt.Errorf("sending SIGKILL to raft %q (PID %d): %w", raft.Name, raft.RaftPID, err)
		}
		fmt.Printf("sent SIGKILL to raft %s (PID %d)\n", raft.Name, raft.RaftPID)
	}
	return nil
}

func (s *Cove) Copy(cmd *domain.CommandCopy) error {
	raftName, remotePath, localPath, fromRaft, err := s.parseCopyPaths(cmd.Source, cmd.Destination)
	if err != nil {
		return err
	}

	rafts, err := s.Get(&domain.CommandGet{Names: []string{raftName}})
	if err != nil {
		return err
	}

	if rafts[0].State != domain.RaftStateRunning {
		return fmt.Errorf("raft is not running")
	}

	clientSSHKey, err := rafts[0].GetSSHClientKey()
	if err != nil {
		return fmt.Errorf("getting ssh client key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(clientSSHKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key, %w", err)
	}

	hostSSHKey, err := rafts[0].GetSSHHostKey()
	if err != nil {
		return fmt.Errorf("getting ssh host key: %w", err)
	}

	hostKey, err := ssh.NewSignerFromKey(hostSSHKey)
	if err != nil {
		return fmt.Errorf("could not parse server ssh public key: %w", err)
	}

	// Prepend chroot path if raft has an image and chroot is not disabled
	if rafts[0].Image != "" && !cmd.NoChroot {
		remotePath = filepath.Join("/mnt/rootfs", remotePath)
	}

	return s.copyViaSFTP(rafts[0], localPath, remotePath, fromRaft, signer, hostKey)
}

func (s *Cove) parseCopyPaths(source, destination string) (raftName, remotePath, localPath string, fromRaft bool, err error) {
	sourceParts := strings.SplitN(source, ":", 2)
	destParts := strings.SplitN(destination, ":", 2)

	sourceIsRemote := len(sourceParts) == 2
	destIsRemote := len(destParts) == 2

	if sourceIsRemote && destIsRemote {
		return "", "", "", false, fmt.Errorf("both source and destination cannot be remote paths")
	}

	if !sourceIsRemote && !destIsRemote {
		return "", "", "", false, fmt.Errorf("either source or destination must be a remote path (use SANDBOX:PATH)")
	}

	if sourceIsRemote {
		return sourceParts[0], sourceParts[1], destination, true, nil
	}

	return destParts[0], destParts[1], source, false, nil
}

func (s *Cove) copyViaSFTP(raft *domain.Raft, localPath, remotePath string, fromRaft bool, signer ssh.Signer, hostKey ssh.Signer) error {
	config := &ssh.ClientConfig{
		User: domain.SSHManagementUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	}

	addr := fmt.Sprintf("127.0.0.1:%d", raft.SSHServerPort.HostPort)
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if fromRaft {
		return s.copyFromRemote(client, remotePath, localPath)
	}

	localInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("failed to stat local source: %w", err)
	}

	return s.copyToRemote(client, localPath, remotePath, localInfo)
}

func (s *Cove) copyToRemote(client *sftp.Client, source, destination string, sourceInfo os.FileInfo) error {
	if sourceInfo.IsDir() {
		return s.copyDirToRemote(client, source, destination)
	}
	return s.copyFileToRemote(client, source, destination)
}

func (s *Cove) copyFileToRemote(client *sftp.Client, source, destination string) error {
	srcFile, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	destInfo, err := client.Stat(destination)
	if err == nil && destInfo.IsDir() {
		destination = filepath.Join(destination, filepath.Base(source))
	}

	dstFile, err := client.Create(destination)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	fmt.Printf("Copied %s to %s\n", source, destination)
	return nil
}

func (s *Cove) copyDirToRemote(client *sftp.Client, source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}

		remotePath := filepath.Join(destination, relPath)

		if info.IsDir() {
			if err := client.MkdirAll(remotePath); err != nil {
				return fmt.Errorf("failed to create remote directory %s: %w", remotePath, err)
			}
			return nil
		}

		return s.copyFileToRemote(client, path, remotePath)
	})
}

func (s *Cove) copyFromRemote(client *sftp.Client, source, destination string) error {
	sourceInfo, err := client.Stat(source)
	if err != nil {
		return fmt.Errorf("failed to stat remote source: %w", err)
	}

	if sourceInfo.IsDir() {
		return s.copyDirFromRemote(client, source, destination)
	}
	return s.copyFileFromRemote(client, source, destination)
}

func (s *Cove) copyFileFromRemote(client *sftp.Client, source, destination string) error {
	srcFile, err := client.Open(source)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	destInfo, err := os.Stat(destination)
	if err == nil && destInfo.IsDir() {
		destination = filepath.Join(destination, filepath.Base(source))
	}

	dstFile, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	fmt.Printf("Copied %s to %s\n", source, destination)
	return nil
}

func (s *Cove) copyDirFromRemote(client *sftp.Client, source, destination string) error {
	walker := client.Walk(source)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		path := walker.Path()
		info := walker.Stat()

		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}

		localPath := filepath.Join(destination, relPath)

		if info.IsDir() {
			if err := os.MkdirAll(localPath, 0755); err != nil {
				return fmt.Errorf("failed to create local directory %s: %w", localPath, err)
			}
			continue
		}

		if err := s.copyFileFromRemote(client, path, localPath); err != nil {
			return err
		}
	}
	return nil
}
