package qemu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"golang.org/x/sync/errgroup"
)

type QEMU struct {
	cfg        domain.QemuConfig
	cmd        *exec.Cmd
	ctx        context.Context
	eg         *errgroup.Group
	outMtx     *sync.Mutex
	serialLog  *os.File
	processLog *os.File
}

func NewQEMU(ctx context.Context, cfg domain.QemuConfig) (qemu *QEMU, err error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	eg, ctx := errgroup.WithContext(ctx)
	if err := cfg.Valid(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	qemu = &QEMU{
		cfg:    cfg,
		ctx:    ctx,
		outMtx: &sync.Mutex{},
		eg:     eg,
	}
	return qemu, nil
}

func (q *QEMU) PID() int {
	if q.cmd != nil {
		return q.cmd.Process.Pid
	}
	return 0
}

func (q *QEMU) Run() (err error) {

	if q.cfg.Raft.SerialLogPath == "" {
		q.cfg.Raft.SerialLogPath = filepath.Join(os.TempDir(), fmt.Sprintf("serial.%d%d.log", time.Now().UnixNano(), rand.Int()))
	}
	if q.cfg.Raft.QemuLogPath == "" {
		q.cfg.Raft.QemuLogPath = filepath.Join(os.TempDir(), fmt.Sprintf("qemu.%d%d.log", time.Now().UnixNano(), rand.Int()))
	}

	args := []string{
		"-M", "microvm",
		"-accel", "kvm",
		"-accel", "xen",
		"-accel", "hvf",
		"-accel", "whpx",
		"-accel", "nvmm",
		"-accel", "tcg",
		"-cpu", "max",
		"-m", q.cfg.Raft.Memory,
		"-smp", strconv.Itoa(int(q.cfg.Raft.CPU)),
		"-kernel", q.cfg.Raft.KernelPath,
		"-initrd", q.cfg.Raft.InitPath,
		"-nodefaults",
		"-no-user-config",
		"-nographic",
		"-monitor", "none",
		"-serial", fmt.Sprintf("file:%s", q.cfg.Raft.SerialLogPath),
	}

	// TODO
	// Switch serial to stdio on unix and console on windows
	// https://www.qemu.org/docs/master/system/invocation.html#hxtool-6

	if len(q.cfg.Raft.InitCommand) == 0 {
		q.cfg.Raft.InitCommand = "/bin/sh"
	}
	kernelAppend := fmt.Sprintf("earlyprintk=ttyS0 console=ttyS0 init=%s", q.cfg.Raft.InitCommand)
	if len(q.cfg.Raft.KernelAppend) > 0 {
		kernelAppend = fmt.Sprintf("%s %s", kernelAppend, q.cfg.Raft.KernelAppend)
	}

	args = append(args, "-append", kernelAppend)

	netdevArgs := []string{"user", "id=unet", "ipv4=on", "ipv6=off"}
	if q.cfg.Raft.RestrictNetwork {
		netdevArgs = append(netdevArgs, "restrict=yes")
	}

	var ports []domain.Ports
	if q.cfg.Raft.SSHServerPort.HostPort > 0 && q.cfg.Raft.SSHServerPort.GuestPort != 0 {
		ports = append(ports, q.cfg.Raft.SSHServerPort)
	}
	ports = append(ports, q.cfg.Raft.Ports...)

	for _, port := range ports {
		if port.HostIP == "" {
			port.HostIP = "127.0.0.1"
		}
		var fwdRule string
		if port.GuestIP != "" {
			fwdRule = fmt.Sprintf("hostfwd=tcp:%s:%d-%s:%d", port.HostIP, port.HostPort, port.GuestIP, port.GuestPort)
		} else {
			fwdRule = fmt.Sprintf("hostfwd=tcp:%s:%d-:%d", port.HostIP, port.HostPort, port.GuestPort)
		}
		netdevArgs = append(netdevArgs, fwdRule)
	}

	args = append(args, "-netdev", strings.Join(netdevArgs, ","))
	args = append(args, "-device", "virtio-net-device,netdev=unet")

	// Add disk image if configured
	if q.cfg.Raft.DiskImagePath != "" {
		args = append(args, "-drive", fmt.Sprintf("format=raw,file=%s,id=rootfs,if=none", q.cfg.Raft.DiskImagePath))
		args = append(args, "-device", "virtio-blk-device,drive=rootfs")
	}

	// Add 9p filesystem shares
	for i, share := range q.cfg.Raft.FSShares {
		fsdevID := fmt.Sprintf("fsdev%d", i)

		// Build fsdev arguments
		fsdevArgs := []string{
			"local",
			fmt.Sprintf("id=%s", fsdevID),
			fmt.Sprintf("path=%s", share.HostPath),
			fmt.Sprintf("security_model=%s", share.SecurityModel),
		}
		if share.ReadOnly {
			fsdevArgs = append(fsdevArgs, "readonly=on")
		}

		args = append(args, "-fsdev", strings.Join(fsdevArgs, ","))

		// Add virtio-9p device (using virtio-9p-device for microvm)
		deviceArgs := fmt.Sprintf("virtio-9p-device,fsdev=%s,mount_tag=%s", fsdevID, share.MountTag)
		args = append(args, "-device", deviceArgs)
	}

	// Add virtio-balloon device for dynamic memory management
	if q.cfg.Raft.BalloonDevice {
		args = append(args, "-device", "virtio-balloon-device")
	}

	q.cmd = exec.CommandContext(q.ctx, q.cfg.Raft.QemuPath, args...)

	if len(os.Getenv("DEBUG")) > 0 {
		cmdStr := strings.Builder{}
		cmdStr.WriteString("qemu command: ")
		cmdStr.WriteString(q.cfg.Raft.QemuPath)
		cmdStr.WriteString(" ")
		for _, arg := range args {
			if strings.Contains(arg, " ") {
				cmdStr.WriteString(fmt.Sprintf(`"%s"`, arg))
			} else {
				cmdStr.WriteString(arg)
			}
			cmdStr.WriteString(" ")
		}
		fmt.Println(cmdStr.String())
	}

	q.processLog, err = os.OpenFile(q.cfg.Raft.QemuLogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to create process log file: %w", err)
	}
	defer func() { _ = q.processLog.Close() }()
	q.cmd.Stdout = q.processLog
	q.cmd.Stderr = q.processLog
	q.cfg.Logger.Debug("process log file created", "file", q.cfg.Raft.QemuLogPath)

	q.serialLog, err = os.OpenFile(q.cfg.Raft.SerialLogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to create serial log file: %w", err)
	}
	defer func() { _ = q.serialLog.Close() }()
	q.cfg.Logger.Debug("serial log file created", "file", q.cfg.Raft.SerialLogPath)

	q.eg.Go(q.cmd.Run)
	q.eg.Go(func() error { return q.tailLog(q.serialLog, "kernel") })
	q.eg.Go(func() error { return q.tailLog(q.processLog, "qemu") })

	return q.eg.Wait()
}

func (q *QEMU) tailLog(f *os.File, source string) (err error) {
	reader := bufio.NewReader(&noErrorReader{ctx: q.ctx, r: f})
	var line []byte
	for {
		select {
		case <-q.ctx.Done():
			line, _ = reader.ReadBytes('\n')
			q.outMtx.Lock()
			_, _ = q.cfg.Stderr.Write(jsonStdErr(line, source))
			_, _ = q.cfg.Stderr.Write([]byte("\n"))
			q.outMtx.Unlock()
			return nil
		default:
			line, err = reader.ReadBytes('\n')
			q.outMtx.Lock()
			_, _ = q.cfg.Stderr.Write(jsonStdErr(line, source))
			_, _ = q.cfg.Stderr.Write([]byte("\n"))
			q.outMtx.Unlock()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
}

func jsonStdErr(line []byte, source string) []byte {
	line = bytes.TrimRightFunc(line, func(r rune) bool { return r == '\n' || r == '\r' })
	if bytes.HasPrefix(line, []byte("{")) {
		if bytes.Contains(line, []byte("source")) && bytes.Contains(line, []byte("time")) && bytes.Contains(line, []byte("msg")) {
			return line
		}
	}
	data, _ := json.Marshal(struct {
		Source  string    `json:"source"`
		Time    time.Time `json:"time"`
		Message string    `json:"msg"`
	}{
		Source:  source,
		Time:    time.Now(),
		Message: string(line),
	})
	return data
}

type noErrorReader struct {
	ctx context.Context
	r   io.Reader
}

func (n *noErrorReader) Read(p []byte) (nb int, err error) {
	for {
		select {
		case <-n.ctx.Done():
			return n.r.Read(p)
		default:
			nb, err = n.r.Read(p)
			if nb == 0 && err == io.EOF {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return nb, err
		}
	}
}
