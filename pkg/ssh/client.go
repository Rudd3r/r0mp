package ssh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"
)

func Client(ctx context.Context, log *slog.Logger, cfg *domain.SSHClientConfig) error {

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	dailer := &net.Dialer{Timeout: time.Second * 10}
	conn, err := dailer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	connection, chans, reqs, err := ssh.NewClientConn(
		conn,
		addr,
		&ssh.ClientConfig{
			Config:          ssh.Config{},
			User:            cfg.User,
			Auth:            cfg.Auth,
			HostKeyCallback: cfg.HostKeyCallback,
			Timeout:         time.Second * 10,
		},
	)
	if err != nil {
		return err
	}
	sshClient := ssh.NewClient(connection, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	sshSession, err := sshClient.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = sshSession.Close() }()

	sshSession.Stdout = cfg.Stdout
	sshSession.Stderr = cfg.Stderr
	if cfg.Interactive {
		sshSession.Stdin = cfg.Stdin
	}
	if len(cfg.EnvironmentVars) > 0 {
		for k, v := range cfg.EnvironmentVars {
			if err = sshSession.Setenv(k, v); err != nil {
				return fmt.Errorf("failed to set environment variable %s, %w", k, err)
			}
		}
	}
	
	// Pass detach flag to server
	if cfg.Detach {
		if err = sshSession.Setenv(EnvRaftDetach, "1"); err != nil {
			return fmt.Errorf("failed to set %s environment variable, %w", EnvRaftDetach, err)
		}
	}

	// Pass log output flag to server
	if cfg.LogOutput {
		if err = sshSession.Setenv(EnvRaftLogOutput, "1"); err != nil {
			return fmt.Errorf("failed to set %s environment variable, %w", EnvRaftLogOutput, err)
		}
	}

	// Check if stdin is a terminal and request PTY if so
	if cfg.EnableTTY {
		fd := int(os.Stdin.Fd())
		if terminal.IsTerminal(fd) {
			state, err := terminal.MakeRaw(fd)
			if err != nil {
				return fmt.Errorf("terminal make raw: %s", err)
			}
			defer func() { _ = terminal.Restore(fd, state) }()

			width, height, err := terminal.GetSize(fd)
			if err != nil {
				return fmt.Errorf("terminal get size: %s", err)
			}

			term := os.Getenv("TERM")
			if term == "" {
				term = "xterm-256color"
			}

			if err = sshSession.RequestPty(
				term,
				height,
				width,
				ssh.TerminalModes{
					ssh.ECHO:          1,
					ssh.TTY_OP_ISPEED: 14400,
					ssh.TTY_OP_OSPEED: 14400,
				},
			); err != nil {
				return err
			}

			// Handle window resize signals
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGWINCH)
			defer func() {
				signal.Reset(syscall.SIGWINCH)
				close(sigChan)
			}()
			go func() {
				var newWidth, newHeight int
				for range sigChan {
					newWidth, newHeight, err = terminal.GetSize(fd)
					if err != nil {
						log.Error("terminal get size", "error", err)
						continue
					}
					if newWidth == height && newHeight == width {
						continue
					}
					width = newWidth
					height = newHeight
					err = sshSession.WindowChange(height, width)
					if err != nil {
						log.Error("terminal change size", "error", err)
					}
				}
			}()
		}
	}

	if err = sshSession.Run(cfg.Command); err != nil {
		var sshErr *ssh.ExitError
		if errors.As(err, &sshErr) && sshErr.ExitStatus() != 130 {
			return sshErr
		}
	}

	return nil
}
