package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/containerd/console"
	"golang.org/x/crypto/ssh"
)

func Client(ctx context.Context, log *slog.Logger, cfg *domain.SSHClientConfig) error {

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	dialer := &net.Dialer{Timeout: time.Second * 10}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
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
		if err = sshSession.Setenv(domain.EnvRaftDetach, "1"); err != nil {
			return fmt.Errorf("failed to set %s environment variable, %w", domain.EnvRaftDetach, err)
		}
	}

	// Pass log output flag to server
	if cfg.LogOutput {
		if err = sshSession.Setenv(domain.EnvRaftLogOutput, "1"); err != nil {
			return fmt.Errorf("failed to set %s environment variable, %w", domain.EnvRaftLogOutput, err)
		}
	}

	// Check if stdin is a terminal and request PTY if so
	if cfg.EnableTTY {
		con := console.Current()
		defer func() { _ = con.Reset() }()
		if err := con.SetRaw(); err != nil {
			return fmt.Errorf("terminal make raw: %s", err)
		}

		winSize, err := con.Size()
		if err != nil {
			return fmt.Errorf("failed to get terminal size, %w", err)
		}

		term := os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}

		if err = sshSession.RequestPty(
			term,
			int(winSize.Height),
			int(winSize.Width),
			ssh.TerminalModes{
				ssh.ECHO:          1,
				ssh.TTY_OP_ISPEED: 14400,
				ssh.TTY_OP_OSPEED: 14400,
			},
		); err != nil {
			return err
		}

		// Handle window resize signals
		sigChan, sigDone := sigWinch()
		defer sigDone()
		go func() {
			var newWinSize console.WinSize
			for range sigChan {
				newWinSize, err = con.Size()
				if err != nil {
					log.Error("terminal get size", "error", err)
					continue
				}

				if newWinSize.Height == winSize.Height && newWinSize.Width == winSize.Width {
					continue
				}
				winSize = newWinSize
				err = sshSession.WindowChange(int(winSize.Height), int(winSize.Width))
				if err != nil {
					log.Error("terminal change size", "error", err)
				}
			}
		}()
	}

	if err = sshSession.Run(cfg.Command); err != nil {
		var sshErr *ssh.ExitError
		if errors.As(err, &sshErr) && sshErr.ExitStatus() != 130 {
			return sshErr
		}
	}

	return nil
}
