//go:build linux || darwin

package client

import (
	"os"
	"os/signal"
	"syscall"
)

func sigWinch() (chan os.Signal, func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGWINCH)
	return sigChan, func() {
		signal.Reset(syscall.SIGWINCH)
		close(sigChan)
	}
}
