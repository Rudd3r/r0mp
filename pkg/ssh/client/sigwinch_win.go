//go:build windows

package client

import (
	"os"
	"syscall"
	"time"
)

func sigWinch() (chan os.Signal, func()) {
	sigChan := make(chan os.Signal, 1)
	t := time.NewTicker(time.Second)
	go func() {
		for range t.C {
			sigChan <- syscall.Signal(0x1c)
		}
	}()
	return sigChan, func() {
		t.Stop()
		close(sigChan)
	}
}
