//go:build linux || darwin

package domain

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func IsProcessRunning(pid int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("invalid pid %d", pid)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	// On Unix systems, os.FindProcess always succeeds and returns a *Process
	// for the given pid, regardless of whether the process exists.
	// To check if it actually exists, we must send an "empty" signal (0).
	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return true, nil
	}

	// Check specific syscall errors
	var errno syscall.Errno
	ok := errors.As(err, &errno)
	if !ok {
		return false, err
	}
	switch {
	case errors.Is(errno, syscall.ESRCH): // No such process
		return false, nil
	case errors.Is(errno, syscall.EPERM): // Operation not permitted (process exists, but we can't signal it)
		return true, nil
	}

	// Default to false if the error wasn't explicitly handled above
	return false, err
}
