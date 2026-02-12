//go:build windows

package domain

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func IsProcessRunning(pid int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("invalid pid %d", pid)
	}

	// On Windows, use OpenProcess to check if the process exists
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// ERROR_INVALID_PARAMETER or ERROR_ACCESS_DENIED could mean different things
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false, nil // Process doesn't exist
		}
		// Access denied typically means process exists but we can't open it
		if errors.Is(err, syscall.Errno(0x5)) { // ERROR_ACCESS_DENIED
			return true, nil
		}
		return false, nil
	}
	return true, windows.CloseHandle(handle)
}
