package disk

import (
	"fmt"
	"io"
	"os"
)

// CreateSparse creates an empty sparse disk image file.
// The file will appear to be sizeBytes large but will only occupy minimal space on disk.
// This is useful for creating empty disks that will be formatted by the guest OS.
func CreateSparse(path string, sizeBytes int64) error {
	// Create the file
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create sparse disk file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Seek to the desired size - 1
	if _, err := file.Seek(sizeBytes-1, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to end of disk: %w", err)
	}

	// Write a single byte to set the file size
	// This creates a sparse file without allocating all the space
	if _, err := file.Write([]byte{0}); err != nil {
		return fmt.Errorf("failed to set disk size: %w", err)
	}

	return nil
}
