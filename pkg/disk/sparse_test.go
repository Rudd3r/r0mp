package disk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSparse(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test-sparse.img")

	// Create a 1GB sparse disk
	size := int64(1024 * 1024 * 1024) // 1GB
	err := CreateSparse(diskPath, size)
	require.NoError(t, err, "CreateSparse should not fail")

	// Verify file exists
	stat, err := os.Stat(diskPath)
	require.NoError(t, err, "Failed to stat disk file")

	// Verify file size
	assert.Equal(t, size, stat.Size(), "File size should match requested size")

	// Note: We can't easily test actual disk usage in a portable way,
	// but we can at least verify the file was created with the correct size
	t.Logf("Created sparse disk: %s (apparent size: %d bytes)", diskPath, stat.Size())
}

func TestCreateSparseInvalidPath(t *testing.T) {
	// Try to create a disk in a non-existent directory
	err := CreateSparse("/nonexistent/directory/disk.img", 1024)
	assert.Error(t, err, "Expected error for invalid path")
}
