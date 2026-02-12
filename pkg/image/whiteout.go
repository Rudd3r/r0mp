package image

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

// Whiteout file constants from the OCI image specification
// See: https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts
const (
	// WhiteoutPrefix is the prefix for whiteout files
	// Example: .wh.foo means delete file/directory named "foo"
	WhiteoutPrefix = ".wh."

	// WhiteoutOpaqueDir marks a directory as opaque
	// When present, all previous contents of the directory should be hidden
	WhiteoutOpaqueDir = ".wh..wh..opq"
)

// IsWhiteout checks if a filename represents a whiteout file
func IsWhiteout(name string) bool {
	base := filepath.Base(name)
	return strings.HasPrefix(base, WhiteoutPrefix)
}

// IsOpaqueWhiteout checks if a filename represents an opaque directory whiteout
func IsOpaqueWhiteout(name string) bool {
	base := filepath.Base(name)
	return base == WhiteoutOpaqueDir
}

// GetWhiteoutTarget returns the path that should be deleted for a whiteout file
// For regular whiteouts (.wh.foo), returns the path with .wh. removed
// For opaque whiteouts (.wh..wh..opq), returns the directory path
func GetWhiteoutTarget(whiteoutPath string) string {
	dir := filepath.Dir(whiteoutPath)
	base := filepath.Base(whiteoutPath)

	if base == WhiteoutOpaqueDir {
		// Opaque whiteout - target is the directory itself
		return dir
	}

	// Regular whiteout - remove .wh. prefix to get target name
	target := strings.TrimPrefix(base, WhiteoutPrefix)
	return filepath.Join(dir, target)
}

// ProcessWhiteout handles a whiteout file by deleting the appropriate target
// For opaque whiteouts, removes all directory contents
// For regular whiteouts, removes the target file or directory
func ProcessWhiteout(fs domain.Writer, baseDir, whiteoutPath string) error {
	targetPath := filepath.Join(baseDir, GetWhiteoutTarget(whiteoutPath))

	if IsOpaqueWhiteout(whiteoutPath) {
		// Opaque whiteout: remove all contents of the directory but keep the directory
		return removeDirectoryContents(fs, targetPath)
	}

	// Regular whiteout: remove the target file or directory
	if err := fs.RemoveAll(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// removeDirectoryContents removes all files and directories within a directory
// but keeps the directory itself
func removeDirectoryContents(fs domain.Writer, dir string) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist, nothing to remove
			return nil
		}
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if err := fs.RemoveAll(path); err != nil {
			return err
		}
	}

	return nil
}
