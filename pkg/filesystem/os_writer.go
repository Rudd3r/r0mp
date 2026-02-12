package filesystem

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

var _ domain.Writer = (*OSWriter)(nil)

// OSWriter implements Writer interface for OS filesystem operations.
// It writes files relative to a base directory for safety.
type OSWriter struct {
	baseDir string
}

// NewOSWriter creates a writer for the specified base directory.
// The base directory will be created if it doesn't exist.
func NewOSWriter(baseDir string) (*OSWriter, error) {
	absPath, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve base directory: %w", err)
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		return nil, fmt.Errorf("create base directory: %w", err)
	}

	return &OSWriter{baseDir: absPath}, nil
}

// normalizePath converts paths to be relative to baseDir
func (w *OSWriter) normalizePath(path string) string {
	if filepath.IsAbs(path) && strings.HasPrefix(path, w.baseDir) {
		return path
	}
	path = strings.TrimPrefix(path, "/")
	return filepath.Join(w.baseDir, path)
}

func (w *OSWriter) Mkdir(name string, info domain.FileInfo) error {
	path := w.normalizePath(name)
	if err := os.Mkdir(path, info.FMode); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir %s: %w", name, err)
	}
	return nil
}

func (w *OSWriter) MkdirAll(path string, info domain.FileInfo) error {
	path = w.normalizePath(path)
	if err := os.MkdirAll(path, info.FMode); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", path, err)
	}
	return nil
}

func (w *OSWriter) WriteFile(name string, info domain.FileInfo, reader io.Reader) error {
	path := w.normalizePath(name)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.FMode)
	if err != nil {
		return fmt.Errorf("create file %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, reader); err != nil {
		return fmt.Errorf("write file %s: %w", name, err)
	}

	return nil
}

func (w *OSWriter) Symlink(oldname, newname string, info domain.FileInfo) error {
	newpath := w.normalizePath(newname)

	dir := filepath.Dir(newpath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	_ = os.Remove(newpath)

	if err := os.Symlink(oldname, newpath); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", newname, oldname, err)
	}
	return nil
}

func (w *OSWriter) Link(oldname, newname string) error {
	oldpath := w.normalizePath(oldname)
	newpath := w.normalizePath(newname)

	dir := filepath.Dir(newpath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	if err := os.Link(oldpath, newpath); err != nil {
		return fmt.Errorf("link %s -> %s: %w", newname, oldname, err)
	}
	return nil
}

func (w *OSWriter) Remove(name string) error {
	path := w.normalizePath(name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return nil
}

func (w *OSWriter) RemoveAll(path string) error {
	path = w.normalizePath(path)
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove -r %s: %w", path, err)
	}
	return nil
}

func (w *OSWriter) ReadDir(name string) ([]fs.DirEntry, error) {
	path := w.normalizePath(name)
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", name, err)
	}
	return entries, nil
}

func (w *OSWriter) Stat(name string) (os.FileInfo, error) {
	path := w.normalizePath(name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", name, err)
	}
	return info, nil
}

func (w *OSWriter) Chown(name string, uid, gid uint32) error {
	path := w.normalizePath(name)
	if err := os.Lchown(path, int(uid), int(gid)); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	return nil
}

func (w *OSWriter) Chmod(name string, mode os.FileMode) error {
	path := w.normalizePath(name)
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	return nil
}

func (w *OSWriter) Close() error {
	return nil
}
