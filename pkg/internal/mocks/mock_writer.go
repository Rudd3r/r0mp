package mocks

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

var _ domain.Writer = (*MockWriter)(nil)

// MockWriter is an in-memory filesystem.Writer implementation for testing
// It tracks all operations and stores files in memory
type MockWriter struct {
	files    map[string]*mockFile
	symlinks map[string]*mockSymlink
	closed   bool
}

// mockSymlink represents a symbolic link in the mock filesystem
type mockSymlink struct {
	target string
	info   domain.FileInfo
}

func (m *MockWriter) Close() error {
	if m.closed {
		return fmt.Errorf("already closed")
	}
	m.closed = true
	return nil
}

func (m *MockWriter) Chown(name string, uid, gid uint32) error {
	name = m.normalize(name)

	file, exists := m.files[name]
	if !exists {
		return &os.PathError{Op: "chmod", Path: name, Err: os.ErrNotExist}
	}

	file.info.Uid = uid
	file.info.Gid = gid
	return nil
}

func (m *MockWriter) BaseDir() string {
	return ""
}

// mockFile represents a file in the mock filesystem
type mockFile struct {
	content []byte
	info    domain.FileInfo
	modTime time.Time
	isDir   bool
}

// NewMockWriter creates a new mock filesystem writer
func NewMockWriter() *MockWriter {
	if !testing.Testing() {
		panic(fmt.Errorf("NewMockWriter cannot be used outside test"))
	}
	return &MockWriter{
		files:    make(map[string]*mockFile),
		symlinks: make(map[string]*mockSymlink),
	}
}

// normalize cleans the path for consistent lookups
func (m *MockWriter) normalize(path string) string {
	path = filepath.Clean(path)
	// Remove leading slash for consistency
	return strings.TrimPrefix(path, "/")
}

// Mkdir creates a directory
func (m *MockWriter) Mkdir(path string, info domain.FileInfo) error {
	// TODO make this fail if the parent path doesn't exist
	return m.MkdirAll(path, info)
}

// MkdirAll creates a directory and all necessary parent directories
func (m *MockWriter) MkdirAll(path string, info domain.FileInfo) error {
	path = m.normalize(path)

	// Create all parent directories
	parts := strings.Split(path, string(filepath.Separator))
	for i := 1; i <= len(parts); i++ {
		dir := filepath.Join(parts[:i]...)
		if dir == "" {
			continue
		}
		if _, exists := m.files[dir]; !exists {
			// Ensure the FMode has the directory bit set
			dirInfo := info
			dirInfo.FMode = dirInfo.FMode | os.ModeDir
			m.files[dir] = &mockFile{
				info:    dirInfo,
				modTime: time.Now(),
				isDir:   true,
			}
		}
	}

	return nil
}

// Chmod changes the permissions of a file or directory
func (m *MockWriter) Chmod(path string, mode os.FileMode) error {
	path = m.normalize(path)

	file, exists := m.files[path]
	if !exists {
		return &os.PathError{Op: "chmod", Path: path, Err: os.ErrNotExist}
	}

	file.info.FMode = mode
	return nil
}

// WriteFile creates a file and writes content from the reader
func (m *MockWriter) WriteFile(path string, info domain.FileInfo, reader io.Reader) error {
	path = m.normalize(path)

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	// TODO handle this better, messy
	if dir != "." && dir != "" {
		if err := m.MkdirAll(dir, domain.FileInfo{
			FMode:        os.FileMode(0755),
			Uid:          0,
			Gid:          0,
			AccessTime:   time.Now(),
			ChangeTime:   time.Now(),
			ModifiedTime: time.Now(),
			CreateTime:   time.Now(),
			Xattrs:       nil,
		}); err != nil {
			return err
		}
	}

	// Read content
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read content: %w", err)
	}

	// Store file
	m.files[path] = &mockFile{
		content: content,
		info:    info,
		modTime: time.Now(),
		isDir:   false,
	}

	return nil
}

// Remove removes a file or empty directory
func (m *MockWriter) Remove(path string) error {
	path = m.normalize(path)

	if _, exists := m.files[path]; !exists {
		if _, exists := m.symlinks[path]; !exists {
			return &os.PathError{Op: "remove", Path: path, Err: os.ErrNotExist}
		}
		delete(m.symlinks, path)
		return nil
	}

	// If it's a directory, check if it's empty
	if m.files[path].isDir {
		for p := range m.files {
			if strings.HasPrefix(p, path+string(filepath.Separator)) {
				return &os.PathError{Op: "remove", Path: path, Err: fmt.Errorf("directory not empty")}
			}
		}
	}

	delete(m.files, path)
	return nil
}

// RemoveAll removes a path and any children it contains
func (m *MockWriter) RemoveAll(path string) error {
	path = m.normalize(path)

	// Remove the path itself
	delete(m.files, path)
	delete(m.symlinks, path)

	// Remove all children
	prefix := path + string(filepath.Separator)
	for p := range m.files {
		if strings.HasPrefix(p, prefix) {
			delete(m.files, p)
		}
	}
	for p := range m.symlinks {
		if strings.HasPrefix(p, prefix) {
			delete(m.symlinks, p)
		}
	}

	return nil
}

// Symlink creates a symbolic link from linkname pointing to target
func (m *MockWriter) Symlink(target, linkname string, info domain.FileInfo) error {
	linkname = m.normalize(linkname)

	// Ensure parent directory exists
	dir := filepath.Dir(linkname)
	if dir != "." && dir != "" {
		if err := m.MkdirAll(dir, domain.FileInfo{
			FMode:        os.FileMode(0755),
			Uid:          0,
			Gid:          0,
			AccessTime:   time.Now(),
			ChangeTime:   time.Now(),
			ModifiedTime: time.Now(),
			CreateTime:   time.Now(),
			Xattrs:       nil,
		}); err != nil {
			return err
		}
	}

	// Remove existing if present
	delete(m.files, linkname)

	// Create symlink with FileInfo
	m.symlinks[linkname] = &mockSymlink{
		target: target,
		info:   info,
	}

	return nil
}

// Link creates a hard link from linkname to target
func (m *MockWriter) Link(target, linkname string) error {
	target = m.normalize(target)
	linkname = m.normalize(linkname)

	// Check if target exists
	file, exists := m.files[target]
	if !exists {
		return &os.PathError{Op: "link", Path: target, Err: os.ErrNotExist}
	}

	// Ensure parent directory exists
	dir := filepath.Dir(linkname)
	if dir != "." && dir != "" {
		if err := m.MkdirAll(dir, domain.FileInfo{
			FMode:        os.FileMode(0755),
			Uid:          0,
			Gid:          0,
			AccessTime:   time.Now(),
			ChangeTime:   time.Now(),
			ModifiedTime: time.Now(),
			CreateTime:   time.Now(),
			Xattrs:       nil,
		}); err != nil {
			return err
		}
	}

	// Remove existing if present
	delete(m.files, linkname)

	// Create hard link (copy the file content)
	m.files[linkname] = &mockFile{
		content: file.content,
		info: domain.FileInfo{
			FName:        "",
			FSize:        file.info.FSize,
			FMode:        file.info.FMode,
			Uid:          file.info.Uid,
			Gid:          file.info.Gid,
			AccessTime:   file.info.AccessTime,
			ChangeTime:   file.info.ChangeTime,
			ModifiedTime: file.info.ModifiedTime,
			CreateTime:   file.info.CreateTime,
			Xattrs:       maps.Clone(file.info.Xattrs),
		},
		modTime: file.modTime,
		isDir:   file.isDir,
	}

	return nil
}

// ReadDir reads the directory and returns directory entries
func (m *MockWriter) ReadDir(path string) ([]os.DirEntry, error) {
	path = m.normalize(path)

	// Check if directory exists
	if file, exists := m.files[path]; !exists || !file.isDir {
		return nil, &os.PathError{Op: "readdir", Path: path, Err: os.ErrNotExist}
	}

	// Find all direct children
	entries := make([]os.DirEntry, 0)
	seen := make(map[string]bool)
	prefix := path
	if prefix != "" {
		prefix += string(filepath.Separator)
	}

	for p, f := range m.files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}

		rel := strings.TrimPrefix(p, prefix)
		if rel == "" {
			continue
		}

		// Only include direct children (not grandchildren)
		parts := strings.Split(rel, string(filepath.Separator))
		name := parts[0]

		if !seen[name] {
			seen[name] = true
			entries = append(entries, &mockDirEntry{
				name:  name,
				isDir: len(parts) > 1 || f.isDir,
				mode:  f.info.Mode(),
			})
		}
	}

	return entries, nil
}

// Stat returns file information for the given path
func (m *MockWriter) Stat(path string) (os.FileInfo, error) {
	path = m.normalize(path)

	// Check if it's a file
	file, exists := m.files[path]
	if exists {
		// Return a copy of the FileInfo with the actual file info
		fileInfo := file.info
		fileInfo.FName = filepath.Base(path)
		fileInfo.FSize = int64(len(file.content))
		fileInfo.ModifiedTime = file.modTime
		return fileInfo, nil
	}

	// Check if it's a symlink
	symlink, exists := m.symlinks[path]
	if exists {
		// Return a copy of the FileInfo for the symlink
		fileInfo := symlink.info
		fileInfo.FName = filepath.Base(path)
		return fileInfo, nil
	}

	return nil, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
}

// GetFileContent returns the content of a file (for testing assertions)
func (m *MockWriter) GetFileContent(path string) ([]byte, error) {
	path = m.normalize(path)

	file, exists := m.files[path]
	if !exists {
		return nil, &os.PathError{Op: "read", Path: path, Err: os.ErrNotExist}
	}

	return file.content, nil
}

// GetSymlinkTarget returns the target of a symlink (for testing assertions)
func (m *MockWriter) GetSymlinkTarget(path string) (string, error) {
	path = m.normalize(path)

	symlink, exists := m.symlinks[path]
	if !exists {
		return "", &os.PathError{Op: "readlink", Path: path, Err: os.ErrNotExist}
	}

	return symlink.target, nil
}

// FileExists checks if a file exists (for testing assertions)
func (m *MockWriter) FileExists(path string) bool {
	path = m.normalize(path)
	_, exists := m.files[path]
	return exists
}

// mockDirEntry implements os.DirEntry for testing
type mockDirEntry struct {
	name  string
	isDir bool
	mode  os.FileMode
}

func (e *mockDirEntry) Usage() string {
	//TODO implement me
	panic("implement me")
}

func (e *mockDirEntry) Name() string      { return e.name }
func (e *mockDirEntry) IsDir() bool       { return e.isDir }
func (e *mockDirEntry) Type() os.FileMode { return e.mode.Type() }
func (e *mockDirEntry) Info() (os.FileInfo, error) {
	return &mockFileInfo{
		name:  e.name,
		mode:  e.mode,
		isDir: e.isDir,
	}, nil
}

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (f *mockFileInfo) Usage() string {
	//TODO implement me
	panic("implement me")
}

func (f *mockFileInfo) Name() string       { return f.name }
func (f *mockFileInfo) Size() int64        { return f.size }
func (f *mockFileInfo) Mode() os.FileMode  { return f.mode }
func (f *mockFileInfo) ModTime() time.Time { return f.modTime }
func (f *mockFileInfo) IsDir() bool        { return f.isDir }
func (f *mockFileInfo) Sys() interface{}   { return nil }
