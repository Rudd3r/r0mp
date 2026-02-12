package domain

import (
	"io"
	"io/fs"
	"os"
	"time"
)

var _ fs.DirEntry = (*DirEntry)(nil)

type DirEntry struct {
	name string
	typ  fs.FileMode
	info fs.FileInfo
}

func (d *DirEntry) Usage() string {
	return ""
}

func NewDirEntry(name string, typ fs.FileMode, info fs.FileInfo) *DirEntry {
	return &DirEntry{
		name: name,
		typ:  typ,
		info: info,
	}
}

func (d *DirEntry) Name() string      { return d.name }
func (d *DirEntry) IsDir() bool       { return d.typ.IsDir() }
func (d *DirEntry) Type() fs.FileMode { return d.typ }

func (d *DirEntry) Info() (fs.FileInfo, error) {
	return d.info, nil
}

func (d *DirEntry) String() string {
	return fs.FormatDirEntry(d)
}

var _ fs.FileInfo = (*FileInfo)(nil)

type FileInfo struct {
	FName        string
	LName        string
	FSize        int64
	FMode        fs.FileMode
	Uid          uint32
	Gid          uint32
	AccessTime   time.Time
	ChangeTime   time.Time
	ModifiedTime time.Time
	CreateTime   time.Time
	Xattrs       map[string][]byte
}

func (f FileInfo) Usage() string {
	return ""
}

func (f FileInfo) Name() string {
	return f.FName
}

func (f FileInfo) Size() int64 {
	return f.FSize
}

func (f FileInfo) Mode() fs.FileMode {
	return f.FMode
}

func (f FileInfo) ModTime() time.Time {
	return f.ModifiedTime
}

func (f FileInfo) IsDir() bool {
	return f.FMode.IsDir()
}

func (f FileInfo) Sys() any {
	return f
}

// Writer provides an abstraction for filesystem operations
// This interface allows the image extractor to work with different storage backends
// (OS filesystem, disk images via go-diskfs, in-memory for testing, etc.)
type Writer interface {
	// MkdirAll creates a directory and all necessary parent directories
	MkdirAll(path string, info FileInfo) error

	// Mkdir creates a directory
	Mkdir(path string, info FileInfo) error

	// Chown changes the ownership of a file or directory
	Chown(name string, uid, gid uint32) error

	// Chmod changes the permissions of a file or directory
	Chmod(path string, mode os.FileMode) error

	// WriteFile creates a file and writes content from the reader
	// If the file exists, it will be truncated
	WriteFile(path string, info FileInfo, reader io.Reader) error

	// Remove removes a file or empty directory
	Remove(path string) error

	// RemoveAll removes a path and any children it contains
	// It removes everything it can but returns the first error it encounters
	RemoveAll(path string) error

	// Symlink creates a symbolic link from linkname pointing to target
	Symlink(target, linkname string, info FileInfo) error

	// Link creates a hard link from linkname to target
	Link(target, linkname string) error

	// ReadDir reads the directory and returns directory entries
	ReadDir(path string) ([]os.DirEntry, error)

	// Stat returns file information for the given path
	Stat(path string) (os.FileInfo, error)

	// Close will cleanup the temporary files created by the filesystem generation steps
	Close() error
}
