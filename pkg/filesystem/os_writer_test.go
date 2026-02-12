package filesystem

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

func TestNewOSWriter(t *testing.T) {
	tmpDir := t.TempDir()

	writer, err := NewOSWriter(tmpDir)
	if err != nil {
		t.Fatalf("NewOSWriter failed: %v", err)
	}

	if writer.baseDir != tmpDir {
		t.Errorf("expected baseDir %s, got %s", tmpDir, writer.baseDir)
	}

	// Verify directory was created
	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("base directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("base path is not a directory")
	}
}

func TestOSWriter_WriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	content := []byte("hello world")
	info := domain.FileInfo{
		FName: "test.txt",
		FMode: 0644,
	}

	err := writer.WriteFile("test.txt", info, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("expected content %q, got %q", content, data)
	}
}

func TestOSWriter_Mkdir(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	info := domain.FileInfo{
		FName: "testdir",
		FMode: 0755,
	}

	err := writer.Mkdir("testdir", info)
	if err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	// Verify directory was created
	stat, err := os.Stat(filepath.Join(tmpDir, "testdir"))
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}

	if !stat.IsDir() {
		t.Error("path is not a directory")
	}
}

func TestOSWriter_MkdirAll(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	info := domain.FileInfo{
		FName: "a/b/c",
		FMode: 0755,
	}

	err := writer.MkdirAll("a/b/c", info)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Verify nested directories were created
	stat, err := os.Stat(filepath.Join(tmpDir, "a/b/c"))
	if err != nil {
		t.Fatalf("nested directories not created: %v", err)
	}

	if !stat.IsDir() {
		t.Error("path is not a directory")
	}
}

func TestOSWriter_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Create target file
	targetContent := []byte("target")
	err := writer.WriteFile("target.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader(targetContent))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Create symlink
	err = writer.Symlink("target.txt", "link.txt", domain.FileInfo{})
	if err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	// Verify symlink
	linkPath := filepath.Join(tmpDir, "link.txt")
	stat, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("symlink not created: %v", err)
	}

	if stat.Mode()&os.ModeSymlink == 0 {
		t.Error("path is not a symlink")
	}

	// Verify link target
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("failed to read symlink: %v", err)
	}

	if target != "target.txt" {
		t.Errorf("expected link target %q, got %q", "target.txt", target)
	}
}

func TestOSWriter_Link(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Create original file
	content := []byte("original")
	err := writer.WriteFile("original.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Create hard link
	err = writer.Link("original.txt", "hardlink.txt")
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}

	// Verify hard link
	data, err := os.ReadFile(filepath.Join(tmpDir, "hardlink.txt"))
	if err != nil {
		t.Fatalf("hard link not created: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("expected content %q, got %q", content, data)
	}

	// Verify both files have same inode (hard link)
	stat1, _ := os.Stat(filepath.Join(tmpDir, "original.txt"))
	stat2, _ := os.Stat(filepath.Join(tmpDir, "hardlink.txt"))

	// On some filesystems we can check link count
	// This is a best-effort check
	if stat1.Size() != stat2.Size() {
		t.Error("hard link files have different sizes")
	}
}

func TestOSWriter_Remove(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Create file
	err := writer.WriteFile("test.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("test")))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Remove file
	err = writer.Remove("test.txt")
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Verify file was removed
	_, err = os.Stat(filepath.Join(tmpDir, "test.txt"))
	if !os.IsNotExist(err) {
		t.Error("file was not removed")
	}
}

func TestOSWriter_RemoveAll(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Create nested structure
	_ = writer.MkdirAll("a/b/c", domain.FileInfo{FMode: 0755})
	_ = writer.WriteFile("a/file1.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("test")))
	_ = writer.WriteFile("a/b/file2.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("test")))

	// Remove directory tree
	err := writer.RemoveAll("a")
	if err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	// Verify directory was removed
	_, err = os.Stat(filepath.Join(tmpDir, "a"))
	if !os.IsNotExist(err) {
		t.Error("directory was not removed")
	}
}

func TestOSWriter_PathNormalization(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"relative path", "test.txt", filepath.Join(tmpDir, "test.txt")},
		{"absolute path", "/test.txt", filepath.Join(tmpDir, "test.txt")},
		{"nested path", "a/b/c.txt", filepath.Join(tmpDir, "a/b/c.txt")},
		{"already normalized", filepath.Join(tmpDir, "test.txt"), filepath.Join(tmpDir, "test.txt")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := writer.normalizePath(tt.input)
			if normalized != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, normalized)
			}
		})
	}
}

func TestOSWriter_WriteFileCreatesParentDirs(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Write file in nested directory that doesn't exist
	content := []byte("test")
	err := writer.WriteFile("a/b/c/test.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(filepath.Join(tmpDir, "a/b/c/test.txt"))
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("expected content %q, got %q", content, data)
	}
}

func TestOSWriter_ReadDir(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Create some files and directories
	_ = writer.WriteFile("file1.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("test")))
	_ = writer.WriteFile("file2.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("test")))
	_ = writer.Mkdir("dir1", domain.FileInfo{FMode: 0755})

	// Read directory
	entries, err := writer.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestOSWriter_Stat(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	content := []byte("test content")
	_ = writer.WriteFile("test.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader(content))

	// Stat file
	info, err := writer.Stat("test.txt")
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Size() != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), info.Size())
	}

	if info.IsDir() {
		t.Error("file reported as directory")
	}
}

func TestOSWriter_Close(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Close should not error
	err := writer.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestOSWriter_AsWriterInterface(t *testing.T) {
	tmpDir := t.TempDir()
	writer, _ := NewOSWriter(tmpDir)

	// Verify it implements domain.Writer
	var _ domain.Writer = writer

	// Use it through the interface
	var w domain.Writer = writer
	err := w.WriteFile("test.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("test")))
	if err != nil {
		t.Fatalf("WriteFile through interface failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}

	if string(data) != "test" {
		t.Errorf("expected content %q, got %q", "test", data)
	}
}
