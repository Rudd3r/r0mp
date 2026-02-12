package image

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsWhiteout(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{
			name:     "regular whiteout",
			filename: ".wh.foo",
			want:     true,
		},
		{
			name:     "opaque whiteout",
			filename: ".wh..wh..opq",
			want:     true,
		},
		{
			name:     "regular file",
			filename: "foo.txt",
			want:     false,
		},
		{
			name:     "hidden file",
			filename: ".hidden",
			want:     false,
		},
		{
			name:     "whiteout with path",
			filename: "/some/path/.wh.file",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWhiteout(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsOpaqueWhiteout(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{
			name:     "opaque whiteout",
			filename: ".wh..wh..opq",
			want:     true,
		},
		{
			name:     "opaque whiteout with path",
			filename: "/some/path/.wh..wh..opq",
			want:     true,
		},
		{
			name:     "regular whiteout",
			filename: ".wh.foo",
			want:     false,
		},
		{
			name:     "regular file",
			filename: "foo.txt",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOpaqueWhiteout(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetWhiteoutTarget(t *testing.T) {
	tests := []struct {
		name         string
		whiteoutPath string
		want         string
	}{
		{
			name:         "regular whiteout in root",
			whiteoutPath: ".wh.foo",
			want:         "foo",
		},
		{
			name:         "regular whiteout with path",
			whiteoutPath: "some/path/.wh.bar",
			want:         "some/path/bar",
		},
		{
			name:         "opaque whiteout",
			whiteoutPath: "some/dir/.wh..wh..opq",
			want:         "some/dir",
		},
		{
			name:         "opaque whiteout in root",
			whiteoutPath: ".wh..wh..opq",
			want:         ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetWhiteoutTarget(tt.whiteoutPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProcessWhiteout(t *testing.T) {
	t.Run("regular whiteout removes target file", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()

		// Create a file to be deleted
		err := mockWriter.WriteFile("foo.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content")))
		require.NoError(t, err)

		// Process whiteout
		err = ProcessWhiteout(mockWriter, "/", ".wh.foo.txt")
		require.NoError(t, err)

		// Verify file was deleted
		assert.False(t, mockWriter.FileExists("foo.txt"), "file should be deleted")
	})

	t.Run("regular whiteout removes target directory", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()

		// Create a directory with files
		require.NoError(t, mockWriter.MkdirAll("mydir", domain.FileInfo{FMode: 0755}))
		require.NoError(t, mockWriter.WriteFile("mydir/file.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content"))))

		// Process whiteout
		err := ProcessWhiteout(mockWriter, "/", ".wh.mydir")
		require.NoError(t, err)

		// Verify directory was deleted
		assert.False(t, mockWriter.FileExists("mydir"), "directory should be deleted")
	})

	t.Run("opaque whiteout removes directory contents", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()

		// Create a directory with multiple files
		require.NoError(t, mockWriter.MkdirAll("opaquedir", domain.FileInfo{FMode: 0755}))
		require.NoError(t, mockWriter.WriteFile("opaquedir/file1.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content1"))))
		require.NoError(t, mockWriter.WriteFile("opaquedir/file2.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content2"))))
		require.NoError(t, mockWriter.MkdirAll("opaquedir/subdir", domain.FileInfo{FMode: 0755}))

		// Process opaque whiteout
		err := ProcessWhiteout(mockWriter, "/", filepath.Join("opaquedir", ".wh..wh..opq"))
		require.NoError(t, err)

		// Verify directory still exists
		info, err := mockWriter.Stat("opaquedir")
		require.NoError(t, err)
		assert.True(t, info.IsDir(), "directory should still exist")

		// Verify directory is empty
		entries, err := mockWriter.ReadDir("opaquedir")
		require.NoError(t, err)
		assert.Empty(t, entries, "directory should be empty")
	})

	t.Run("whiteout for non-existent target is OK", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()

		// Process whiteout for non-existent file
		err := ProcessWhiteout(mockWriter, "/", ".wh.nonexistent")
		assert.NoError(t, err, "processing whiteout for non-existent file should not error")
	})

	t.Run("opaque whiteout for non-existent directory is OK", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()

		// Process opaque whiteout for non-existent directory
		err := ProcessWhiteout(mockWriter, "/", filepath.Join("nonexistent", ".wh..wh..opq"))
		assert.NoError(t, err, "processing opaque whiteout for non-existent directory should not error")
	})
}
