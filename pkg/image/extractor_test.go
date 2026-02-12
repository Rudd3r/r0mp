package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/internal/mocks"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExtractorWithFS(t *testing.T) {
	t.Run("creates extractor with mock writer", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)
		require.NotNil(t, extractor)
	})

	t.Run("works with any Writer implementation", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)
		require.NotNil(t, extractor)
		assert.NotNil(t, extractor)
	})
}

func TestExtractEntry_PathTraversal(t *testing.T) {
	mockWriter := mocks.NewMockWriter()
	extractor := NewExtractorWithFS(mockWriter)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "parent directory reference",
			path: "../etc/passwd",
		},
		{
			name: "multiple parent references",
			path: "../../etc/passwd",
		},
		{
			name: "parent reference in middle",
			path: "foo/../../../etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := &tar.Header{
				Name:     tt.path,
				Typeflag: tar.TypeReg,
				Mode:     0644,
			}

			err := extractor.extractEntry(header, bytes.NewReader(nil))
			assert.Error(t, err, "should reject path with ..")
			assert.Contains(t, err.Error(), "invalid path")
		})
	}
}

func TestExtractEntry_Files(t *testing.T) {
	mockWriter := mocks.NewMockWriter()
	extractor := NewExtractorWithFS(mockWriter)

	t.Run("extracts regular file", func(t *testing.T) {
		content := []byte("hello world")
		header := &tar.Header{
			Name:     "test.txt",
			Typeflag: tar.TypeReg,
			Mode:     0644,
			Size:     int64(len(content)),
		}

		err := extractor.extractEntry(header, bytes.NewReader(content))
		require.NoError(t, err)

		// Verify file was created with correct content
		data, err := mockWriter.GetFileContent("test.txt")
		require.NoError(t, err)
		assert.Equal(t, content, data)

		// Verify permissions
		info, err := mockWriter.Stat("test.txt")
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
	})

	t.Run("extracts file with subdirectories", func(t *testing.T) {
		content := []byte("nested content")
		header := &tar.Header{
			Name:     "subdir/nested/file.txt",
			Typeflag: tar.TypeReg,
			Mode:     0644,
			Size:     int64(len(content)),
		}

		err := extractor.extractEntry(header, bytes.NewReader(content))
		require.NoError(t, err)

		// Verify file was created
		data, err := mockWriter.GetFileContent("subdir/nested/file.txt")
		require.NoError(t, err)
		assert.Equal(t, content, data)
	})
}

func TestExtractEntry_Directories(t *testing.T) {
	mockWriter := mocks.NewMockWriter()
	extractor := NewExtractorWithFS(mockWriter)

	header := &tar.Header{
		Name:     "mydir/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}

	err := extractor.extractEntry(header, nil)
	require.NoError(t, err)

	// Verify directory was created
	info, err := mockWriter.Stat("mydir")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestExtractEntry_Symlinks(t *testing.T) {
	mockWriter := mocks.NewMockWriter()
	extractor := NewExtractorWithFS(mockWriter)

	// Create a target file first
	targetContent := []byte("target content")
	targetHeader := &tar.Header{
		Name:     "target.txt",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(targetContent)),
	}
	err := extractor.extractEntry(targetHeader, bytes.NewReader(targetContent))
	require.NoError(t, err)

	// Create symlink
	symlinkHeader := &tar.Header{
		Name:     "link.txt",
		Typeflag: tar.TypeSymlink,
		Linkname: "target.txt",
	}
	err = extractor.extractEntry(symlinkHeader, nil)
	require.NoError(t, err)

	// Verify symlink was created and target is correct
	target, err := mockWriter.GetSymlinkTarget("link.txt")
	require.NoError(t, err)
	assert.Equal(t, "target.txt", target)
}

func TestExtractEntry_Hardlinks(t *testing.T) {
	mockWriter := mocks.NewMockWriter()
	extractor := NewExtractorWithFS(mockWriter)

	// Create a target file first
	targetContent := []byte("target content")
	targetHeader := &tar.Header{
		Name:     "original.txt",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(targetContent)),
	}
	err := extractor.extractEntry(targetHeader, bytes.NewReader(targetContent))
	require.NoError(t, err)

	// Create hard link
	hardlinkHeader := &tar.Header{
		Name:     "hardlink.txt",
		Typeflag: tar.TypeLink,
		Linkname: "original.txt",
	}
	err = extractor.extractEntry(hardlinkHeader, nil)
	require.NoError(t, err)

	// Verify hard link was created with same content
	data, err := mockWriter.GetFileContent("hardlink.txt")
	require.NoError(t, err)
	assert.Equal(t, targetContent, data)

	// Verify both files have same size
	originalInfo, err := mockWriter.Stat("original.txt")
	require.NoError(t, err)
	linkInfo, err := mockWriter.Stat("hardlink.txt")
	require.NoError(t, err)
	assert.Equal(t, originalInfo.Size(), linkInfo.Size())
}

func TestExtractEntry_Whiteouts(t *testing.T) {
	t.Run("whiteout deletes existing file", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		// Create a file
		err := mockWriter.WriteFile("deleteme.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content")))
		require.NoError(t, err)

		// Extract whiteout entry
		header := &tar.Header{
			Name:     ".wh.deleteme.txt",
			Typeflag: tar.TypeReg,
			Mode:     0644,
		}
		err = extractor.extractEntry(header, bytes.NewReader(nil))
		require.NoError(t, err)

		// Verify file was deleted
		assert.False(t, mockWriter.FileExists("deleteme.txt"))
	})

	t.Run("opaque whiteout clears directory", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		// Create directory with files
		require.NoError(t, mockWriter.MkdirAll("clearme", domain.FileInfo{FMode: 0755}))
		require.NoError(t, mockWriter.WriteFile("clearme/file1.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content"))))
		require.NoError(t, mockWriter.WriteFile("clearme/file2.txt", domain.FileInfo{FMode: 0644}, bytes.NewReader([]byte("content"))))

		// Extract opaque whiteout entry
		header := &tar.Header{
			Name:     "clearme/.wh..wh..opq",
			Typeflag: tar.TypeReg,
			Mode:     0644,
		}
		err := extractor.extractEntry(header, bytes.NewReader(nil))
		require.NoError(t, err)

		// Verify directory exists but is empty
		entries, err := mockWriter.ReadDir("clearme")
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

// Helper function to create a test layer (tar.gz archive)
func createTestLayer(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for name, content := range files {
		header := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0644,
			Size:     int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(header))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gzw.Close())

	return buf.Bytes()
}

func TestExtractLayer(t *testing.T) {
	t.Run("extracts simple tar.gz layer", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		// Create a test tar.gz with multiple files
		files := map[string]string{
			"file1.txt":        "content1",
			"file2.txt":        "content2",
			"subdir/file3.txt": "content3",
		}
		layerData := createTestLayer(t, files)

		// Create a mock layer that returns our test data
		layer := &mockExtractorLayer{data: layerData}

		// Extract the layer
		err := extractor.extractLayer(layer)
		require.NoError(t, err)

		// Verify all files were extracted
		for name, expectedContent := range files {
			data, err := mockWriter.GetFileContent(name)
			require.NoError(t, err)
			assert.Equal(t, expectedContent, string(data))
		}
	})
}

// Mock layer implementation for testing
type mockExtractorLayer struct {
	data []byte
}

func (m *mockExtractorLayer) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (m *mockExtractorLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (m *mockExtractorLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.data)), nil
}

func (m *mockExtractorLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.data)), nil
}

func (m *mockExtractorLayer) Size() (int64, error) {
	return int64(len(m.data)), nil
}

func (m *mockExtractorLayer) MediaType() (types.MediaType, error) {
	return "", nil
}

func TestExtractEntry_Xattrs(t *testing.T) {
	t.Run("extracts extended attributes from PAX records", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		// Create tar header with PAX records containing xattrs
		header := &tar.Header{
			Name:     "test.txt",
			Mode:     0644,
			Size:     7,
			Typeflag: tar.TypeReg,
			PAXRecords: map[string]string{
				"SCHILY.xattr.user.myattr":      "myvalue",
				"SCHILY.xattr.security.selinux": "unconfined_u:object_r:user_tmp_t:s0",
				"SCHILY.xattr.trusted.overlay":  "overlay-data",
				"OTHER.record":                  "should-be-ignored",
			},
		}

		content := bytes.NewReader([]byte("content"))
		err := extractor.extractEntry(header, content)
		require.NoError(t, err)

		// Verify the file was created with xattrs
		info, err := mockWriter.Stat("test.txt")
		require.NoError(t, err)

		fileInfo, ok := info.(domain.FileInfo)
		require.True(t, ok, "Stat should return FileInfo")
		require.NotNil(t, fileInfo.Xattrs)
		assert.Len(t, fileInfo.Xattrs, 3)
		assert.Equal(t, []byte("myvalue"), fileInfo.Xattrs["user.myattr"])
		assert.Equal(t, []byte("unconfined_u:object_r:user_tmp_t:s0"), fileInfo.Xattrs["security.selinux"])
		assert.Equal(t, []byte("overlay-data"), fileInfo.Xattrs["trusted.overlay"])

		// Verify non-xattr PAX records are not included
		_, exists := fileInfo.Xattrs["OTHER.record"]
		assert.False(t, exists)
	})

	t.Run("handles entries without xattrs", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		header := &tar.Header{
			Name:     "test.txt",
			Mode:     0644,
			Size:     7,
			Typeflag: tar.TypeReg,
			// No PAXRecords
		}

		content := bytes.NewReader([]byte("content"))
		err := extractor.extractEntry(header, content)
		require.NoError(t, err)

		info, err := mockWriter.Stat("test.txt")
		require.NoError(t, err)

		fileInfo, ok := info.(domain.FileInfo)
		require.True(t, ok, "Stat should return FileInfo")
		assert.Nil(t, fileInfo.Xattrs)
	})

	t.Run("extracts xattrs for directories", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		header := &tar.Header{
			Name:     "testdir/",
			Mode:     0755,
			Typeflag: tar.TypeDir,
			PAXRecords: map[string]string{
				"SCHILY.xattr.user.dirattr": "dirvalue",
			},
		}

		err := extractor.extractEntry(header, nil)
		require.NoError(t, err)

		info, err := mockWriter.Stat("testdir")
		require.NoError(t, err)

		fileInfo, ok := info.(domain.FileInfo)
		require.True(t, ok, "Stat should return FileInfo")
		require.NotNil(t, fileInfo.Xattrs)
		assert.Equal(t, []byte("dirvalue"), fileInfo.Xattrs["user.dirattr"])
	})

	t.Run("extracts xattrs for symlinks", func(t *testing.T) {
		mockWriter := mocks.NewMockWriter()
		extractor := NewExtractorWithFS(mockWriter)

		header := &tar.Header{
			Name:     "testlink",
			Mode:     0777,
			Typeflag: tar.TypeSymlink,
			Linkname: "target",
			PAXRecords: map[string]string{
				"SCHILY.xattr.user.linkattr": "linkvalue",
			},
		}

		err := extractor.extractEntry(header, nil)
		require.NoError(t, err)

		info, err := mockWriter.Stat("testlink")
		require.NoError(t, err)

		fileInfo, ok := info.(domain.FileInfo)
		require.True(t, ok, "Stat should return FileInfo")
		require.NotNil(t, fileInfo.Xattrs)
		assert.Equal(t, []byte("linkvalue"), fileInfo.Xattrs["user.linkattr"])
	})
}
