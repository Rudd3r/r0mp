package image

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestTar creates a minimal docker save tar file for testing
func createTestTar(t *testing.T, tags []string) string {
	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "test.tar")

	f, err := os.Create(tarPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	tw := tar.NewWriter(f)
	defer func() { _ = tw.Close() }()

	// Create a minimal manifest.json
	manifest := []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}{
		{
			Config:   "config.json",
			RepoTags: tags,
			Layers:   []string{"layer.tar"},
		},
	}

	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)

	// Write manifest.json
	err = tw.WriteHeader(&tar.Header{
		Name: "manifest.json",
		Mode: 0644,
		Size: int64(len(manifestBytes)),
	})
	require.NoError(t, err)
	_, err = tw.Write(manifestBytes)
	require.NoError(t, err)

	// Create a minimal config.json
	config := v1.ConfigFile{
		Architecture: "amd64",
		OS:           "linux",
		RootFS: v1.RootFS{
			Type:    "layers",
			DiffIDs: []v1.Hash{{Algorithm: "sha256", Hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
		},
	}
	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	err = tw.WriteHeader(&tar.Header{
		Name: "config.json",
		Mode: 0644,
		Size: int64(len(configBytes)),
	})
	require.NoError(t, err)
	_, err = tw.Write(configBytes)
	require.NoError(t, err)

	// Create a minimal layer.tar (empty gzipped tar)
	layerPath := filepath.Join(tmpDir, "layer_tmp.tar.gz")
	lf, err := os.Create(layerPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(lf)
	ltw := tar.NewWriter(gw)
	_ = ltw.Close()
	_ = gw.Close()
	_ = lf.Close()

	layerData, err := os.ReadFile(layerPath)
	require.NoError(t, err)

	err = tw.WriteHeader(&tar.Header{
		Name: "layer.tar",
		Mode: 0644,
		Size: int64(len(layerData)),
	})
	require.NoError(t, err)
	_, err = tw.Write(layerData)
	require.NoError(t, err)

	return tarPath
}

func TestImportFromTar_SingleImage(t *testing.T) {
	// Create a test tar with a single tagged image
	tarPath := createTestTar(t, []string{"test:latest"})

	// Create a cache client
	tmpDir := t.TempDir()
	layerCache, err := NewLayerCache(filepath.Join(tmpDir, "layers"))
	require.NoError(t, err)

	imageCache, err := NewImageCache(tmpDir)
	require.NoError(t, err)

	client := NewCacheClient(
		slog.Default(),
		NewClient(),
		layerCache,
		imageCache,
	)

	// Import the image
	img, err := client.ImportFromTar(tarPath, "mytest:v1")
	require.NoError(t, err)
	assert.NotNil(t, img)

	// Verify the image was cached
	cached := imageCache.Has("mytest:v1")
	assert.True(t, cached, "image should be cached")

	// Verify we can retrieve metadata
	metadata, err := imageCache.Get("mytest:v1")
	require.NoError(t, err)
	assert.NotNil(t, metadata)
	assert.Equal(t, "mytest:v1", metadata.Reference)
}

func TestImportMultipleFromTar(t *testing.T) {
	// Create a test tar with multiple tags
	tarPath := createTestTar(t, []string{"test:latest", "test:v1", "test:stable"})

	// Create a cache client
	tmpDir := t.TempDir()
	layerCache, err := NewLayerCache(filepath.Join(tmpDir, "layers"))
	require.NoError(t, err)

	imageCache, err := NewImageCache(tmpDir)
	require.NoError(t, err)

	client := NewCacheClient(
		slog.Default(),
		NewClient(),
		layerCache,
		imageCache,
	)

	// Import all images
	results, err := client.ImportMultipleFromTar(tarPath)
	require.NoError(t, err)
	assert.Len(t, results, 3, "should import 3 tagged images")

	// Verify all images are present
	assert.Contains(t, results, "test:latest")
	assert.Contains(t, results, "test:v1")
	assert.Contains(t, results, "test:stable")

	// Verify all images are cached
	assert.True(t, imageCache.Has("test:latest"))
	assert.True(t, imageCache.Has("test:v1"))
	assert.True(t, imageCache.Has("test:stable"))
}

func TestImportFromTar_NonexistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	layerCache, err := NewLayerCache(filepath.Join(tmpDir, "layers"))
	require.NoError(t, err)

	imageCache, err := NewImageCache(tmpDir)
	require.NoError(t, err)

	client := NewCacheClient(
		slog.Default(),
		NewClient(),
		layerCache,
		imageCache,
	)

	// Try to import a nonexistent file
	_, err = client.ImportFromTar("/nonexistent/path.tar", "test:latest")
	assert.Error(t, err, "should error on nonexistent file")
}

func TestImportFromTar_InvalidTar(t *testing.T) {
	// Create an invalid tar file
	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "invalid.tar")
	err := os.WriteFile(tarPath, []byte("not a tar file"), 0644)
	require.NoError(t, err)

	layerCache, err := NewLayerCache(filepath.Join(tmpDir, "layers"))
	require.NoError(t, err)

	imageCache, err := NewImageCache(tmpDir)
	require.NoError(t, err)

	client := NewCacheClient(
		slog.Default(),
		NewClient(),
		layerCache,
		imageCache,
	)

	// Try to import the invalid tar
	_, err = client.ImportFromTar(tarPath, "test:latest")
	assert.Error(t, err, "should error on invalid tar")
}

func TestImportFromTar_Stdin(t *testing.T) {
	// Create a test tar
	tarPath := createTestTar(t, []string{"test:stdin"})

	// Read the tar file
	tarData, err := os.ReadFile(tarPath)
	require.NoError(t, err)

	// Save original stdin and create a pipe
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r

	// Write tar data to the pipe in a goroutine
	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.Write(tarData)
	}()

	// Create a cache client
	tmpDir := t.TempDir()
	layerCache, err := NewLayerCache(filepath.Join(tmpDir, "layers"))
	require.NoError(t, err)

	imageCache, err := NewImageCache(tmpDir)
	require.NoError(t, err)

	client := NewCacheClient(
		slog.Default(),
		NewClient(),
		layerCache,
		imageCache,
	)

	// Import from stdin using "-"
	img, err := client.ImportFromTar("-", "mystdin:v1")
	require.NoError(t, err)
	assert.NotNil(t, img)

	// Verify the image was cached
	cached := imageCache.Has("mystdin:v1")
	assert.True(t, cached, "image should be cached")
}

func TestImportMultipleFromTar_Stdin(t *testing.T) {
	// Create a test tar with multiple tags
	tarPath := createTestTar(t, []string{"stdin:v1", "stdin:v2", "stdin:latest"})

	// Read the tar file
	tarData, err := os.ReadFile(tarPath)
	require.NoError(t, err)

	// Save original stdin and create a pipe
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r

	// Write tar data to the pipe in a goroutine
	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.Write(tarData)
	}()

	// Create a cache client
	tmpDir := t.TempDir()
	layerCache, err := NewLayerCache(filepath.Join(tmpDir, "layers"))
	require.NoError(t, err)

	imageCache, err := NewImageCache(tmpDir)
	require.NoError(t, err)

	client := NewCacheClient(
		slog.Default(),
		NewClient(),
		layerCache,
		imageCache,
	)

	// Import all images from stdin
	results, err := client.ImportMultipleFromTar("-")
	require.NoError(t, err)
	assert.Len(t, results, 3, "should import 3 tagged images")

	// Verify all images are cached
	assert.True(t, imageCache.Has("stdin:v1"))
	assert.True(t, imageCache.Has("stdin:v2"))
	assert.True(t, imageCache.Has("stdin:latest"))
}
