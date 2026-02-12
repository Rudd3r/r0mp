package image

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestNewLayerCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")

	cache, err := NewLayerCache(cacheDir)
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	if cache.GetCacheDir() != cacheDir {
		t.Errorf("Expected cache dir %s, got %s", cacheDir, cache.GetCacheDir())
	}

	// Verify directory was created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Error("Cache directory was not created")
	}
}

func TestHasLayer(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	content := []byte("test content")
	digest := computeDigest(content)

	// Should not exist initially
	if cache.HasLayer(digest) {
		t.Error("HasLayer returned true for non-existent layer")
	}

	// Add layer using GetOrFetchLayer
	rc, _, err := cache.GetOrFetchLayer(digest, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	})
	if err != nil {
		t.Fatalf("GetOrFetchLayer failed: %v", err)
	}
	_ = rc.Close()

	// Should exist now
	if !cache.HasLayer(digest) {
		t.Error("HasLayer returned false for existing layer")
	}
}

func TestGetLayer_NotCached(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	// Try to get non-existent layer
	fakeDigest := v1.Hash{
		Algorithm: "sha256",
		Hex:       "0000000000000000000000000000000000000000000000000000000000000000",
	}

	rc, err := cache.GetLayer(fakeDigest)
	if err != nil {
		t.Fatalf("GetLayer failed: %v", err)
	}
	if rc != nil {
		t.Error("GetLayer should return nil for non-cached layer")
	}
}

func TestGetOrFetchLayer_DigestMismatch(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	content := []byte("test content")
	wrongDigest := v1.Hash{
		Algorithm: "sha256",
		Hex:       "1111111111111111111111111111111111111111111111111111111111111111",
	}

	// Should fail due to digest mismatch
	_, _, err = cache.GetOrFetchLayer(wrongDigest, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	})
	if err == nil {
		t.Fatal("GetOrFetchLayer should fail with wrong digest")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("Expected digest mismatch error, got: %v", err)
	}
}

func TestGetOrFetchLayer_CacheHit(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	content := []byte("cached content")
	digest := computeDigest(content)

	// Pre-populate cache using GetOrFetchLayer
	rc1, _, err := cache.GetOrFetchLayer(digest, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	})
	if err != nil {
		t.Fatalf("GetOrFetchLayer failed: %v", err)
	}
	_ = rc1.Close()

	// Fetch should hit cache now
	fetchCalled := false
	rc, cached, err := cache.GetOrFetchLayer(digest, func() (io.ReadCloser, error) {
		fetchCalled = true
		return nil, fmt.Errorf("should not be called")
	})
	if err != nil {
		t.Fatalf("GetOrFetchLayer failed: %v", err)
	}
	if !cached {
		t.Error("Expected cache hit")
	}
	if fetchCalled {
		t.Error("Fetch function should not be called on cache hit")
	}
	defer func() { _ = rc.Close() }()

	// Verify content
	retrieved, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}
	if !bytes.Equal(content, retrieved) {
		t.Error("Content mismatch")
	}
}

func TestGetOrFetchLayer_CacheMiss(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	content := []byte("fetched content")
	digest := computeDigest(content)

	// Fetch should miss cache and call fetch function
	fetchCalled := false
	rc, cached, err := cache.GetOrFetchLayer(digest, func() (io.ReadCloser, error) {
		fetchCalled = true
		return io.NopCloser(bytes.NewReader(content)), nil
	})
	if err != nil {
		t.Fatalf("GetOrFetchLayer failed: %v", err)
	}
	if cached {
		t.Error("Expected cache miss")
	}
	if !fetchCalled {
		t.Error("Fetch function should be called on cache miss")
	}
	defer func() { _ = rc.Close() }()

	// Verify content
	retrieved, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}
	if !bytes.Equal(content, retrieved) {
		t.Error("Content mismatch")
	}

	// Verify layer was cached (should be synchronous now)
	if !cache.HasLayer(digest) {
		t.Error("Layer should be cached after fetch")
	}
}

func TestStats(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	// Empty cache
	stats, err := cache.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.TotalLayers != 0 {
		t.Errorf("Expected 0 layers, got %d", stats.TotalLayers)
	}
	if stats.TotalSize != 0 {
		t.Errorf("Expected 0 size, got %d", stats.TotalSize)
	}

	// Add some layers
	layers := [][]byte{
		[]byte("layer 1 content"),
		[]byte("layer 2 content with more data"),
		[]byte("layer 3"),
	}

	expectedSize := int64(0)
	for _, content := range layers {
		digest := computeDigest(content)
		rc, _, err := cache.GetOrFetchLayer(digest, func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(content)), nil
		})
		if err != nil {
			t.Fatalf("GetOrFetchLayer failed: %v", err)
		}
		_ = rc.Close()
		expectedSize += int64(len(content))
	}

	// Check stats
	stats, err = cache.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.TotalLayers != len(layers) {
		t.Errorf("Expected %d layers, got %d", len(layers), stats.TotalLayers)
	}
	if stats.TotalSize != expectedSize {
		t.Errorf("Expected size %d, got %d", expectedSize, stats.TotalSize)
	}
}

// Helper function to compute SHA256 digest
func computeDigest(data []byte) v1.Hash {
	return v1.Hash{
		Algorithm: "sha256",
		Hex:       fmt.Sprintf("%x", sha256Sum(data)),
	}
}

func sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
