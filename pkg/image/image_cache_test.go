package image

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestImageCache_PutAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	// Create a mock image
	mockImg := &mockImage{
		layers: []v1.Layer{
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer1"}},
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer2"}},
		},
	}

	ref := "test:latest"

	// Put the image
	err = cache.Put(mockImg, ref)
	if err != nil {
		t.Fatalf("failed to put image: %v", err)
	}

	// Get the image
	metadata, err := cache.Get(ref)
	if err != nil {
		t.Fatalf("failed to get image: %v", err)
	}

	if metadata == nil {
		t.Fatal("expected metadata, got nil")
	}

	if metadata.Reference != ref {
		t.Errorf("expected reference %s, got %s", ref, metadata.Reference)
	}

	if len(metadata.LayerDigests) != 2 {
		t.Errorf("expected 2 layers, got %d", len(metadata.LayerDigests))
	}
}

func TestImageCache_Has(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	ref := "test:latest"

	// Should not have the image initially
	if cache.Has(ref) {
		t.Error("expected Has to return false for non-existent image")
	}

	// Put the image
	mockImg := &mockImage{layers: []v1.Layer{}}
	err = cache.Put(mockImg, ref)
	if err != nil {
		t.Fatalf("failed to put image: %v", err)
	}

	// Should have the image now
	if !cache.Has(ref) {
		t.Error("expected Has to return true for cached image")
	}
}

func TestImageCache_List(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	// List should be empty initially
	images, err := cache.List()
	if err != nil {
		t.Fatalf("failed to list images: %v", err)
	}
	if len(images) != 0 {
		t.Errorf("expected 0 images, got %d", len(images))
	}

	// Add some images
	mockImg := &mockImage{layers: []v1.Layer{}}
	refs := []string{"test1:latest", "test2:v1.0", "test3:stable"}
	for _, ref := range refs {
		err = cache.Put(mockImg, ref)
		if err != nil {
			t.Fatalf("failed to put image %s: %v", ref, err)
		}
	}

	// List should have all images
	images, err = cache.List()
	if err != nil {
		t.Fatalf("failed to list images: %v", err)
	}
	if len(images) != len(refs) {
		t.Errorf("expected %d images, got %d", len(refs), len(images))
	}
}

func TestImageCache_Remove(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	ref := "test:latest"
	mockImg := &mockImage{layers: []v1.Layer{}}

	// Put the image
	err = cache.Put(mockImg, ref)
	if err != nil {
		t.Fatalf("failed to put image: %v", err)
	}

	// Remove the image
	metadata, err := cache.Remove(ref)
	if err != nil {
		t.Fatalf("failed to remove image: %v", err)
	}

	if metadata == nil {
		t.Fatal("expected metadata from remove, got nil")
	}

	if metadata.Reference != ref {
		t.Errorf("expected reference %s, got %s", ref, metadata.Reference)
	}

	// Should not have the image anymore
	if cache.Has(ref) {
		t.Error("expected Has to return false after removal")
	}
}

func TestImageCache_GetLayerReferences(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	// Create images with overlapping layers
	img1 := &mockImage{
		layers: []v1.Layer{
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer1"}},
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer2"}},
		},
	}
	img2 := &mockImage{
		layers: []v1.Layer{
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer2"}}, // shared with img1
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer3"}},
		},
	}

	err = cache.Put(img1, "test1:latest")
	if err != nil {
		t.Fatalf("failed to put image1: %v", err)
	}

	err = cache.Put(img2, "test2:latest")
	if err != nil {
		t.Fatalf("failed to put image2: %v", err)
	}

	// Get layer references
	refs, err := cache.GetLayerReferences()
	if err != nil {
		t.Fatalf("failed to get layer references: %v", err)
	}

	// layer1 should have 1 reference
	if refs["sha256:layer1"] != 1 {
		t.Errorf("expected layer1 to have 1 reference, got %d", refs["sha256:layer1"])
	}

	// layer2 should have 2 references
	if refs["sha256:layer2"] != 2 {
		t.Errorf("expected layer2 to have 2 references, got %d", refs["sha256:layer2"])
	}

	// layer3 should have 1 reference
	if refs["sha256:layer3"] != 1 {
		t.Errorf("expected layer3 to have 1 reference, got %d", refs["sha256:layer3"])
	}
}

func TestImageCache_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	// Add some images
	mockImg := &mockImage{layers: []v1.Layer{}}
	refs := []string{"test1:latest", "test2:v1.0"}
	for _, ref := range refs {
		err = cache.Put(mockImg, ref)
		if err != nil {
			t.Fatalf("failed to put image %s: %v", ref, err)
		}
	}

	// Clear the cache
	err = cache.Clear()
	if err != nil {
		t.Fatalf("failed to clear cache: %v", err)
	}

	// List should be empty
	images, err := cache.List()
	if err != nil {
		t.Fatalf("failed to list images: %v", err)
	}
	if len(images) != 0 {
		t.Errorf("expected 0 images after clear, got %d", len(images))
	}
}

func TestImageCache_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	// Add images with different layers
	img1 := &mockImage{
		layers: []v1.Layer{
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer1"}},
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer2"}},
		},
	}
	img2 := &mockImage{
		layers: []v1.Layer{
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer2"}}, // shared
			&mockLayer{digest: v1.Hash{Algorithm: "sha256", Hex: "layer3"}},
		},
	}

	err = cache.Put(img1, "test1:latest")
	if err != nil {
		t.Fatalf("failed to put image1: %v", err)
	}

	// Wait a bit to ensure different timestamps
	time.Sleep(10 * time.Millisecond)

	err = cache.Put(img2, "test2:latest")
	if err != nil {
		t.Fatalf("failed to put image2: %v", err)
	}

	// Get stats
	stats, err := cache.Stats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}

	if stats.TotalImages != 2 {
		t.Errorf("expected 2 images, got %d", stats.TotalImages)
	}

	// Should have 3 unique layers (layer1, layer2, layer3)
	if stats.TotalLayers != 3 {
		t.Errorf("expected 3 unique layers, got %d", stats.TotalLayers)
	}

	if stats.OldestImage.IsZero() || stats.NewestImage.IsZero() {
		t.Error("expected non-zero timestamps")
	}

	if !stats.NewestImage.After(stats.OldestImage) {
		t.Error("expected newest image to be after oldest image")
	}
}

func TestImageCache_MetadataPath(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create image cache: %v", err)
	}

	ref := "docker.io/library/alpine:latest"
	path := cache.metadataPath(ref)

	// Path should be in the images directory
	expectedPrefix := filepath.Join(tmpDir, "images") + string(filepath.Separator)
	if !strings.HasPrefix(path, expectedPrefix) && path != filepath.Join(tmpDir, "images") {
		t.Errorf("expected path to start with %s, got %s", expectedPrefix, path)
	}

	// Path should have .json extension
	if filepath.Ext(path) != ".json" {
		t.Errorf("expected .json extension, got %s", filepath.Ext(path))
	}

	// Same reference should always produce same path
	path2 := cache.metadataPath(ref)
	if path != path2 {
		t.Errorf("expected consistent path for same reference")
	}

	// Different references should produce different paths
	path3 := cache.metadataPath("different:ref")
	if path == path3 {
		t.Errorf("expected different paths for different references")
	}
}
