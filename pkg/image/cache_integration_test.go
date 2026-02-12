package image

import (
	"bytes"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TestIntegration_CachedImageWorkflow tests a complete workflow
// of pulling an image and accessing its layers multiple times
func TestIntegration_CachedImageWorkflow(t *testing.T) {
	// Setup cache
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Create mock layers with call tracking
	layer1Content := []byte("layer 1 content data")
	layer2Content := []byte("layer 2 content data with more bytes")
	layer3Content := []byte("layer 3")

	var calls1, calls2, calls3 int
	mockLayers := []v1.Layer{
		newMockLayer(layer1Content, &calls1),
		newMockLayer(layer2Content, &calls2),
		newMockLayer(layer3Content, &calls3),
	}

	// Create mock image
	mockImg := &mockImage{layers: mockLayers}

	// Wrap with caching
	cachedImg := &cachedImage{
		image: mockImg,
		cache: cache,
	}

	// First access - should download all layers
	t.Log("First access to layers...")
	layers1, err := cachedImg.Layers()
	if err != nil {
		t.Fatalf("Failed to get layers: %v", err)
	}

	if len(layers1) != 3 {
		t.Fatalf("Expected 3 layers, got %d", len(layers1))
	}

	// Access each layer's compressed data
	for i, layer := range layers1 {
		rc, err := layer.Compressed()
		if err != nil {
			t.Fatalf("Failed to get compressed data for layer %d: %v", i, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("Failed to read layer %d: %v", i, err)
		}

		// Verify content
		var expected []byte
		switch i {
		case 0:
			expected = layer1Content
		case 1:
			expected = layer2Content
		case 2:
			expected = layer3Content
		}

		if !bytes.Equal(data, expected) {
			t.Errorf("Content mismatch for layer %d", i)
		}
	}

	// All layers should have been called once
	if calls1 != 1 || calls2 != 1 || calls3 != 1 {
		t.Errorf("Expected 1 call per layer on first access, got %d, %d, %d",
			calls1, calls2, calls3)
	}

	// Verify all layers are cached
	for i, layer := range mockLayers {
		digest, _ := layer.Digest()
		if !cache.HasLayer(digest) {
			t.Errorf("Layer %d should be cached after first access", i)
		}
	}

	// Second access - should use cache for all layers
	t.Log("Second access to layers (should use cache)...")
	layers2, err := cachedImg.Layers()
	if err != nil {
		t.Fatalf("Failed to get layers on second access: %v", err)
	}

	// Access each layer again
	for i, layer := range layers2 {
		rc, err := layer.Compressed()
		if err != nil {
			t.Fatalf("Failed to get compressed data for layer %d: %v", i, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("Failed to read layer %d: %v", i, err)
		}

		// Verify content still matches
		var expected []byte
		switch i {
		case 0:
			expected = layer1Content
		case 1:
			expected = layer2Content
		case 2:
			expected = layer3Content
		}

		if !bytes.Equal(data, expected) {
			t.Errorf("Content mismatch for layer %d on second access", i)
		}
	}

	// Should still be only 1 call per layer (using cache)
	if calls1 != 1 || calls2 != 1 || calls3 != 1 {
		t.Errorf("Expected 1 call per layer total (cached on second access), got %d, %d, %d",
			calls1, calls2, calls3)
	}

	// Third access with LayerByDigest
	t.Log("Third access using LayerByDigest (should use cache)...")
	digest1, _ := mockLayers[0].Digest()
	layer, err := cachedImg.LayerByDigest(digest1)
	if err != nil {
		t.Fatalf("LayerByDigest failed: %v", err)
	}

	rc, err := layer.Compressed()
	if err != nil {
		t.Fatalf("Failed to get compressed data: %v", err)
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Failed to read layer: %v", err)
	}

	if !bytes.Equal(data, layer1Content) {
		t.Error("Content mismatch for LayerByDigest")
	}

	// Still should be only 1 call (cache hit)
	if calls1 != 1 {
		t.Errorf("Expected 1 call for layer 1 (cached), got %d", calls1)
	}

	// Verify cache statistics
	stats, err := cache.Stats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if stats.TotalLayers != 3 {
		t.Errorf("Expected 3 cached layers, got %d", stats.TotalLayers)
	}

	expectedSize := int64(len(layer1Content) + len(layer2Content) + len(layer3Content))
	if stats.TotalSize != expectedSize {
		t.Errorf("Expected total size %d, got %d", expectedSize, stats.TotalSize)
	}

	t.Logf("Cache stats: %d layers, %d bytes", stats.TotalLayers, stats.TotalSize)
	t.Log("Integration test passed: All layers cached and reused successfully")
}

// TestIntegration_MultipleImages tests caching behavior with multiple images
func TestIntegration_MultipleImages(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Create first image with 2 layers
	layer1 := newMockLayer([]byte("image1-layer1"), nil)
	layer2 := newMockLayer([]byte("image1-layer2"), nil)
	img1 := &cachedImage{
		image: &mockImage{layers: []v1.Layer{layer1, layer2}},
		cache: cache,
	}

	// Create second image with 2 layers (1 shared, 1 unique)
	layer3 := newMockLayer([]byte("image2-layer3"), nil)
	img2 := &cachedImage{
		image: &mockImage{layers: []v1.Layer{layer1, layer3}}, // Reuses layer1
		cache: cache,
	}

	// Access first image
	layers1, _ := img1.Layers()
	for _, layer := range layers1 {
		rc, _ := layer.Compressed()
		_, _ = io.ReadAll(rc)
		_ = rc.Close()
	}

	// Should have 2 layers cached
	stats, _ := cache.Stats()
	if stats.TotalLayers != 2 {
		t.Errorf("Expected 2 layers after first image, got %d", stats.TotalLayers)
	}

	// Access second image
	layers2, _ := img2.Layers()
	for _, layer := range layers2 {
		rc, _ := layer.Compressed()
		_, _ = io.ReadAll(rc)
		_ = rc.Close()
	}

	// Should have 3 layers cached (layer1 is shared)
	stats, _ = cache.Stats()
	if stats.TotalLayers != 3 {
		t.Errorf("Expected 3 unique layers total, got %d", stats.TotalLayers)
	}

	t.Log("Multiple images test passed: Shared layers reused successfully")
}

// TestIntegration_AllImageMethods tests that all v1.Image methods work correctly
func TestIntegration_AllImageMethods(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	layer := newMockLayer([]byte("test"), nil)
	mockImg := &mockImage{layers: []v1.Layer{layer}}
	cachedImg := &cachedImage{
		image: mockImg,
		cache: cache,
	}

	// Test all interface methods
	tests := []struct {
		name string
		test func() error
	}{
		{"Layers", func() error {
			_, err := cachedImg.Layers()
			return err
		}},
		{"MediaType", func() error {
			mt, err := cachedImg.MediaType()
			if mt != types.DockerManifestSchema2 {
				t.Error("MediaType mismatch")
			}
			return err
		}},
		{"Size", func() error {
			_, err := cachedImg.Size()
			return err
		}},
		{"ConfigName", func() error {
			_, err := cachedImg.ConfigName()
			return err
		}},
		{"ConfigFile", func() error {
			_, err := cachedImg.ConfigFile()
			return err
		}},
		{"RawConfigFile", func() error {
			_, err := cachedImg.RawConfigFile()
			return err
		}},
		{"Digest", func() error {
			_, err := cachedImg.Digest()
			return err
		}},
		{"Manifest", func() error {
			_, err := cachedImg.Manifest()
			return err
		}},
		{"RawManifest", func() error {
			_, err := cachedImg.RawManifest()
			return err
		}},
		{"LayerByDigest", func() error {
			digest, _ := layer.Digest()
			_, err := cachedImg.LayerByDigest(digest)
			return err
		}},
		{"LayerByDiffID", func() error {
			diffID, _ := layer.DiffID()
			_, err := cachedImg.LayerByDiffID(diffID)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.test(); err != nil {
				t.Errorf("%s failed: %v", tt.name, err)
			}
		})
	}

	t.Log("All v1.Image methods working correctly")
}
