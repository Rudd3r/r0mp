package image

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// mockImage implements v1.Image for testing
type mockImage struct {
	layers []v1.Layer
}

func (m *mockImage) Layers() ([]v1.Layer, error) {
	return m.layers, nil
}

func (m *mockImage) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

func (m *mockImage) Size() (int64, error) {
	return 1234, nil
}

func (m *mockImage) ConfigName() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "confighash"}, nil
}

func (m *mockImage) ConfigFile() (*v1.ConfigFile, error) {
	return &v1.ConfigFile{}, nil
}

func (m *mockImage) RawConfigFile() ([]byte, error) {
	return []byte("{}"), nil
}

func (m *mockImage) Digest() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "imagehash"}, nil
}

func (m *mockImage) Manifest() (*v1.Manifest, error) {
	return &v1.Manifest{}, nil
}

func (m *mockImage) RawManifest() ([]byte, error) {
	return []byte("{}"), nil
}

func (m *mockImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	for _, layer := range m.layers {
		digest, err := layer.Digest()
		if err != nil {
			return nil, err
		}
		if digest.String() == h.String() {
			return layer, nil
		}
	}
	return nil, fmt.Errorf("layer not found")
}

func (m *mockImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	for _, layer := range m.layers {
		diffID, err := layer.DiffID()
		if err != nil {
			return nil, err
		}
		if diffID.String() == h.String() {
			return layer, nil
		}
	}
	return nil, fmt.Errorf("layer not found")
}

// mockLayer implements v1.Layer for testing
type mockLayer struct {
	content []byte
	digest  v1.Hash
	diffID  v1.Hash
	calls   *int // Track number of Compressed() calls
}

func newMockLayer(content []byte, calls *int) *mockLayer {
	hash := sha256.Sum256(content)
	return &mockLayer{
		content: content,
		digest:  v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", hash)},
		diffID:  v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", hash)},
		calls:   calls,
	}
}

func (m *mockLayer) Digest() (v1.Hash, error) {
	return m.digest, nil
}

func (m *mockLayer) DiffID() (v1.Hash, error) {
	return m.diffID, nil
}

func (m *mockLayer) Compressed() (io.ReadCloser, error) {
	if m.calls != nil {
		*m.calls++
	}
	return io.NopCloser(bytes.NewReader(m.content)), nil
}

func (m *mockLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.content)), nil
}

func (m *mockLayer) Size() (int64, error) {
	return int64(len(m.content)), nil
}

func (m *mockLayer) MediaType() (types.MediaType, error) {
	return types.DockerLayer, nil
}

func TestCachedImage_Layers(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Create mock layers
	layer1Content := []byte("layer 1 content")
	layer2Content := []byte("layer 2 content")

	var calls1, calls2 int
	mockLayers := []v1.Layer{
		newMockLayer(layer1Content, &calls1),
		newMockLayer(layer2Content, &calls2),
	}

	mockImg := &mockImage{layers: mockLayers}
	cachedImg := &cachedImage{
		image: mockImg,
		cache: cache,
	}

	layers, err := cachedImg.Layers()
	if err != nil {
		t.Fatalf("Failed to get layers: %v", err)
	}

	if len(layers) != 2 {
		t.Errorf("Expected 2 layers, got %d", len(layers))
	}

	for i, layer := range layers {
		if _, ok := layer.(*cachedLayer); !ok {
			t.Errorf("Layer %d is not a cachedLayer", i)
		}
	}
}

func TestCachedLayer_Compressed_Caching(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	content := []byte("test layer content")
	var compressedCalls int
	mockLayer := newMockLayer(content, &compressedCalls)

	cachedLayer := &cachedLayer{
		layer: mockLayer,
		cache: cache,
	}

	rc1, err := cachedLayer.Compressed()
	if err != nil {
		t.Fatalf("First Compressed() call failed: %v", err)
	}
	data1, err := io.ReadAll(rc1)
	_ = rc1.Close()
	if err != nil {
		t.Fatalf("Failed to read first result: %v", err)
	}

	if !bytes.Equal(content, data1) {
		t.Errorf("Content mismatch on first call")
	}

	if compressedCalls != 1 {
		t.Errorf("Expected 1 call to underlying Compressed(), got %d", compressedCalls)
	}

	rc2, err := cachedLayer.Compressed()
	if err != nil {
		t.Fatalf("Second Compressed() call failed: %v", err)
	}
	data2, err := io.ReadAll(rc2)
	_ = rc2.Close()
	if err != nil {
		t.Fatalf("Failed to read second result: %v", err)
	}

	if !bytes.Equal(content, data2) {
		t.Errorf("Content mismatch on second call")
	}

	if compressedCalls != 1 {
		t.Errorf("Expected 1 call to underlying Compressed() after caching, got %d", compressedCalls)
	}
}

func TestCachedLayer_PassthroughMethods(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	content := []byte("test content")
	mockLayer := newMockLayer(content, nil)

	cachedLayer := &cachedLayer{
		layer: mockLayer,
		cache: cache,
	}

	digest, err := cachedLayer.Digest()
	if err != nil {
		t.Errorf("Digest() failed: %v", err)
	}
	expectedDigest, _ := mockLayer.Digest()
	if digest.String() != expectedDigest.String() {
		t.Errorf("Digest mismatch: expected %s, got %s", expectedDigest, digest)
	}

	diffID, err := cachedLayer.DiffID()
	if err != nil {
		t.Errorf("DiffID() failed: %v", err)
	}
	expectedDiffID, _ := mockLayer.DiffID()
	if diffID.String() != expectedDiffID.String() {
		t.Errorf("DiffID mismatch: expected %s, got %s", expectedDiffID, diffID)
	}

	size, err := cachedLayer.Size()
	if err != nil {
		t.Errorf("Size() failed: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("Size mismatch: expected %d, got %d", len(content), size)
	}

	mediaType, err := cachedLayer.MediaType()
	if err != nil {
		t.Errorf("MediaType() failed: %v", err)
	}
	if mediaType != types.DockerLayer {
		t.Errorf("MediaType mismatch: expected %s, got %s", types.DockerLayer, mediaType)
	}
}

func TestCachedImage_LayerByDigest(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	content := []byte("test layer")
	mockLayer := newMockLayer(content, nil)
	mockImg := &mockImage{layers: []v1.Layer{mockLayer}}

	cachedImg := &cachedImage{
		image: mockImg,
		cache: cache,
	}

	digest, _ := mockLayer.Digest()
	layer, err := cachedImg.LayerByDigest(digest)
	if err != nil {
		t.Fatalf("LayerByDigest() failed: %v", err)
	}

	if _, ok := layer.(*cachedLayer); !ok {
		t.Error("LayerByDigest should return a cachedLayer")
	}
}

func TestCachedImage_LayerByDiffID(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	content := []byte("test layer")
	mockLayer := newMockLayer(content, nil)
	mockImg := &mockImage{layers: []v1.Layer{mockLayer}}

	cachedImg := &cachedImage{
		image: mockImg,
		cache: cache,
	}

	diffID, _ := mockLayer.DiffID()
	layer, err := cachedImg.LayerByDiffID(diffID)
	if err != nil {
		t.Fatalf("LayerByDiffID() failed: %v", err)
	}

	if _, ok := layer.(*cachedLayer); !ok {
		t.Error("LayerByDiffID should return a cachedLayer")
	}
}

func TestCachedImage_PassthroughMethods(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	mockImg := &mockImage{layers: []v1.Layer{}}
	cachedImg := &cachedImage{
		image: mockImg,
		cache: cache,
	}

	mediaType, err := cachedImg.MediaType()
	if err != nil {
		t.Errorf("MediaType() failed: %v", err)
	}
	if mediaType != types.DockerManifestSchema2 {
		t.Errorf("MediaType mismatch")
	}

	size, err := cachedImg.Size()
	if err != nil {
		t.Errorf("Size() failed: %v", err)
	}
	if size != 1234 {
		t.Errorf("Size mismatch")
	}

	digest, err := cachedImg.Digest()
	if err != nil {
		t.Errorf("Digest() failed: %v", err)
	}
	if digest.Hex != "imagehash" {
		t.Errorf("Digest mismatch")
	}
}

func TestNewCacheClient(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewLayerCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	imageCache, err := NewImageCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create image cache: %v", err)
	}

	// Note: We can't easily test registry.NewClient() without mocking,
	// so we'll just test the client wrapper structure
	log := slog.Default()
	client := NewCacheClient(log, nil, cache, imageCache)
	if client == nil {
		t.Error("NewClient returned nil")
	}

	if client.GetCache() != cache {
		t.Error("GetCache() doesn't return the same cache")
	}

	if client.GetImageCache() != imageCache {
		t.Error("GetImageCache() doesn't return the same image cache")
	}
}
