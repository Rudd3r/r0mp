package image

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ImageMetadata contains cached metadata about an image
type ImageMetadata struct {
	Reference    string    `json:"reference"`
	Digest       string    `json:"digest"`
	Manifest     []byte    `json:"manifest"`
	Config       []byte    `json:"config"`
	LayerDigests []string  `json:"layer_digests"`
	MediaType    string    `json:"media_type"`
	Size         int64     `json:"size"`
	CachedAt     time.Time `json:"cached_at"`
	LastAccessed time.Time `json:"last_accessed"`
}

// ImageCache manages cached image metadata
type ImageCache struct {
	dir string
	mu  sync.RWMutex
}

// NewImageCache creates a new image cache in the specified directory
func NewImageCache(cacheDir string) (*ImageCache, error) {
	imagesDir := filepath.Join(cacheDir, "images")
	if err := os.MkdirAll(imagesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create images directory: %w", err)
	}
	return &ImageCache{
		dir: imagesDir,
	}, nil
}

// Put stores image metadata in the cache
func (c *ImageCache) Put(img v1.Image, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("failed to get image digest: %w", err)
	}

	manifest, err := img.RawManifest()
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	config, err := img.RawConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get layers: %w", err)
	}

	layerDigests := make([]string, len(layers))
	for i, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			return fmt.Errorf("failed to get layer digest: %w", err)
		}
		layerDigests[i] = layerDigest.String()
	}

	mediaType, err := img.MediaType()
	if err != nil {
		return fmt.Errorf("failed to get media type: %w", err)
	}

	size, err := img.Size()
	if err != nil {
		return fmt.Errorf("failed to get size: %w", err)
	}

	metadata := &ImageMetadata{
		Reference:    ref,
		Digest:       digest.String(),
		Manifest:     manifest,
		Config:       config,
		LayerDigests: layerDigests,
		MediaType:    string(mediaType),
		Size:         size,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}

	return c.writeMetadata(metadata)
}

// Get retrieves image metadata from the cache by reference
func (c *ImageCache) Get(ref string) (*ImageMetadata, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.metadataPath(ref)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not in cache
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata ImageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	go c.updateLastAccessed(ref)

	return &metadata, nil
}

// Has checks if an image is cached by reference
func (c *ImageCache) Has(ref string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.metadataPath(ref)
	_, err := os.Stat(path)
	return err == nil
}

// List returns all cached image metadata
func (c *ImageCache) List() ([]*ImageMetadata, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	files, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}

	var images []*ImageMetadata
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(c.dir, file.Name()))
		if err != nil {
			continue // Skip files we can't read
		}

		var metadata ImageMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			continue // Skip files we can't parse
		}

		images = append(images, &metadata)
	}

	return images, nil
}

// Remove deletes image metadata from the cache
func (c *ImageCache) Remove(ref string) (*ImageMetadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.metadataPath(ref)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("image not found in cache: %s", ref)
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata ImageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("failed to remove metadata: %w", err)
	}

	return &metadata, nil
}

// GetLayerReferences returns a map of layer digests to the number of images using them
func (c *ImageCache) GetLayerReferences() (map[string]int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	images, err := c.listUnlocked()
	if err != nil {
		return nil, err
	}

	refCounts := make(map[string]int)
	for _, img := range images {
		for _, layerDigest := range img.LayerDigests {
			refCounts[layerDigest]++
		}
	}

	return refCounts, nil
}

// Clear removes all cached image metadata
func (c *ImageCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	files, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		path := filepath.Join(c.dir, file.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}

	return nil
}

// metadataPath returns the filesystem path for image metadata
func (c *ImageCache) metadataPath(ref string) string {
	hash := sha256.Sum256([]byte(ref))
	filename := fmt.Sprintf("%x.json", hash[:16])
	return filepath.Join(c.dir, filename)
}

// writeMetadata writes image metadata to disk
func (c *ImageCache) writeMetadata(metadata *ImageMetadata) error {
	path := c.metadataPath(metadata.Reference)

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err = os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// updateLastAccessed updates the last accessed time for an image
func (c *ImageCache) updateLastAccessed(ref string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.metadataPath(ref)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var metadata ImageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return
	}

	metadata.LastAccessed = time.Now()
	_ = c.writeMetadata(&metadata)
}

// listUnlocked returns all cached image metadata without locking (caller must hold lock)
func (c *ImageCache) listUnlocked() ([]*ImageMetadata, error) {
	files, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}

	var images []*ImageMetadata
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(c.dir, file.Name()))
		if err != nil {
			continue
		}

		var metadata ImageMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			continue
		}

		images = append(images, &metadata)
	}

	return images, nil
}

// Stats provides statistics about the image cache
type ImageCacheStats struct {
	TotalImages int
	TotalLayers int
	OldestImage time.Time
	NewestImage time.Time
}

// Stats returns statistics about the image cache
func (c *ImageCache) Stats() (*ImageCacheStats, error) {
	images, err := c.List()
	if err != nil {
		return nil, err
	}

	stats := &ImageCacheStats{
		TotalImages: len(images),
	}

	layerSet := make(map[string]bool)
	for _, img := range images {
		for _, digest := range img.LayerDigests {
			layerSet[digest] = true
		}

		if stats.OldestImage.IsZero() || img.CachedAt.Before(stats.OldestImage) {
			stats.OldestImage = img.CachedAt
		}
		if stats.NewestImage.IsZero() || img.CachedAt.After(stats.NewestImage) {
			stats.NewestImage = img.CachedAt
		}
	}

	stats.TotalLayers = len(layerSet)

	return stats, nil
}
