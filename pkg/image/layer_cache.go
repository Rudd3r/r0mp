package image

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// LayerCache provides content-addressed storage for image layers
type LayerCache struct {
	dir string
	mu  sync.RWMutex
}

// NewLayerCache creates a new layer cache in the specified directory
func NewLayerCache(cacheDir string) (*LayerCache, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &LayerCache{
		dir: cacheDir,
	}, nil
}

// GetLayer retrieves a layer from the cache if it exists
// Returns a ReadCloser for the layer data, or nil if not cached
func (c *LayerCache) GetLayer(digest v1.Hash) (io.ReadCloser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.layerPath(digest)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil // Not in cache
	} else if err != nil {
		return nil, fmt.Errorf("failed to stat cache file: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open cached layer: %w", err)
	}

	return f, nil
}

// HasLayer checks if a layer exists in the cache without opening it
func (c *LayerCache) HasLayer(digest v1.Hash) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.layerPath(digest)
	_, err := os.Stat(path)
	return err == nil
}

// GetOrFetchLayer retrieves a layer from cache or fetches it using the provided function
// This is a convenience method that handles cache logic
func (c *LayerCache) GetOrFetchLayer(digest v1.Hash, fetchFunc func() (io.ReadCloser, error)) (io.ReadCloser, bool, error) {
	cached, err := c.GetLayer(digest)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check cache: %w", err)
	}
	if cached != nil {
		return cached, true, nil // Cache hit
	}

	// Fetch from source
	data, err := fetchFunc()
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch layer: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Write directly to cache file while computing hash (single pass)
	path := c.layerPath(digest)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		_ = data.Close()
		return nil, false, fmt.Errorf("failed to create cache directory: %w", err)
	}

	tmpPath := path + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		_ = data.Close()
		return nil, false, fmt.Errorf("failed to create cache file: %w", err)
	}
	defer func() { _ = os.Remove(tmpPath) }() // Clean up temp file on error

	hash := sha256.New()
	writer := io.MultiWriter(tmpFile, hash)

	if _, err := io.Copy(writer, data); err != nil {
		_ = data.Close()
		_ = tmpFile.Close()
		return nil, false, fmt.Errorf("failed to write layer data: %w", err)
	}
	_ = data.Close()

	if err := tmpFile.Close(); err != nil {
		return nil, false, fmt.Errorf("failed to close cache file: %w", err)
	}

	computedDigest := v1.Hash{
		Algorithm: "sha256",
		Hex:       fmt.Sprintf("%x", hash.Sum(nil)),
	}

	if computedDigest.String() != digest.String() {
		return nil, false, fmt.Errorf("digest mismatch: expected %s, got %s", digest, computedDigest)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return nil, false, fmt.Errorf("failed to rename cache file: %w", err)
	}

	// Open and return the cached file
	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open cached layer: %w", err)
	}

	return f, false, nil
}

// layerPath returns the filesystem path for a layer digest
// Uses a two-level directory structure to avoid too many files in one directory
func (c *LayerCache) layerPath(digest v1.Hash) string {
	hex := strings.TrimPrefix(digest.Hex, "sha256:")

	// Use first 2 chars as first level, next 2 as second level
	if len(hex) >= 4 {
		return filepath.Join(c.dir, hex[0:2], hex[2:4], hex)
	}

	// Fallback for short hashes
	return filepath.Join(c.dir, hex)
}

// CacheStats provides statistics about the cache
type CacheStats struct {
	TotalLayers int
	TotalSize   int64
	OldestLayer time.Time
	NewestLayer time.Time
}

// Stats returns statistics about the cache
func (c *LayerCache) Stats() (*CacheStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &CacheStats{}

	err := filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || strings.HasSuffix(path, ".tmp") {
			return nil
		}

		stats.TotalLayers++
		stats.TotalSize += info.Size()

		modTime := info.ModTime()
		if stats.OldestLayer.IsZero() || modTime.Before(stats.OldestLayer) {
			stats.OldestLayer = modTime
		}
		if stats.NewestLayer.IsZero() || modTime.After(stats.NewestLayer) {
			stats.NewestLayer = modTime
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk cache directory: %w", err)
	}

	return stats, nil
}

// cleanEmptyDirs removes empty directories in the cache
func (c *LayerCache) cleanEmptyDirs() {
	_ = filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || path == c.dir {
			return nil
		}
		_ = os.Remove(path)
		return nil
	})
}

// GetCacheDir returns the cache directory path
func (c *LayerCache) GetCacheDir() string {
	return c.dir
}

// RemoveLayer removes a specific layer from the cache
func (c *LayerCache) RemoveLayer(digest v1.Hash) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.layerPath(digest)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to stat layer file: %w", err)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove layer: %w", err)
	}

	c.cleanEmptyDirs()
	return nil
}

// GetAllLayerDigests returns a list of all layer digests currently in the cache
func (c *LayerCache) GetAllLayerDigests() ([]v1.Hash, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var digests []v1.Hash

	err := filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || strings.HasSuffix(path, ".tmp") {
			return nil
		}

		filename := filepath.Base(path)
		if len(filename) > 0 {
			digests = append(digests, v1.Hash{
				Algorithm: "sha256",
				Hex:       filename,
			})
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk cache directory: %w", err)
	}

	return digests, nil
}
