package image

import (
	"fmt"
	"log/slog"

	"github.com/Rudd3r/r0mp/pkg/domain"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// CacheClient wraps a registry client and provides transparent layer caching
type CacheClient struct {
	log            *slog.Logger
	registryClient *Client
	cache          *LayerCache
	imageCache     *ImageCache
}

// NewCacheClient creates a new caching client that wraps a registry client
func NewCacheClient(log *slog.Logger, registryClient *Client, cache *LayerCache, imageCache *ImageCache) *CacheClient {
	return &CacheClient{
		log:            log,
		registryClient: registryClient,
		cache:          cache,
		imageCache:     imageCache,
	}
}

// NewDefaultCachedClient creates a new caching client that wraps a registry client
func NewDefaultCachedClient(log *slog.Logger) (*CacheClient, error) {
	cacheDir, err := domain.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("could not create layer cache, %w", err)
	}
	layerCache, err := NewLayerCache(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("could not create layer cache, %w", err)
	}
	imageCache, err := NewImageCache(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("could not create image cache, %w", err)
	}
	return &CacheClient{
		log:            log,
		registryClient: NewClient(),
		cache:          layerCache,
		imageCache:     imageCache,
	}, nil
}

// Pull downloads an image from a registry and returns a cached image descriptor.
// The returned image automatically caches layers when they are accessed.
// ref should be in the format: [registry/]repository[:tag|@digest]
// Examples:
//   - "alpine:latest"
//   - "ubuntu:22.04"
//   - "docker.io/library/nginx:1.25"
//   - "ghcr.io/myorg/myapp:v1.0.0"
func (c *CacheClient) Pull(ref string) (v1.Image, error) {
	// Pull the image using the wrapped registry client
	img, err := c.registryClient.Pull(ref)
	if err != nil {
		return nil, err
	}

	// Cache the image metadata
	if err := c.imageCache.Put(img, ref); err != nil {
		c.log.Warn("failed to cache image metadata", "error", err)
	}

	// Wrap the image to provide caching
	return &cachedImage{
		image: img,
		cache: c.cache,
	}, nil
}

// ListImages returns a list of all cached images
func (c *CacheClient) ListImages() ([]*ImageMetadata, error) {
	return c.imageCache.List()
}

// RemoveImage removes an image from the cache and deletes any layers
// that are not referenced by other cached images
func (c *CacheClient) RemoveImage(ref string) error {
	metadata, err := c.imageCache.Remove(ref)
	if err != nil {
		return fmt.Errorf("failed to remove image metadata: %w", err)
	}

	layerRefs, err := c.imageCache.GetLayerReferences()
	if err != nil {
		return fmt.Errorf("failed to get layer references: %w", err)
	}

	for _, layerDigest := range metadata.LayerDigests {
		if layerRefs[layerDigest] == 0 {
			digest, err := v1.NewHash(layerDigest)
			if err != nil {
				c.log.Warn("failed to parse layer digest", "digest", layerDigest, "error", err)
				continue
			}
			if err := c.cache.RemoveLayer(digest); err != nil {
				c.log.Warn("failed to remove layer", "digest", layerDigest, "error", err)
			}
		}
	}

	return nil
}

// GetCache returns the underlying layer cache for direct access if needed
func (c *CacheClient) GetCache() *LayerCache {
	return c.cache
}

// GetImageCache returns the underlying image cache for direct access if needed
func (c *CacheClient) GetImageCache() *ImageCache {
	return c.imageCache
}

// GetRegistryClient returns the underlying registry client for direct access if needed
func (c *CacheClient) GetRegistryClient() *Client {
	return c.registryClient
}

// ImportFromTar imports a docker image tar archive (from `docker save`) into the cache.
// The tar file should contain a complete image with layers and metadata in OCI/Docker format.
// ref is the reference name to store the image as (e.g., "alpine:latest").
// Returns the imported image wrapped with caching support.
//
// Stdin support: Use "-" or empty string as tarPath to read from stdin.
//
// Examples:
//
//	# Import from file with custom tag
//	img, err := client.ImportFromTar("alpine.tar", "alpine:custom")
//
//	# Import from stdin
//	img, err := client.ImportFromTar("-", "alpine:piped")
func (c *CacheClient) ImportFromTar(tarPath string, ref string) (v1.Image, error) {
	// Note: tarball.ImageFromPath is imported from go-containerregistry
	// The actual import is implemented in a separate file to keep dependencies clean
	return importImageFromTar(c, tarPath, ref)
}

// ImportMultipleFromTar imports all images from a docker tar archive (from `docker save`) into the cache.
// Docker save can bundle multiple images into one tar file. This method imports all of them.
// Each image is stored with its original tag name from the tar file.
// Returns a map of reference names to imported images.
//
// Stdin support: Use "-" or empty string as tarPath to read from stdin.
//
// Examples:
//
//	# Import multiple images from file
//	images, err := client.ImportMultipleFromTar("multi.tar")
//
//	# Import from stdin
//	images, err := client.ImportMultipleFromTar("-")
func (c *CacheClient) ImportMultipleFromTar(tarPath string) (map[string]v1.Image, error) {
	return importMultipleImagesFromTar(c, tarPath)
}
