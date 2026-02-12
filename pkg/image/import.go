package image

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// resolveTarPath handles stdin buffering if needed
// If tarPath is "-" or empty, reads from stdin and returns path to temp file and cleanup function
// Otherwise returns the original path and a no-op cleanup
func resolveTarPath(tarPath string) (resolvedPath string, cleanup func(), err error) {
	// If not stdin, use path directly
	if tarPath != "-" && tarPath != "" {
		return tarPath, func() {}, nil
	}

	// Buffer stdin to a temporary file since we need to read it multiple times
	tmpFile, err := os.CreateTemp("", "r0mp-import-*.tar")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file for stdin: %w", err)
	}

	tmpPath := tmpFile.Name()
	cleanup = func() {
		_ = os.Remove(tmpPath)
	}

	// Copy stdin to temp file
	if _, err := io.Copy(tmpFile, os.Stdin); err != nil {
		_ = tmpFile.Close()
		cleanup()
		return "", nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	return tmpPath, cleanup, nil
}

// importImageFromTar loads a single image from a tar file and caches it
// Supports reading from stdin when tarPath is "-" or empty
func importImageFromTar(c *CacheClient, tarPath string, ref string) (v1.Image, error) {
	// Resolve stdin to temp file if needed
	resolvedPath, cleanup, err := resolveTarPath(tarPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Load the image from the tar file using go-containerregistry's tarball package
	img, err := tarball.ImageFromPath(resolvedPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from tar %q: %w", tarPath, err)
	}

	// Cache the image metadata
	if err := c.imageCache.Put(img, ref); err != nil {
		c.log.Warn("failed to cache image metadata", "error", err, "ref", ref)
	}

	// Wrap the image to provide transparent layer caching
	cachedImg := &cachedImage{
		image: img,
		cache: c.cache,
	}

	return cachedImg, nil
}

// importMultipleImagesFromTar loads all images from a tar file
// Docker save can bundle multiple images with different tags
// Supports reading from stdin when tarPath is "-" or empty
func importMultipleImagesFromTar(c *CacheClient, tarPath string) (map[string]v1.Image, error) {
	// Resolve stdin to temp file if needed
	resolvedPath, cleanup, err := resolveTarPath(tarPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Parse the tar file to extract all image tags
	manifest, err := tarball.LoadManifest(func() (io.ReadCloser, error) {
		return os.Open(resolvedPath)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load manifest from tar %q: %w", tarPath, err)
	}

	if len(manifest) == 0 {
		return nil, fmt.Errorf("no images found in tar file %q", tarPath)
	}

	results := make(map[string]v1.Image)

	// Import each image with its respective tags
	for _, descriptor := range manifest {
		if len(descriptor.RepoTags) == 0 {
			// Image has no tags, skip it or use a generated name
			c.log.Warn("skipping image with no tags in tar", "tarPath", tarPath)
			continue
		}

		// Load the image with each tag reference
		for _, tagStr := range descriptor.RepoTags {
			// Parse the tag string into a name.Tag
			tag, err := name.NewTag(tagStr)
			if err != nil {
				c.log.Warn("failed to parse tag", "error", err, "tag", tagStr)
				continue
			}

			img, err := tarball.ImageFromPath(resolvedPath, &tag)
			if err != nil {
				c.log.Warn("failed to load image from tar", "error", err, "tag", tagStr)
				continue
			}

			// Cache the image metadata
			if err := c.imageCache.Put(img, tagStr); err != nil {
				c.log.Warn("failed to cache image metadata", "error", err, "tag", tagStr)
			}

			// Wrap the image for caching
			cachedImg := &cachedImage{
				image: img,
				cache: c.cache,
			}

			results[tagStr] = cachedImg
			c.log.Info("imported image from tar", "tag", tagStr, "tarPath", tarPath)
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no images could be imported from tar file %q", tarPath)
	}

	return results, nil
}
