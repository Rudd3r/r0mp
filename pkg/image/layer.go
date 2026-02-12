package image

import (
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// cachedLayer wraps a v1.Layer and adds transparent caching for compressed layer data
type cachedLayer struct {
	layer v1.Layer
	cache *LayerCache
}

// Digest returns the Hash of the compressed layer.
func (l *cachedLayer) Digest() (v1.Hash, error) {
	return l.layer.Digest()
}

// DiffID returns the Hash of the uncompressed layer.
func (l *cachedLayer) DiffID() (v1.Hash, error) {
	return l.layer.DiffID()
}

// Compressed returns an io.ReadCloser for the compressed layer contents.
// This method uses the cache to avoid redundant downloads.
func (l *cachedLayer) Compressed() (io.ReadCloser, error) {
	digest, err := l.layer.Digest()
	if err != nil {
		return nil, err
	}
	rc, _, err := l.cache.GetOrFetchLayer(digest, func() (io.ReadCloser, error) {
		return l.layer.Compressed()
	})
	return rc, err
}

// Uncompressed returns an io.ReadCloser for the uncompressed layer contents.
func (l *cachedLayer) Uncompressed() (io.ReadCloser, error) {
	return l.layer.Uncompressed()
}

// Size returns the compressed size of the Layer.
func (l *cachedLayer) Size() (int64, error) {
	return l.layer.Size()
}

// MediaType returns the media type of the Layer.
func (l *cachedLayer) MediaType() (types.MediaType, error) {
	return l.layer.MediaType()
}
