package image

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// cachedImage wraps a v1.Image and returns cached layers
type cachedImage struct {
	image v1.Image
	cache *LayerCache
}

// Layers returns the ordered collection of filesystem layers that comprise this image.
// The order of the list is oldest/base layer first, and most-recent/top layer last.
// Layers are wrapped to provide transparent caching.
func (i *cachedImage) Layers() ([]v1.Layer, error) {
	layers, err := i.image.Layers()
	if err != nil {
		return nil, err
	}
	cachedLayers := make([]v1.Layer, len(layers))
	for idx, layer := range layers {
		cachedLayers[idx] = &cachedLayer{
			layer: layer,
			cache: i.cache,
		}
	}
	return cachedLayers, nil
}

// MediaType of this image's manifest.
func (i *cachedImage) MediaType() (types.MediaType, error) {
	return i.image.MediaType()
}

// Size returns the size of the manifest.
func (i *cachedImage) Size() (int64, error) {
	return i.image.Size()
}

// ConfigName returns the hash of the image's config file.
func (i *cachedImage) ConfigName() (v1.Hash, error) {
	return i.image.ConfigName()
}

// ConfigFile returns this image's config file.
func (i *cachedImage) ConfigFile() (*v1.ConfigFile, error) {
	return i.image.ConfigFile()
}

// RawConfigFile returns the serialized bytes of ConfigFile().
func (i *cachedImage) RawConfigFile() ([]byte, error) {
	return i.image.RawConfigFile()
}

// Digest returns the sha256 of this image's manifest.
func (i *cachedImage) Digest() (v1.Hash, error) {
	return i.image.Digest()
}

// Manifest returns this image's Manifest object.
func (i *cachedImage) Manifest() (*v1.Manifest, error) {
	return i.image.Manifest()
}

// RawManifest returns the serialized bytes of Manifest()
func (i *cachedImage) RawManifest() ([]byte, error) {
	return i.image.RawManifest()
}

// LayerByDigest returns a Layer for interacting with a particular layer of
// the image, looking it up by "digest" (the compressed hash).
// The returned layer is wrapped to provide transparent caching.
func (i *cachedImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	layer, err := i.image.LayerByDigest(h)
	if err != nil {
		return nil, err
	}

	return &cachedLayer{
		layer: layer,
		cache: i.cache,
	}, nil
}

// LayerByDiffID is an analog to LayerByDigest, looking up by "diff id"
// (the uncompressed hash).
// The returned layer is wrapped to provide transparent caching.
func (i *cachedImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	layer, err := i.image.LayerByDiffID(h)
	if err != nil {
		return nil, err
	}

	return &cachedLayer{
		layer: layer,
		cache: i.cache,
	}, nil
}
