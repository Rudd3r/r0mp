package image

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPullAlpine tests pulling a real image from Docker Hub
func TestPullAlpine(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	// Pull alpine:latest - a small, commonly available image
	img, err := client.Pull("alpine:latest")
	require.NoError(t, err, "should successfully pull alpine:latest")
	require.NotNil(t, img, "image should not be nil")

	// Verify we can get the config
	config, err := img.ConfigFile()
	require.NoError(t, err, "should be able to get config")
	require.NotNil(t, config, "config should not be nil")

	// Verify basic config properties
	assert.Equal(t, "linux", config.OS, "OS should be linux")
	assert.NotEmpty(t, config.Architecture, "Architecture should not be empty")

	// Verify we can get layers
	layers, err := img.Layers()
	require.NoError(t, err, "should be able to get layers")
	assert.NotEmpty(t, layers, "should have at least one layer")

	// Verify we can get the manifest
	manifest, err := img.Manifest()
	require.NoError(t, err, "should be able to get manifest")
	require.NotNil(t, manifest, "manifest should not be nil")
	assert.NotEmpty(t, manifest.Layers, "manifest should have layers")
}

// TestPullUbuntu tests pulling Ubuntu image
func TestPullUbuntu(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	// Pull ubuntu:22.04
	img, err := client.Pull("ubuntu:22.04")
	require.NoError(t, err, "should successfully pull ubuntu:22.04")
	require.NotNil(t, img, "image should not be nil")

	// Verify config
	config, err := img.ConfigFile()
	require.NoError(t, err, "should be able to get config")
	assert.Equal(t, "linux", config.OS)
}

// TestPullWithPlatform tests pulling a multi-arch image with platform selection
func TestPullWithPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform v1.Platform
	}{
		{
			name: "amd64",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		},
		{
			name: "arm64",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "arm64",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(
				WithAuthFromKeychain(),
				WithPlatform(tt.platform),
			)

			// Pull alpine which has multi-arch support
			img, err := client.Pull("alpine:latest")
			require.NoError(t, err, "should successfully pull image")
			require.NotNil(t, img, "image should not be nil")

			// Verify platform matches
			config, err := img.ConfigFile()
			require.NoError(t, err, "should be able to get config")
			assert.Equal(t, tt.platform.OS, config.OS)
			assert.Equal(t, tt.platform.Architecture, config.Architecture)
		})
	}
}

// TestGetManifest tests getting just the manifest without pulling layers
func TestGetManifest(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	manifest, err := client.GetManifest("alpine:latest")
	require.NoError(t, err, "should successfully get manifest")
	require.NotNil(t, manifest, "manifest should not be nil")

	assert.NotEmpty(t, manifest.Layers, "manifest should have layers")
	assert.NotEmpty(t, manifest.Config.Digest, "config digest should not be empty")
	assert.Greater(t, manifest.Config.Size, int64(0), "config size should be positive")
}

// TestGetConfig tests getting image configuration
func TestGetConfig(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	config, err := client.GetConfig("alpine:latest")
	require.NoError(t, err, "should successfully get config")
	require.NotNil(t, config, "config should not be nil")

	assert.Equal(t, "linux", config.OS)
	assert.NotEmpty(t, config.Architecture)
	assert.NotNil(t, config.RootFS, "rootfs should not be nil")
	assert.NotEmpty(t, config.RootFS.DiffIDs, "should have diff IDs")
}

// TestPullNonExistentImage tests error handling for non-existent images
func TestPullNonExistentImage(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	// Try to pull an image that definitely doesn't exist
	img, err := client.Pull("thisdoesnotexist12345678:nonexistenttag")
	assert.Error(t, err, "should fail to pull non-existent image")
	assert.Nil(t, img, "image should be nil on error")
	assert.Contains(t, err.Error(), "failed to pull image")
}

// TestPullFromCustomRegistry tests pulling from a custom registry (GitHub Container Registry)
func TestPullFromCustomRegistry(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	// Try to pull a public image from GHCR - using a well-known public image
	// Note: This might fail if the image doesn't exist, which is expected
	img, err := client.Pull("ghcr.io/google/ko:latest")

	if err != nil {
		// It's okay if this fails due to auth or missing image
		t.Logf("Expected potential failure for GHCR pull: %v", err)
		return
	}

	// If it succeeds, verify basic properties
	require.NotNil(t, img)
	config, err := img.ConfigFile()
	require.NoError(t, err)
	assert.NotNil(t, config)
}

// TestPullByDigest tests pulling an image by its digest
func TestPullByDigest(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	// Get the image digest
	img1, err := client.Pull("alpine:latest")
	require.NoError(t, err)
	digest, err := img1.Digest()
	require.NoError(t, err)

	// Now pull by digest
	digestRef := "alpine@" + digest.String()
	img2, err := client.Pull(digestRef)
	require.NoError(t, err, "should successfully pull by digest")
	require.NotNil(t, img2)

	// Verify the digest matches
	digest2, err := img2.Digest()
	require.NoError(t, err)
	assert.Equal(t, digest.String(), digest2.String(), "digests should match")
}

// TestLayerAccess tests that we can access and read layer contents
func TestLayerAccess(t *testing.T) {
	client := NewClient(WithAuthFromKeychain())

	img, err := client.Pull("alpine:latest")
	require.NoError(t, err)

	layers, err := img.Layers()
	require.NoError(t, err)
	require.NotEmpty(t, layers, "should have layers")

	// Test accessing the first layer
	layer := layers[0]

	// Get layer digest
	digest, err := layer.Digest()
	require.NoError(t, err)
	assert.NotEmpty(t, digest.String(), "digest should not be empty")

	// Get layer size
	size, err := layer.Size()
	require.NoError(t, err)
	assert.Greater(t, size, int64(0), "size should be positive")

	// Get uncompressed layer content (tar stream)
	rc, err := layer.Uncompressed()
	require.NoError(t, err)
	require.NotNil(t, rc, "uncompressed reader should not be nil")
	defer func() { _ = rc.Close() }()

	// Verify we can read some bytes
	buf := make([]byte, 512)
	n, err := rc.Read(buf)
	assert.NoError(t, err, "should be able to read from layer")
	assert.Greater(t, n, 0, "should read some bytes")
}
