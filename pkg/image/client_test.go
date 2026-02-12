package image

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "client with no options",
			opts: nil,
		},
		{
			name: "client with auth",
			opts: []Option{WithAuth("user", "pass")},
		},
		{
			name: "client with keychain auth",
			opts: []Option{WithAuthFromKeychain()},
		},
		{
			name: "client with platform",
			opts: []Option{WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"})},
		},
		{
			name: "client with user agent",
			opts: []Option{WithUserAgent("test-agent/1.0")},
		},
		{
			name: "client with multiple options",
			opts: []Option{
				WithAuth("user", "pass"),
				WithPlatform(v1.Platform{OS: "linux", Architecture: "arm64"}),
				WithUserAgent("test-agent/1.0"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.opts...)
			assert.NotNil(t, client)
			assert.NotNil(t, client.options)
		})
	}
}

func TestParseReference(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantErr   bool
		wantRepo  string
		checkFunc func(t *testing.T, ref interface{})
	}{
		{
			name:     "simple image with tag",
			ref:      "alpine:latest",
			wantErr:  false,
			wantRepo: "alpine:latest",
		},
		{
			name:     "image with registry and tag",
			ref:      "docker.io/library/ubuntu:22.04",
			wantErr:  false,
			wantRepo: "docker.io/library/ubuntu:22.04",
		},
		{
			name:     "image with custom registry",
			ref:      "ghcr.io/myorg/myapp:v1.0.0",
			wantErr:  false,
			wantRepo: "ghcr.io/myorg/myapp:v1.0.0",
		},
		{
			name:     "image with digest",
			ref:      "alpine@sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
			wantErr:  false,
			wantRepo: "alpine@sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
		},
		{
			name:    "invalid reference - empty",
			ref:     "",
			wantErr: true,
		},
		{
			name:    "invalid reference - bad format",
			ref:     "not a valid:image:reference",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseReference(tt.ref)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, ref)
			assert.Equal(t, tt.wantRepo, ref.String())
		})
	}
}

func TestDefaultPlatform(t *testing.T) {
	platform := DefaultPlatform()
	assert.Equal(t, "linux", platform.OS)
	assert.Equal(t, "amd64", platform.Architecture)
}

func TestClientPull_InvalidReference(t *testing.T) {
	client := NewClient()

	tests := []struct {
		name string
		ref  string
	}{
		{
			name: "empty reference",
			ref:  "",
		},
		{
			name: "invalid format",
			ref:  ":::invalid:::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := client.Pull(tt.ref)
			assert.Error(t, err)
			assert.Nil(t, img)
			assert.Contains(t, err.Error(), "failed to parse image reference")
		})
	}
}

func TestClientGetManifest_InvalidReference(t *testing.T) {
	client := NewClient()

	manifest, err := client.GetManifest("")
	assert.Error(t, err)
	assert.Nil(t, manifest)
	assert.Contains(t, err.Error(), "failed to parse image reference")
}

func TestClientGetConfig_InvalidReference(t *testing.T) {
	client := NewClient()

	config, err := client.GetConfig("")
	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "failed to parse image reference")
}

// TestWithOptions verifies that options can be combined
func TestWithOptions(t *testing.T) {
	platform := v1.Platform{
		OS:           "linux",
		Architecture: "arm64",
		Variant:      "v8",
	}

	client := NewClient(
		WithAuth("testuser", "testpass"),
		WithPlatform(platform),
		WithUserAgent("test/1.0"),
	)

	assert.NotNil(t, client)
	// We can't easily test the internal options array without exposing it,
	// but we verify that the client is created successfully with multiple options
	assert.Len(t, client.options, 3)
}
