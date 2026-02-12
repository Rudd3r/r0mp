package image

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Client provides high-level registry operations as a wrapper around go-containerregistry
type Client struct {
	options []remote.Option
}

// Option configures the registry client
type Option func(*Client)

// NewClient creates a new registry client with optional configuration
func NewClient(opts ...Option) *Client {
	c := &Client{
		options: []remote.Option{},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithAuth sets authentication credentials for registry access
func WithAuth(username, password string) Option {
	return func(c *Client) {
		auth := &authn.Basic{
			Username: username,
			Password: password,
		}
		c.options = append(c.options, remote.WithAuth(auth))
	}
}

// WithAuthFromKeychain uses the default Docker keychain for authentication
// This reads credentials from ~/.docker/config.json
func WithAuthFromKeychain() Option {
	return func(c *Client) {
		c.options = append(c.options, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}
}

// WithPlatform specifies the platform (OS/architecture) for multi-arch images
func WithPlatform(platform v1.Platform) Option {
	return func(c *Client) {
		c.options = append(c.options, remote.WithPlatform(platform))
	}
}

// WithUserAgent sets a custom user agent for registry requests
func WithUserAgent(userAgent string) Option {
	return func(c *Client) {
		c.options = append(c.options, remote.WithUserAgent(userAgent))
	}
}

// Pull downloads an image from a registry and returns the image descriptor
// ref should be in the format: [registry/]repository[:tag|@digest]
// Examples:
//   - "alpine:latest"
//   - "ubuntu:22.04"
//   - "docker.io/library/nginx:1.25"
//   - "ghcr.io/myorg/myapp:v1.0.0"
func (c *Client) Pull(ref string) (v1.Image, error) {
	// Parse the image reference
	imageRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %q: %w", ref, err)
	}

	// Pull the image using go-containerregistry
	img, err := remote.Image(imageRef, c.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to pull image %q: %w", ref, err)
	}

	return img, nil
}

// GetManifest retrieves just the manifest for an image without pulling layers
func (c *Client) GetManifest(ref string) (*v1.Manifest, error) {
	imageRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %q: %w", ref, err)
	}

	img, err := remote.Image(imageRef, c.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get image descriptor %q: %w", ref, err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest for %q: %w", ref, err)
	}

	return manifest, nil
}

// GetConfig retrieves the image configuration
func (c *Client) GetConfig(ref string) (*v1.ConfigFile, error) {
	imageRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %q: %w", ref, err)
	}

	img, err := remote.Image(imageRef, c.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get image descriptor %q: %w", ref, err)
	}

	config, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to get config for %q: %w", ref, err)
	}

	return config, nil
}

// ParseReference parses an image reference string and returns the parsed reference
// This is useful for validating references or extracting components
func ParseReference(ref string) (name.Reference, error) {
	return name.ParseReference(ref)
}

// DefaultPlatform returns the platform for the current runtime
func DefaultPlatform() v1.Platform {
	return v1.Platform{
		OS:           "linux",
		Architecture: "amd64",
	}
}
