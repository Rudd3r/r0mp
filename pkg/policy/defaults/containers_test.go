package defaults

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerRegistries(t *testing.T) {
	policy := ContainerRegistries()
	require.NotNil(t, policy)
	require.NotEmpty(t, policy.AcceptRules)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		path     string
		expected string
	}{
		// Docker Hub
		{"docker hub registry", "registry-1.docker.io", "/v2/library/nginx/manifests/latest", "docker-hub-registry"},
		{"docker hub alt", "registry.hub.docker.com", "/v2/library/redis/tags/list", "docker-hub-registry"},
		{"docker hub auth", "auth.docker.io", "/token", "docker-hub-auth"},
		{"docker hub cdn", "production.cloudflare.docker.com", "/v2/blobs/sha256/abc123", "docker-hub-cdn"},

		// GitHub Container Registry
		{"ghcr v2", "ghcr.io", "/v2/owner/repo/manifests/latest", "ghcr"},
		{"ghcr token", "ghcr.io", "/token", "ghcr"},

		// Google Container Registry
		{"gcr", "gcr.io", "/v2/project/image/manifests/latest", "gcr"},
		{"gcr us", "us.gcr.io", "/v2/project/image/tags/list", "gcr"},
		{"gcr artifact registry", "us-docker.pkg.dev", "/v2/project/repo/image/manifests/sha256:abc", "gcr"},

		// AWS ECR
		{"ecr private", "123456789012.dkr.ecr.us-east-1.amazonaws.com", "/v2/my-repo/manifests/latest", "ecr"},
		{"ecr public", "public.ecr.aws", "/v2/nginx/manifests/latest", "ecr-public"},

		// Quay.io
		{"quay", "quay.io", "/v2/coreos/etcd/manifests/latest", "quay"},

		// Azure Container Registry
		{"acr", "myregistry.azurecr.io", "/v2/myimage/manifests/latest", "acr"},
		{"acr oauth", "myregistry.azurecr.io", "/oauth2/token", "acr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host:   tt.host,
				Method: "GET",
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied, "Host %s path %s should not be denied", tt.host, tt.path)
			require.NotNil(t, allowed, "Host %s path %s should be allowed", tt.host, tt.path)
			assert.Equal(t, tt.expected, allowed.Name, "Host %s path %s should match policy %s", tt.host, tt.path, tt.expected)
		})
	}
}

func TestContainerRegistriesRejectsUnknownHosts(t *testing.T) {
	policy := ContainerRegistries()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"random domain", "example.com", "/v2/image/manifests/latest"},
		{"malicious docker", "registry-1.docker.io.evil.com", "/v2/image/manifests/latest"},
		{"wrong gcr", "fake.gcr.io", "/v2/image/manifests/latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host:   tt.host,
				Method: "GET",
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s should not be allowed", tt.host, tt.path)
			assert.Nil(t, denied, "Host %s path %s should not match any rule", tt.host, tt.path)
		})
	}
}

func TestContainerRegistriesRejectsWriteMethods(t *testing.T) {
	policy := ContainerRegistries()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		host   string
		path   string
	}{
		{"docker hub POST", "POST", "registry-1.docker.io", "/v2/library/nginx/blobs/uploads/"},
		{"docker hub PUT", "PUT", "registry-1.docker.io", "/v2/library/nginx/manifests/latest"},
		{"docker hub PATCH", "PATCH", "registry-1.docker.io", "/v2/library/nginx/blobs/uploads/123"},
		{"docker hub DELETE", "DELETE", "registry-1.docker.io", "/v2/library/nginx/manifests/latest"},
		{"ghcr POST", "POST", "ghcr.io", "/v2/owner/repo/blobs/uploads/"},
		{"gcr PUT", "PUT", "gcr.io", "/v2/project/image/manifests/latest"},
		{"ecr POST", "POST", "123456789012.dkr.ecr.us-east-1.amazonaws.com", "/v2/repo/blobs/uploads/"},
		{"quay DELETE", "DELETE", "quay.io", "/v2/repo/manifests/latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host:   tt.host,
				Method: tt.method,
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, _ := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s with method %s should not be allowed (write operation)", tt.host, tt.path, tt.method)
		})
	}
}

func TestContainerRegistriesAllowsHEAD(t *testing.T) {
	policy := ContainerRegistries()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		path     string
		expected string
	}{
		{"docker hub HEAD blob", "registry-1.docker.io", "/v2/library/nginx/blobs/sha256:abc123", "docker-hub-registry"},
		{"ghcr HEAD manifest", "ghcr.io", "/v2/owner/repo/manifests/latest", "ghcr"},
		{"gcr HEAD", "gcr.io", "/v2/project/image/manifests/latest", "gcr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host:   tt.host,
				Method: "HEAD",
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied, "Host %s path %s with HEAD should not be denied", tt.host, tt.path)
			require.NotNil(t, allowed, "Host %s path %s with HEAD should be allowed", tt.host, tt.path)
			assert.Equal(t, tt.expected, allowed.Name)
		})
	}
}

func TestIndividualContainerRegistries(t *testing.T) {
	tests := []struct {
		name         string
		policyFunc   func() *domain.ProxyPolicy
		expectedHost string
		expectedPath string
		policyName   string
	}{
		{"Docker Hub", DockerHubRegistry, "registry-1.docker.io", "/v2/library/nginx/manifests/latest", "docker-hub-registry"},
		{"GitHub CR", GitHubContainerRegistry, "ghcr.io", "/v2/owner/repo/manifests/latest", "ghcr"},
		{"Google CR", GoogleContainerRegistry, "gcr.io", "/v2/project/image/manifests/latest", "gcr"},
		{"AWS ECR", AWSContainerRegistry, "123456789012.dkr.ecr.us-east-1.amazonaws.com", "/v2/repo/manifests/latest", "ecr"},
		{"Quay", QuayRegistry, "quay.io", "/v2/repo/manifests/latest", "quay"},
		{"Azure CR", AzureContainerRegistry, "myregistry.azurecr.io", "/v2/image/manifests/latest", "acr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.policyFunc()
			require.NotNil(t, policy)
			require.NotEmpty(t, policy.AcceptRules)

			err := policy.Compile()
			require.NoError(t, err)

			req := &http.Request{
				Host:   tt.expectedHost,
				Method: "GET",
				URL:    &url.URL{Host: tt.expectedHost, Path: tt.expectedPath},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied)
			require.NotNil(t, allowed, "Request to %s%s should be allowed", tt.expectedHost, tt.expectedPath)
			assert.Equal(t, tt.policyName, allowed.Name)
		})
	}
}
