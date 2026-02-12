package defaults

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageRegistries(t *testing.T) {
	policy := PackageRegistries()
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
		// npm
		{"npm package", "registry.npmjs.org", "/express", "npm"},
		{"npm scoped package", "registry.npmjs.org", "/@types/node", "npm"},
		{"npm tarball", "registry.npmjs.org", "/express/-/express-4.18.2.tgz", "npm"},

		// PyPI
		{"pypi simple", "pypi.org", "/simple/flask/", "pypi"},
		{"pypi package", "pypi.org", "/pypi/flask/json", "pypi"},
		{"pypi files", "files.pythonhosted.org", "/packages/ab/cd/flask-2.0.0.tar.gz", "pypi-files"},

		// RubyGems
		{"rubygems gem", "rubygems.org", "/gems/rails-7.0.0.gem", "rubygems"},
		{"rubygems api", "rubygems.org", "/api/v1/gems/rails.json", "rubygems"},
		{"rubygems deps", "rubygems.org", "/api/v1/dependencies/rails.json", "rubygems"},

		// crates.io
		{"crates api", "crates.io", "/api/v1/crates/tokio", "crates-io"},
		{"crates static", "static.crates.io", "/crates/tokio/tokio-1.0.0.crate", "crates-io-static"},
		{"crates index", "index.crates.io", "/to/ki/tokio", "crates-io-index"},

		// Maven Central
		{"maven central", "repo1.maven.org", "/maven2/org/springframework/spring-core/5.3.0/spring-core-5.3.0.jar", "maven-central"},
		{"maven apache", "repo.maven.apache.org", "/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar", "maven-apache"},

		// Go modules
		{"go proxy", "proxy.golang.org", "/github.com/gin-gonic/gin/@v/v1.7.0.zip", "go-proxy"},
		{"go sum lookup", "sum.golang.org", "/lookup/github.com/gin-gonic/gin@v1.7.0", "go-sum"},

		// NuGet
		{"nuget index", "api.nuget.org", "/v3/index.json", "nuget"},
		{"nuget package", "api.nuget.org", "/v3/package/Newtonsoft.Json/13.0.1.nupkg", "nuget"},
		{"nuget query", "api.nuget.org", "/v3/query?q=newtonsoft", "nuget"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				Host:   tt.host,
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied, "Host %s path %s should not be denied", tt.host, tt.path)
			require.NotNil(t, allowed, "Host %s path %s should be allowed", tt.host, tt.path)
			assert.Equal(t, tt.expected, allowed.Name, "Host %s path %s should match policy %s", tt.host, tt.path, tt.expected)
		})
	}
}

func TestPackageRegistriesRejectsUnknownHosts(t *testing.T) {
	policy := PackageRegistries()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"random domain", "example.com", "/package"},
		{"malicious npm", "registry.npmjs.org.evil.com", "/express"},
		{"wrong rubygems", "fake.rubygems.org", "/gems/rails.gem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				Host:   tt.host,
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s should not be allowed", tt.host, tt.path)
			assert.Nil(t, denied, "Host %s path %s should not match any rule", tt.host, tt.path)
		})
	}
}

func TestIndividualPackageRegistries(t *testing.T) {
	tests := []struct {
		name         string
		policyFunc   func() *domain.ProxyPolicy
		expectedHost string
		expectedPath string
		policyName   string
	}{
		{"NPM", NPMRegistry, "registry.npmjs.org", "/express", "npm"},
		{"PyPI", PyPIRegistry, "pypi.org", "/simple/flask/", "pypi"},
		{"RubyGems", RubyGemsRegistry, "rubygems.org", "/gems/rails.gem", "rubygems"},
		{"Crates.io", CratesIORegistry, "crates.io", "/api/v1/crates/tokio", "crates-io"},
		{"Maven Central", MavenCentralRegistry, "repo1.maven.org", "/maven2/org/test/test.jar", "maven-central"},
		{"Go Modules", GoModulesRegistry, "proxy.golang.org", "/github.com/test/test/@v/v1.0.0.zip", "go-proxy"},
		{"NuGet", NuGetRegistry, "api.nuget.org", "/v3/index.json", "nuget"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.policyFunc()
			require.NotNil(t, policy)
			require.NotEmpty(t, policy.AcceptRules)

			err := policy.Compile()
			require.NoError(t, err)

			req := &http.Request{
				Method: "GET",
				Host:   tt.expectedHost,
				URL:    &url.URL{Host: tt.expectedHost, Path: tt.expectedPath},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied)
			require.NotNil(t, allowed, "Request to %s%s should be allowed", tt.expectedHost, tt.expectedPath)
			assert.Equal(t, tt.policyName, allowed.Name)
		})
	}
}
