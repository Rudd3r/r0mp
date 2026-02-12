package defaults

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCDNServices(t *testing.T) {
	policy := CDNServices()
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
		// CDNJS
		{"cdnjs js", "cdnjs.cloudflare.com", "/ajax/libs/jquery/3.6.0/jquery.min.js", "cdnjs"},
		{"cdnjs css", "cdnjs.cloudflare.com", "/ajax/libs/bootstrap/5.0.0/css/bootstrap.min.css", "cdnjs"},
		{"cdnjs font", "cdnjs.cloudflare.com", "/ajax/libs/font-awesome/5.15.0/webfonts/fa-solid-900.woff2", "cdnjs"},

		// Unpkg
		{"unpkg package", "unpkg.com", "/react@18.0.0/umd/react.production.min.js", "unpkg"},
		{"unpkg scoped", "unpkg.com", "/@babel/core@7.0.0/lib/index.js", "unpkg"},

		// jsDelivr
		{"jsdelivr npm", "cdn.jsdelivr.net", "/npm/vue@3.0.0/dist/vue.global.js", "jsdelivr"},
		{"jsdelivr gh", "cdn.jsdelivr.net", "/gh/jquery/jquery@3.6.0/dist/jquery.min.js", "jsdelivr"},
		{"jsdelivr combine", "cdn.jsdelivr.net", "/combine/npm/react@18.0.0,npm/react-dom@18.0.0", "jsdelivr"},

		// Google Fonts
		{"google fonts css", "fonts.googleapis.com", "/css2?family=Roboto:wght@400;700", "google-fonts-api"},
		{"google fonts icon", "fonts.googleapis.com", "/icon?family=Material+Icons", "google-fonts-api"},
		{"google fonts static", "fonts.gstatic.com", "/s/roboto/v30/KFOmCnqEu92Fr1Mu4mxK.woff2", "google-fonts-static"},

		// Bootstrap CDN
		{"bootstrap cdn js", "stackpath.bootstrapcdn.com", "/bootstrap/4.5.0/js/bootstrap.min.js", "bootstrap-cdn"},
		{"bootstrap cdn css", "maxcdn.bootstrapcdn.com", "/bootstrap/3.3.7/css/bootstrap.min.css", "bootstrap-cdn"},
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

func TestCDNServicesRejectsUnknownHosts(t *testing.T) {
	policy := CDNServices()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"random domain", "example.com", "/library.js"},
		{"malicious cdnjs", "cdnjs.cloudflare.com.evil.com", "/ajax/libs/jquery/jquery.js"},
		{"wrong jsdelivr", "fake.jsdelivr.net", "/npm/package.js"},
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

func TestCDNServicesRejectsNonAssetPaths(t *testing.T) {
	policy := CDNServices()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"cdnjs html", "cdnjs.cloudflare.com", "/ajax/libs/jquery/index.html"},
		{"google fonts exe", "fonts.gstatic.com", "/malware.exe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host:   tt.host,
				Method: "GET",
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, _ := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s should not be allowed (invalid file type)", tt.host, tt.path)
		})
	}
}

func TestCDNServicesRejectsNonGETMethods(t *testing.T) {
	policy := CDNServices()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		host   string
		path   string
	}{
		{"cdnjs POST", "POST", "cdnjs.cloudflare.com", "/ajax/libs/jquery/3.6.0/jquery.min.js"},
		{"cdnjs PUT", "PUT", "cdnjs.cloudflare.com", "/ajax/libs/jquery/3.6.0/jquery.min.js"},
		{"cdnjs DELETE", "DELETE", "cdnjs.cloudflare.com", "/ajax/libs/jquery/3.6.0/jquery.min.js"},
		{"unpkg POST", "POST", "unpkg.com", "/react@18.0.0/umd/react.production.min.js"},
		{"jsdelivr POST", "POST", "cdn.jsdelivr.net", "/npm/vue@3.0.0/dist/vue.global.js"},
		{"google fonts POST", "POST", "fonts.googleapis.com", "/css2?family=Roboto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host:   tt.host,
				Method: tt.method,
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, _ := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s with method %s should not be allowed", tt.host, tt.path, tt.method)
		})
	}
}

func TestIndividualCDNServices(t *testing.T) {
	tests := []struct {
		name         string
		policyFunc   func() *domain.ProxyPolicy
		expectedHost string
		expectedPath string
		policyName   string
	}{
		{"CDNJS", CDNJS, "cdnjs.cloudflare.com", "/ajax/libs/jquery/3.6.0/jquery.min.js", "cdnjs"},
		{"Unpkg", UnpkgCDN, "unpkg.com", "/react@18.0.0/umd/react.production.min.js", "unpkg"},
		{"jsDelivr", JsDelivrCDN, "cdn.jsdelivr.net", "/npm/vue@3.0.0/dist/vue.global.js", "jsdelivr"},
		{"Google Fonts", GoogleFontsCDN, "fonts.googleapis.com", "/css2?family=Roboto", "google-fonts-api"},
		{"Bootstrap CDN", BootstrapCDN, "stackpath.bootstrapcdn.com", "/bootstrap/4.5.0/js/bootstrap.min.js", "bootstrap-cdn"},
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
