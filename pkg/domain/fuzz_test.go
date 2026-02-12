package domain

import (
	"net/http"
	"net/url"
	"testing"
)

// FuzzProxyPolicyMatchCompile tests the compilation of policy match regex patterns
func FuzzProxyPolicyMatchCompile(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Seed corpus with various regex patterns
	f.Add(".*", "", "", "", "", "")
	f.Add("^example\\.com$", "GET|POST", "/api/.*", "", "", "")
	f.Add("", "", "", "X-Custom-.*", "id=\\d+", "")
	f.Add("*.example.com", "", "", "", "", "application/json")
	f.Add("[invalid", "", "", "", "", "")
	f.Add("(unclosed", "", "", "", "", "")
	f.Add("(?P<invalid>)", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, host, method, path, headerKey, queryKey, contentType string) {
		headers := make(map[string]string)
		queries := make(map[string]string)

		if headerKey != "" {
			headers[headerKey] = ".*"
		}
		if queryKey != "" {
			queries[queryKey] = ".*"
		}

		match := &ProxyPolicyMatch{
			Host:        host,
			Method:      method,
			Path:        path,
			Header:      headers,
			Query:       queries,
			Fragment:    "",
			ContentType: contentType,
		}

		// Should not panic on any input
		_ = match.Compile()
	})
}

// FuzzProxyPolicyMatch tests the matching logic against various HTTP requests
func FuzzProxyPolicyMatch(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	// Seed corpus with various request combinations
	f.Add("example.com", "GET", "/api/users", "User-Agent", "Mozilla", "id", "123", "")
	f.Add("localhost:8080", "POST", "/", "", "", "", "", "application/json")
	f.Add("*.example.com", "PUT", "/api/.*", "", "", "", "", "")
	f.Add("", "", "", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, host, method, path, headerKey, headerVal, queryKey, queryVal, contentType string) {
		// Create a policy that should compile
		match := &ProxyPolicyMatch{
			Host:   ".*",
			Method: ".*",
			Path:   ".*",
		}

		if err := match.Compile(); err != nil {
			return
		}

		// Create an HTTP request with fuzzed data
		reqURL := &url.URL{
			Scheme: "http",
			Host:   host,
			Path:   path,
		}

		if queryKey != "" {
			q := reqURL.Query()
			q.Add(queryKey, queryVal)
			reqURL.RawQuery = q.Encode()
		}

		req := &http.Request{
			Method: method,
			URL:    reqURL,
			Host:   host,
			Header: make(http.Header),
		}

		if headerKey != "" {
			req.Header.Set(headerKey, headerVal)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		// Should not panic
		_ = match.Match(req)
	})
}

// FuzzProxyActionModifySetHeader tests header manipulation
func FuzzProxyActionModifySetHeader(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("X-Custom-Header", "value")
	f.Add("Authorization", "Bearer token")
	f.Add("", "")
	f.Add("Header\nInjection", "value\r\nX-Injected: true")
	f.Add("X-Long-Header", "very long value that might cause issues")

	f.Fuzz(func(t *testing.T, key, value string) {
		action, err := proxyActionModifySetHeader(key, value)
		if err != nil {
			return
		}

		req := &http.Request{
			URL:    &url.URL{Scheme: "http", Host: "example.com"},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)
	})
}

// FuzzProxyActionModifyPath tests path manipulation
func FuzzProxyActionModifyPath(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("/api/users")
	f.Add("/")
	f.Add("")
	f.Add("/../../../etc/passwd")
	f.Add("/api/../admin")
	f.Add("//double//slash")
	f.Add("/path with spaces")
	f.Add("/path%20encoded")

	f.Fuzz(func(t *testing.T, path string) {
		action, err := proxyActionModifyPath(path)
		if err != nil {
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/original",
			},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)

		// Verify path was set
		if req.URL.Path != path {
			t.Errorf("Path not set correctly: got %q, want %q", req.URL.Path, path)
		}
	})
}

// FuzzProxyActionModifyHost tests host manipulation
func FuzzProxyActionModifyHost(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("example.com")
	f.Add("localhost:8080")
	f.Add("")
	f.Add("192.168.1.1")
	f.Add("[::1]:8080")
	f.Add("sub.example.com:443")

	f.Fuzz(func(t *testing.T, host string) {
		action, err := proxyActionModifyHost(host)
		if err != nil {
			return
		}

		req := &http.Request{
			URL:    &url.URL{Scheme: "http", Host: "original.com"},
			Host:   "original.com",
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)

		// Verify host was set
		if req.Host != host || req.URL.Host != host {
			t.Errorf("Host not set correctly")
		}
	})
}

// FuzzProxyActionModifyAuthBearer tests bearer token setting
func FuzzProxyActionModifyAuthBearer(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("token123")
	f.Add("")
	f.Add("very.long.jwt.token.with.dots")
	f.Add("token\nwith\nnewlines")
	f.Add("token with spaces")

	f.Fuzz(func(t *testing.T, token string) {
		mock := NewMockSecretReadWriter()
		mock.locked = false
		_ = mock.SetSecret(token, token)
		action, err := proxyActionModifyAuthBearer([]string{token}, mock)
		if err != nil {
			return
		}

		req := &http.Request{
			URL:    &url.URL{Scheme: "http", Host: "example.com"},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)

		// Verify authorization header is set
		auth := req.Header.Get("Authorization")
		if auth != "Bearer "+token {
			t.Errorf("Authorization header incorrect: got %q, want %q", auth, "Bearer "+token)
		}
	})
}

// FuzzProxyActionModifyAddPathPrefix tests path prefix addition
func FuzzProxyActionModifyAddPathPrefix(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("/api")
	f.Add("/v1")
	f.Add("")
	f.Add("//")
	f.Add("/prefix/")

	f.Fuzz(func(t *testing.T, prefix string) {
		action, err := proxyActionModifyAddPathPrefix(prefix)
		if err != nil {
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/users",
			},
			Header: make(http.Header),
		}

		originalPath := req.URL.Path

		// Should not panic
		_ = action(req)

		// If prefix doesn't match, it should be added
		if prefix != "" && !hasPrefix(originalPath, prefix) {
			expected := prefix + originalPath
			if req.URL.Path != expected {
				t.Errorf("Path prefix not added correctly: got %q, want %q", req.URL.Path, expected)
			}
		}
	})
}

// Helper function to avoid issues with empty prefix
func hasPrefix(s, prefix string) bool {
	if prefix == "" {
		return true
	}
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

// FuzzProxyActionModifyRemovePathPrefix tests path prefix removal
func FuzzProxyActionModifyRemovePathPrefix(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("/api")
	f.Add("/v1")
	f.Add("")
	f.Add("/")

	f.Fuzz(func(t *testing.T, prefix string) {
		action, err := proxyActionModifyRemovePathPrefix(prefix)
		if err != nil {
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/api/users",
			},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)

		// Path should never be empty (defaults to "/")
		if req.URL.Path == "" {
			t.Errorf("Path should not be empty after removing prefix")
		}
	})
}

// FuzzProxyActionModifySetBasicAuth tests basic auth encoding
func FuzzProxyActionModifySetBasicAuth(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("user", "pass")
	f.Add("", "")
	f.Add("user:with:colons", "pass:word")
	f.Add("user\nname", "pass\nword")
	f.Add("user", "very long password with special characters !@#$%^&*()")

	f.Fuzz(func(t *testing.T, username, password string) {
		mock := NewMockSecretReadWriter()
		mock.locked = false
		_ = mock.SetSecret(password, password)
		action, err := proxyActionModifySetBasicAuth([]string{username, password}, mock)
		if err != nil {
			return
		}

		req := &http.Request{
			URL:    &url.URL{Scheme: "http", Host: "example.com"},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)

		// Verify authorization header is set
		auth := req.Header.Get("Authorization")
		if auth == "" {
			t.Errorf("Authorization header not set")
		}
		if len(auth) < 6 || auth[:6] != "Basic " {
			t.Errorf("Authorization header doesn't start with 'Basic '")
		}
	})
}

// FuzzProxyActionModifyQueryParam tests query parameter manipulation
func FuzzProxyActionModifyQueryParam(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("key", "value")
	f.Add("", "")
	f.Add("key with spaces", "value with spaces")
	f.Add("key=encoded", "value&encoded")
	f.Add("key", "unicode-日本語")

	f.Fuzz(func(t *testing.T, key, value string) {
		// Test add
		addAction, err := proxyActionModifyAddQueryParam(key, value)
		if err != nil {
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/",
			},
			Header: make(http.Header),
		}

		// Should not panic
		_ = addAction(req)

		// Test set
		setAction, err := proxyActionModifySetQueryParam(key, value)
		if err != nil {
			return
		}
		_ = setAction(req)

		// Test delete
		if key != "" {
			delAction, err := proxyActionModifyDeleteQueryParam(key)
			if err != nil {
				return
			}
			_ = delAction(req)
		}
	})
}

// FuzzProxyActionModifySetScheme tests scheme modification
func FuzzProxyActionModifySetScheme(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("http")
	f.Add("https")
	f.Add("ftp")
	f.Add("")
	f.Add("HTTP")
	f.Add("HTTPS")

	f.Fuzz(func(t *testing.T, scheme string) {
		action, err := proxyActionModifySetScheme(scheme)
		if err != nil {
			// Expected to fail for non-http/https schemes
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/",
			},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)

		// Verify scheme was set
		if req.URL.Scheme != scheme {
			t.Errorf("Scheme not set correctly: got %q, want %q", req.URL.Scheme, scheme)
		}
	})
}

// FuzzProxyActionModifyRewritePath tests regex-based path rewriting
func FuzzProxyActionModifyRewritePath(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("^/api/(.*)$", "/v2/$1")
	f.Add("^/old/(.*)$", "/new/$1")
	f.Add(".*", "/replacement")
	f.Add("[invalid", "/replacement")
	f.Add("^/([^/]+)/([^/]+)$", "/$2/$1")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, pattern, replacement string) {
		action, err := proxyActionModifyRewritePath(pattern, replacement)
		if err != nil {
			// Expected to fail for invalid regex
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/api/users/123",
			},
			Header: make(http.Header),
		}

		// Should not panic
		_ = action(req)
	})
}

// FuzzProxyPolicyAcceptCompile tests full policy compilation
func FuzzProxyPolicyAcceptCompile(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("set_bearer_token", "token123")
	f.Add("set_host", "example.com")
	f.Add("set_path", "/api")
	f.Add("set_header", "X-Custom")
	f.Add("delete_header", "X-Delete")
	f.Add("add_path_prefix", "/v1")
	f.Add("remove_path_prefix", "/old")
	f.Add("set_basic_auth", "user")
	f.Add("add_query_param", "key")
	f.Add("set_scheme", "https")
	f.Add("rewrite_path", "^/api/(.*)$")

	f.Fuzz(func(t *testing.T, actionName, arg1 string) {
		var args []string
		if arg1 != "" {
			args = append(args, arg1)
		}

		// Some actions need 2 args
		if actionName == "set_header" || actionName == "set_basic_auth" ||
			actionName == "add_query_param" || actionName == "rewrite_path" ||
			actionName == "set_query_param" {
			args = append(args, "value")
		}

		policy := &ProxyPolicyAcceptRule{
			Name: "test-policy",
			Match: &ProxyPolicyMatch{
				Host: ".*",
			},
			ActionModify: []ActionModify{
				{
					Name: actionName,
					Args: args,
				},
			},
		}

		// Should not panic
		mock := NewMockSecretReadWriter()
		_ = policy.Compile(mock)
	})
}

// FuzzProxyConfigFind tests policy matching in config
func FuzzProxyConfigFind(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("example.com", "GET", "/api/users")
	f.Add("localhost", "POST", "/")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, host, method, path string) {
		config := &ProxyConfig{
			Policy: &ProxyPolicy{
				AcceptRules: []*ProxyPolicyAcceptRule{
					{
						Name: "allow-all",
						Match: &ProxyPolicyMatch{
							Host: ".*",
						},
					},
				},
				DenyRules: []*ProxyPolicyDenyRule{
					{
						Name: "deny-none",
						Match: &ProxyPolicyMatch{
							Host: "^$", // Match nothing
						},
					},
				},
			},
		}

		mock := NewMockSecretReadWriter()
		_ = config.Policy.Unlock(mock)
		if err := config.Compile(); err != nil {
			return
		}

		req := &http.Request{
			Method: method,
			URL: &url.URL{
				Scheme: "http",
				Host:   host,
				Path:   path,
			},
			Host:   host,
			Header: make(http.Header),
		}

		// Should not panic
		allowed, denied := config.Find(req)

		// Verify only one is set
		if allowed != nil && denied != nil {
			t.Errorf("Both allowed and denied policies matched")
		}
	})
}

// FuzzProxyPolicyModify tests request modification through policy
func FuzzProxyPolicyModify(f *testing.F) {
	if testing.Short() {
		f.Skipf("skipping in short mode")
	}
	f.Add("example.com", "/api", "token123")

	f.Fuzz(func(t *testing.T, host, path, token string) {
		policy := &ProxyPolicyAcceptRule{
			Name: "modify-test",
			Match: &ProxyPolicyMatch{
				Host: ".*",
			},
			ActionModify: []ActionModify{
				{
					Name: "set_host",
					Args: []string{host},
				},
				{
					Name: "set_path",
					Args: []string{path},
				},
				{
					Name: "set_bearer_token",
					Args: []string{token},
				},
			},
		}

		mock := NewMockSecretReadWriter()
		mock.locked = false
		_ = mock.SetSecret(token, token)
		if err := policy.Compile(mock); err != nil {
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "original.com",
				Path:   "/original",
			},
			Host:   "original.com",
			Header: make(http.Header),
		}

		// Should not panic
		policy.Modify(req)
	})
}
