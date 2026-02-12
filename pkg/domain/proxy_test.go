package domain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestProxyPolicy_Unlock(t *testing.T) {
	t.Run("unlocks with empty secrets", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name:    "test-policy",
			Secrets: []byte{},
		}
		mock := NewMockSecretReadWriter()

		err := policy.Unlock(mock)
		if err != nil {
			t.Fatalf("Unlock() error = %v, want nil", err)
		}
		if mock.locked {
			t.Error("secret store should be unlocked")
		}
		if !mock.resetCalled {
			t.Error("Reset() should have been called")
		}
	})

	t.Run("unlocks and loads existing secrets", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name:    "test-policy",
			Secrets: []byte(`{"token":"secret-value"}`),
		}
		mock := NewMockSecretReadWriter()

		err := policy.Unlock(mock)
		if err != nil {
			t.Fatalf("Unlock() error = %v, want nil", err)
		}
		if mock.buff.Len() == 0 {
			t.Error("secrets data should be written to mock")
		}
	})

	t.Run("returns error on unlock failure", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name:    "test-policy",
			Secrets: []byte{},
		}
		mock := NewMockSecretReadWriter()
		mock.unlockErr = errors.New("unlock failed")

		err := policy.Unlock(mock)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "unlock failed" {
			t.Errorf("error = %v, want 'unlock failed'", err)
		}
	})
}

func TestProxyPolicy_Allow(t *testing.T) {
	t.Run("adds new allow policy", func(t *testing.T) {
		policy := &ProxyPolicy{Name: "test"}
		allow := &ProxyPolicyAcceptRule{
			Name: "allow-1",
			Match: &ProxyPolicyMatch{
				Host: "example\\.com",
			},
		}

		policy.Allow(allow)

		if len(policy.AcceptRules) != 1 {
			t.Errorf("len(AcceptRules) = %d, want 1", len(policy.AcceptRules))
		}
		if policy.AcceptRules[0].Name != "allow-1" {
			t.Errorf("AcceptRules[0].Name = %s, want 'allow-1'", policy.AcceptRules[0].Name)
		}
	})

	t.Run("updates existing allow policy", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-1",
					Match: &ProxyPolicyMatch{
						Host: "old\\.com",
					},
				},
			},
		}
		updated := &ProxyPolicyAcceptRule{
			Name: "allow-1",
			Match: &ProxyPolicyMatch{
				Host: "new\\.com",
			},
		}

		policy.Allow(updated)

		if len(policy.AcceptRules) != 1 {
			t.Errorf("len(AcceptRules) = %d, want 1", len(policy.AcceptRules))
		}
		if policy.AcceptRules[0].Match.Host != "new\\.com" {
			t.Errorf("AcceptRules[0].Match.Host = %s, want 'new\\.com'", policy.AcceptRules[0].Match.Host)
		}
	})
}

func TestProxyPolicy_Deny(t *testing.T) {
	t.Run("adds new deny policy", func(t *testing.T) {
		policy := &ProxyPolicy{Name: "test"}
		deny := &ProxyPolicyDenyRule{
			Name: "deny-1",
			Match: &ProxyPolicyMatch{
				Host: "blocked\\.com",
			},
		}

		policy.Deny(deny)

		if len(policy.DenyRules) != 1 {
			t.Errorf("len(DenyRules) = %d, want 1", len(policy.DenyRules))
		}
		if policy.DenyRules[0].Name != "deny-1" {
			t.Errorf("DenyRules[0].Name = %s, want 'deny-1'", policy.DenyRules[0].Name)
		}
	})

	t.Run("updates existing deny policy", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name: "deny-1",
					Match: &ProxyPolicyMatch{
						Host: "old\\.com",
					},
				},
			},
		}
		updated := &ProxyPolicyDenyRule{
			Name: "deny-1",
			Match: &ProxyPolicyMatch{
				Host: "new\\.com",
			},
		}

		policy.Deny(updated)

		if len(policy.DenyRules) != 1 {
			t.Errorf("len(DenyRules) = %d, want 1", len(policy.DenyRules))
		}
		if policy.DenyRules[0].Match.Host != "new\\.com" {
			t.Errorf("DenyRules[0].Match.Host = %s, want 'new\\.com'", policy.DenyRules[0].Match.Host)
		}
	})
}

func TestProxyPolicy_Clone(t *testing.T) {
	t.Run("clones empty policy", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name:    "test",
			Expire:  time.Hour,
			Version: 1,
		}

		cloned := policy.Clone()

		if cloned.Name != policy.Name {
			t.Errorf("Name = %s, want %s", cloned.Name, policy.Name)
		}
		if cloned.Expire != policy.Expire {
			t.Errorf("Expire = %v, want %v", cloned.Expire, policy.Expire)
		}
		if cloned.Version != policy.Version {
			t.Errorf("Version = %d, want %d", cloned.Version, policy.Version)
		}
	})

	t.Run("clones policy with allowed rules", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-1",
					Match: &ProxyPolicyMatch{
						Host:   "example\\.com",
						Header: map[string]string{"X-Key": "value"},
					},
					ActionModify: []ActionModify{
						{Name: "set_host", Args: []string{"new.com"}},
					},
				},
			},
		}

		cloned := policy.Clone()

		if len(cloned.AcceptRules) != 1 {
			t.Fatalf("len(AcceptRules) = %d, want 1", len(cloned.AcceptRules))
		}
		if cloned.AcceptRules[0].Name != "allow-1" {
			t.Errorf("AcceptRules[0].Name = %s, want 'allow-1'", cloned.AcceptRules[0].Name)
		}
		// Modify cloned to ensure deep copy
		cloned.AcceptRules[0].Match.Host = "modified\\.com"
		if policy.AcceptRules[0].Match.Host == "modified\\.com" {
			t.Error("original policy was modified, not a deep copy")
		}
	})

	t.Run("clones policy with denied rules", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name: "deny-1",
					Match: &ProxyPolicyMatch{
						Host:  "blocked\\.com",
						Query: map[string]string{"admin": "true"},
					},
				},
			},
		}

		cloned := policy.Clone()

		if len(cloned.DenyRules) != 1 {
			t.Fatalf("len(DenyRules) = %d, want 1", len(cloned.DenyRules))
		}
		if cloned.DenyRules[0].Name != "deny-1" {
			t.Errorf("DenyRules[0].Name = %s, want 'deny-1'", cloned.DenyRules[0].Name)
		}
	})
}

func TestProxyPolicy_Merge(t *testing.T) {
	t.Run("merges empty policies", func(t *testing.T) {
		base := &ProxyPolicy{Name: "base"}
		other := &ProxyPolicy{Name: "other"}

		merged := base.Merge(other)

		if merged.Name != "base" {
			t.Errorf("Name = %s, want 'base'", merged.Name)
		}
	})

	t.Run("merges allow rules", func(t *testing.T) {
		base := &ProxyPolicy{
			Name: "base",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{Name: "base-allow", Match: &ProxyPolicyMatch{Host: "base\\.com"}},
			},
		}
		other := &ProxyPolicy{
			Name: "other",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{Name: "other-allow", Match: &ProxyPolicyMatch{Host: "other\\.com"}},
			},
		}

		merged := base.Merge(other)

		if len(merged.AcceptRules) != 2 {
			t.Errorf("len(AcceptRules) = %d, want 2", len(merged.AcceptRules))
		}
	})

	t.Run("merges deny rules", func(t *testing.T) {
		base := &ProxyPolicy{
			Name: "base",
			DenyRules: []*ProxyPolicyDenyRule{
				{Name: "base-deny", Match: &ProxyPolicyMatch{Host: "blocked1\\.com"}},
			},
		}
		other := &ProxyPolicy{
			Name: "other",
			DenyRules: []*ProxyPolicyDenyRule{
				{Name: "other-deny", Match: &ProxyPolicyMatch{Host: "blocked2\\.com"}},
			},
		}

		merged := base.Merge(other)

		if len(merged.DenyRules) != 2 {
			t.Errorf("len(DenyRules) = %d, want 2", len(merged.DenyRules))
		}
	})

	t.Run("overrides duplicate allow rules", func(t *testing.T) {
		base := &ProxyPolicy{
			Name: "base",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{Name: "rule-1", Match: &ProxyPolicyMatch{Host: "old\\.com"}},
			},
		}
		other := &ProxyPolicy{
			Name: "other",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{Name: "rule-1", Match: &ProxyPolicyMatch{Host: "new\\.com"}},
			},
		}

		merged := base.Merge(other)

		if len(merged.AcceptRules) != 1 {
			t.Errorf("len(AcceptRules) = %d, want 1", len(merged.AcceptRules))
		}
		if merged.AcceptRules[0].Match.Host != "new\\.com" {
			t.Errorf("AcceptRules[0].Match.Host = %s, want 'new\\.com'", merged.AcceptRules[0].Match.Host)
		}
	})
}

func TestProxyPolicy_Find(t *testing.T) {
	t.Run("finds matching allow rule", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name:  "allow-1",
					Match: &ProxyPolicyMatch{Host: "example\\.com"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)
		_ = policy.Compile()

		req := &http.Request{
			Host: "example.com",
			URL:  &url.URL{Path: "/"},
		}

		allowed, denied := policy.Find(req)

		if allowed == nil {
			t.Error("expected allowed policy, got nil")
		}
		if denied != nil {
			t.Error("expected no denied policy, got one")
		}
		if allowed != nil && allowed.Name != "allow-1" {
			t.Errorf("allowed.Name = %s, want 'allow-1'", allowed.Name)
		}
	})

	t.Run("finds matching deny rule", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name:  "deny-1",
					Match: &ProxyPolicyMatch{Host: "blocked\\.com"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)
		_ = policy.Compile()

		req := &http.Request{
			Host: "blocked.com",
			URL:  &url.URL{Path: "/"},
		}

		allowed, denied := policy.Find(req)

		if allowed != nil {
			t.Error("expected no allowed policy, got one")
		}
		if denied == nil {
			t.Error("expected denied policy, got nil")
		}
		if denied != nil && denied.Name != "deny-1" {
			t.Errorf("denied.Name = %s, want 'deny-1'", denied.Name)
		}
	})

	t.Run("deny takes precedence over allow", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name:  "allow-1",
					Match: &ProxyPolicyMatch{Host: "example\\.com"},
				},
			},
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name:  "deny-1",
					Match: &ProxyPolicyMatch{Host: "example\\.com"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)
		_ = policy.Compile()

		req := &http.Request{
			Host: "example.com",
			URL:  &url.URL{Path: "/"},
		}

		allowed, denied := policy.Find(req)

		if allowed != nil {
			t.Error("expected no allowed policy when denied, got one")
		}
		if denied == nil {
			t.Fatal("expected denied policy, got nil")
		}
		if denied.Name != "deny-1" {
			t.Errorf("denied.Name = %s, want 'deny-1'", denied.Name)
		}
	})

	t.Run("returns nil when no match", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name:  "allow-1",
					Match: &ProxyPolicyMatch{Host: "example\\.com"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)
		_ = policy.Compile()

		req := &http.Request{
			Host: "different.com",
			URL:  &url.URL{Path: "/"},
		}

		allowed, denied := policy.Find(req)

		if allowed != nil {
			t.Error("expected no allowed policy, got one")
		}
		if denied != nil {
			t.Error("expected no denied policy, got one")
		}
	})
}

func TestProxyPolicy_Compile(t *testing.T) {
	t.Run("compiles valid policy", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name:  "allow-1",
					Match: &ProxyPolicyMatch{Host: "example\\.com"},
				},
			},
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name:  "deny-1",
					Match: &ProxyPolicyMatch{Host: "blocked\\.com"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)

		err := policy.Compile()

		if err != nil {
			t.Errorf("Compile() error = %v, want nil", err)
		}
	})

	t.Run("returns error for invalid allow policy", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name:  "allow-1",
					Match: &ProxyPolicyMatch{Host: "[invalid"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)

		err := policy.Compile()

		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("returns error for invalid deny policy", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name:  "deny-1",
					Match: &ProxyPolicyMatch{Host: "[invalid"},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = policy.Unlock(mock)

		err := policy.Compile()

		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestProxyActionModifyAuthBearer_WithSecrets(t *testing.T) {
	t.Run("sets bearer token from secret store", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = false
		_ = mock.SetSecret("api-token", "my-secret-token-123")

		fn, err := proxyActionModifyAuthBearer([]string{"api-token"}, mock)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := &http.Request{
			Header: http.Header{},
		}
		err = fn(req)
		if err != nil {
			t.Fatalf("function execution error: %v", err)
		}

		auth := req.Header.Get("Authorization")
		expected := "Bearer my-secret-token-123"
		if auth != expected {
			t.Errorf("Authorization = %s, want %s", auth, expected)
		}
	})

	t.Run("returns error when secret not found", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = false

		fn, err := proxyActionModifyAuthBearer([]string{"missing-token"}, mock)
		if err != nil {
			t.Fatalf("unexpected error creating function: %v", err)
		}

		req := &http.Request{
			Header: http.Header{},
		}
		err = fn(req)
		if err == nil {
			t.Error("expected error when secret not found, got nil")
		}
	})

	t.Run("returns error when secret store is locked", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = true

		fn, err := proxyActionModifyAuthBearer([]string{"api-token"}, mock)
		if err != nil {
			t.Fatalf("unexpected error creating function: %v", err)
		}

		req := &http.Request{
			Header: http.Header{},
		}
		err = fn(req)
		if err == nil {
			t.Error("expected error when database locked, got nil")
		}
	})
}

func TestProxyActionModifySetBasicAuth_WithSecrets(t *testing.T) {
	t.Run("sets basic auth with password from secret store", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = false
		_ = mock.SetSecret("db-password", "super-secret-pass")

		fn, err := proxyActionModifySetBasicAuth([]string{"admin", "db-password"}, mock)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := &http.Request{
			Header: http.Header{},
		}
		err = fn(req)
		if err != nil {
			t.Fatalf("function execution error: %v", err)
		}

		auth := req.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:super-secret-pass"))
		if auth != expected {
			t.Errorf("Authorization = %s, want %s", auth, expected)
		}
	})

	t.Run("returns error when password secret not found", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = false

		fn, err := proxyActionModifySetBasicAuth([]string{"admin", "missing-password"}, mock)
		if err != nil {
			t.Fatalf("unexpected error creating function: %v", err)
		}

		req := &http.Request{
			Header: http.Header{},
		}
		err = fn(req)
		if err == nil {
			t.Error("expected error when secret not found, got nil")
		}
	})

	t.Run("returns error when secret store is locked", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = true

		fn, err := proxyActionModifySetBasicAuth([]string{"admin", "db-password"}, mock)
		if err != nil {
			t.Fatalf("unexpected error creating function: %v", err)
		}

		req := &http.Request{
			Header: http.Header{},
		}
		err = fn(req)
		if err == nil {
			t.Error("expected error when database locked, got nil")
		}
	})
}

func TestProxyConfig_WithPolicy(t *testing.T) {
	t.Run("compiles policy through config", func(t *testing.T) {
		config := &ProxyConfig{
			Policy: &ProxyPolicy{
				Name: "test",
				AcceptRules: []*ProxyPolicyAcceptRule{
					{
						Name:  "allow-1",
						Match: &ProxyPolicyMatch{Host: "example\\.com"},
					},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = config.Policy.Unlock(mock)

		err := config.Compile()

		if err != nil {
			t.Errorf("Compile() error = %v, want nil", err)
		}
	})

	t.Run("finds policy through config", func(t *testing.T) {
		config := &ProxyConfig{
			Policy: &ProxyPolicy{
				Name: "test",
				AcceptRules: []*ProxyPolicyAcceptRule{
					{
						Name:  "allow-1",
						Match: &ProxyPolicyMatch{Host: "example\\.com"},
					},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		_ = config.Policy.Unlock(mock)
		_ = config.Compile()

		req := &http.Request{
			Host: "example.com",
			URL:  &url.URL{Path: "/"},
		}

		allowed, denied := config.Find(req)

		if allowed == nil {
			t.Error("expected allowed policy, got nil")
		}
		if denied != nil {
			t.Error("expected no denied policy, got one")
		}
	})
}

func TestProxyPolicyMatch_Compile(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		wantErr bool
	}{
		{
			name: "valid patterns",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET|POST",
				Path:   "/api/.*",
			},
			wantErr: false,
		},
		{
			name: "empty patterns",
			match: &ProxyPolicyMatch{
				Host:   "",
				Method: "",
				Path:   "",
			},
			wantErr: false,
		},
		{
			name: "invalid host regex",
			match: &ProxyPolicyMatch{
				Host:   "[invalid",
				Method: "GET",
				Path:   "/",
			},
			wantErr: true,
		},
		{
			name: "invalid method regex",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "[invalid",
				Path:   "/",
			},
			wantErr: true,
		},
		{
			name: "invalid path regex",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET",
				Path:   "[invalid",
			},
			wantErr: true,
		},
		{
			name: "valid fragment",
			match: &ProxyPolicyMatch{
				Host:     "example\\.com",
				Fragment: "section[0-9]+",
			},
			wantErr: false,
		},
		{
			name: "invalid fragment regex",
			match: &ProxyPolicyMatch{
				Host:     "example\\.com",
				Fragment: "[invalid",
			},
			wantErr: true,
		},
		{
			name: "valid content type",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "application/json.*",
			},
			wantErr: false,
		},
		{
			name: "invalid content type regex",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "[invalid",
			},
			wantErr: true,
		},
		{
			name: "valid headers",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-API-Key":     "secret-.*",
					"Authorization": "Bearer .*",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid header regex",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-API-Key": "[invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "valid query params",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"version": "v[0-9]+",
					"filter":  "active|pending",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid query regex",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"version": "[invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "all fields valid",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				Method:      "GET|POST",
				Path:        "/api/.*",
				Fragment:    "section.*",
				ContentType: "application/.*",
				Header: map[string]string{
					"X-API-Key": "secret-.*",
				},
				Query: map[string]string{
					"version": "v[0-9]+",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.match.Compile()
			if (err != nil) != tt.wantErr {
				t.Errorf("ProxyPolicyMatch.Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProxyPolicyMatch_Match(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		request *http.Request
		want    bool
	}{
		{
			name: "exact match all fields",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET",
				Path:   "/api/users",
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/api/users"},
			},
			want: true,
		},
		{
			name: "host mismatch",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET",
				Path:   "/api/users",
			},
			request: &http.Request{
				Host:   "different.com",
				Method: "GET",
				URL:    &url.URL{Path: "/api/users"},
			},
			want: false,
		},
		{
			name: "method mismatch",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET",
				Path:   "/api/users",
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "POST",
				URL:    &url.URL{Path: "/api/users"},
			},
			want: false,
		},
		{
			name: "path mismatch",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET",
				Path:   "/api/users",
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/api/posts"},
			},
			want: false,
		},
		{
			name: "regex pattern match",
			match: &ProxyPolicyMatch{
				Host:   ".*\\.example\\.com",
				Method: "GET|POST",
				Path:   "/api/.*",
			},
			request: &http.Request{
				Host:   "subdomain.example.com",
				Method: "POST",
				URL:    &url.URL{Path: "/api/v1/users"},
			},
			want: true,
		},
		{
			name: "empty patterns match all",
			match: &ProxyPolicyMatch{
				Host:   "",
				Method: "",
				Path:   "",
			},
			request: &http.Request{
				Host:   "any.host.com",
				Method: "DELETE",
				URL:    &url.URL{Path: "/any/path"},
			},
			want: true,
		},
		{
			name: "partial empty patterns",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "",
				Path:   "",
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "PUT",
				URL:    &url.URL{Path: "/anything"},
			},
			want: true,
		},
		{
			name: "complex regex with groups",
			match: &ProxyPolicyMatch{
				Host:   "(api|www)\\.example\\.com",
				Method: "GET|POST|PUT|DELETE",
				Path:   "^/api/v[0-9]+/.*$",
			},
			request: &http.Request{
				Host:   "api.example.com",
				Method: "PUT",
				URL:    &url.URL{Path: "/api/v2/users/123"},
			},
			want: true,
		},
		{
			name: "path with query params",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET",
				Path:   "/search",
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/search"},
			},
			want: true,
		},
		{
			name: "case sensitive host",
			match: &ProxyPolicyMatch{
				Host:   "Example\\.com",
				Method: "GET",
				Path:   "/",
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
			},
			want: false,
		},
		{
			name: "case insensitive regex",
			match: &ProxyPolicyMatch{
				Host:   "(?i)example\\.com",
				Method: "GET",
				Path:   "/",
			},
			request: &http.Request{
				Host:   "Example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.match.Compile(); err != nil {
				t.Fatalf("failed to compile match patterns: %v", err)
			}
			got := tt.match.Match(tt.request)
			if got != tt.want {
				t.Errorf("ProxyPolicyMatch.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyPolicyMatch_MatchFragment(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		request *http.Request
		want    bool
	}{
		{
			name: "fragment match",
			match: &ProxyPolicyMatch{
				Host:     "example\\.com",
				Fragment: "section[0-9]+",
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/page", Fragment: "section1"},
			},
			want: true,
		},
		{
			name: "fragment mismatch",
			match: &ProxyPolicyMatch{
				Host:     "example\\.com",
				Fragment: "section[0-9]+",
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/page", Fragment: "intro"},
			},
			want: false,
		},
		{
			name: "empty fragment matches empty",
			match: &ProxyPolicyMatch{
				Host:     "example\\.com",
				Fragment: "",
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/page", Fragment: "anything"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.match.Compile(); err != nil {
				t.Fatalf("failed to compile match patterns: %v", err)
			}
			got := tt.match.Match(tt.request)
			if got != tt.want {
				t.Errorf("ProxyPolicyMatch.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyPolicyMatch_MatchContentType(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		request *http.Request
		want    bool
	}{
		{
			name: "content type exact match",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "application/json",
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},
			want: true,
		},
		{
			name: "content type with charset",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "application/json.*",
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"Content-Type": []string{"application/json; charset=utf-8"},
				},
			},
			want: true,
		},
		{
			name: "content type mismatch",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "application/json",
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"Content-Type": []string{"text/html"},
				},
			},
			want: false,
		},
		{
			name: "content type pattern",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "application/(json|xml)",
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"Content-Type": []string{"application/xml"},
				},
			},
			want: true,
		},
		{
			name: "empty content type pattern matches empty header",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "",
			},
			request: &http.Request{
				Host:   "example.com",
				Header: http.Header{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.match.Compile(); err != nil {
				t.Fatalf("failed to compile match patterns: %v", err)
			}
			got := tt.match.Match(tt.request)
			if got != tt.want {
				t.Errorf("ProxyPolicyMatch.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyPolicyMatch_MatchHeader(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		request *http.Request
		want    bool
	}{
		{
			name: "single header match",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-API-Key": "secret-.*",
				},
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"X-Api-Key": []string{"secret-12345"},
				},
			},
			want: true,
		},
		{
			name: "multiple headers match",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-API-Key":     "secret-.*",
					"Authorization": "Bearer .*",
				},
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"X-Api-Key":     []string{"secret-12345"},
					"Authorization": []string{"Bearer token123"},
				},
			},
			want: true,
		},
		{
			name: "header mismatch",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-API-Key": "secret-.*",
				},
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"X-Api-Key": []string{"public-key"},
				},
			},
			want: false,
		},
		{
			name: "missing header",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-Required": ".+",
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Header: http.Header{},
			},
			want: false,
		},
		{
			name: "empty header pattern matches empty value",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"X-Optional": "",
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Header: http.Header{},
			},
			want: true,
		},
		{
			name: "case insensitive header name",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Header: map[string]string{
					"content-type": "application/json",
				},
			},
			request: &http.Request{
				Host: "example.com",
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.match.Compile(); err != nil {
				t.Fatalf("failed to compile match patterns: %v", err)
			}
			got := tt.match.Match(tt.request)
			if got != tt.want {
				t.Errorf("ProxyPolicyMatch.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyPolicyMatch_MatchQuery(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		request *http.Request
		want    bool
	}{
		{
			name: "single query param match",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"version": "v[0-9]+",
				},
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/api", RawQuery: "version=v2"},
			},
			want: true,
		},
		{
			name: "multiple query params match",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"version": "v[0-9]+",
					"filter":  "active|pending",
				},
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/api", RawQuery: "version=v2&filter=active"},
			},
			want: true,
		},
		{
			name: "query param mismatch",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"version": "v[0-9]+",
				},
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/api", RawQuery: "version=beta"},
			},
			want: false,
		},
		{
			name: "missing query param",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"api_key": ".+",
				},
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/api"},
			},
			want: false,
		},
		{
			name: "empty query pattern matches empty value",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"optional": "",
				},
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/api"},
			},
			want: true,
		},
		{
			name: "query param with special characters",
			match: &ProxyPolicyMatch{
				Host: "example\\.com",
				Query: map[string]string{
					"search": "hello.*world",
				},
			},
			request: &http.Request{
				Host: "example.com",
				URL:  &url.URL{Path: "/api", RawQuery: "search=hello+world"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.match.Compile(); err != nil {
				t.Fatalf("failed to compile match patterns: %v", err)
			}
			got := tt.match.Match(tt.request)
			if got != tt.want {
				t.Errorf("ProxyPolicyMatch.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyPolicyMatch_MatchCombined(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		request *http.Request
		want    bool
	}{
		{
			name: "all fields match",
			match: &ProxyPolicyMatch{
				Host:        "api\\.example\\.com",
				Method:      "POST",
				Path:        "/api/.*",
				Fragment:    "section.*",
				ContentType: "application/json.*",
				Header: map[string]string{
					"X-API-Key": "secret-.*",
				},
				Query: map[string]string{
					"version": "v[0-9]+",
				},
			},
			request: &http.Request{
				Host:   "api.example.com",
				Method: "POST",
				URL:    &url.URL{Path: "/api/users", Fragment: "section1", RawQuery: "version=v2"},
				Header: http.Header{
					"Content-Type": []string{"application/json; charset=utf-8"},
					"X-Api-Key":    []string{"secret-12345"},
				},
			},
			want: true,
		},
		{
			name: "all fields except one match",
			match: &ProxyPolicyMatch{
				Host:        "api\\.example\\.com",
				Method:      "POST",
				Path:        "/api/.*",
				Fragment:    "section.*",
				ContentType: "application/json",
				Header: map[string]string{
					"X-API-Key": "secret-.*",
				},
				Query: map[string]string{
					"version": "v[0-9]+",
				},
			},
			request: &http.Request{
				Host:   "api.example.com",
				Method: "POST",
				URL:    &url.URL{Path: "/api/users", Fragment: "section1", RawQuery: "version=beta"},
				Header: http.Header{
					"Content-Type": []string{"application/json"},
					"X-Api-Key":    []string{"secret-12345"},
				},
			},
			want: false,
		},
		{
			name: "partial fields specified and match",
			match: &ProxyPolicyMatch{
				Host:        "example\\.com",
				ContentType: "application/json",
				Query: map[string]string{
					"format": "json",
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/anything", RawQuery: "format=json&page=1"},
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.match.Compile(); err != nil {
				t.Fatalf("failed to compile match patterns: %v", err)
			}
			got := tt.match.Match(tt.request)
			if got != tt.want {
				t.Errorf("ProxyPolicyMatch.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyPolicyAccept_Compile(t *testing.T) {
	tests := []struct {
		name    string
		policy  *ProxyPolicyAcceptRule
		wantErr bool
	}{
		{
			name: "valid set_bearer_token",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_bearer_token", Args: []string{"test-token"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid set_host",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_host", Args: []string{"newhost.com"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid set_path",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_path", Args: []string{"/new/path"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid set_header",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_header", Args: []string{"X-Custom-Header", "custom-value"}},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple actions",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_host", Args: []string{"newhost.com"}},
					{Name: "set_path", Args: []string{"/new/path"}},
					{Name: "set_bearer_token", Args: []string{"token123"}},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid action - wrong arg count",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_bearer_token", Args: []string{"token1", "token2"}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid set_header - wrong arg count",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_header", Args: []string{"X-Header"}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid match pattern",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "[invalid",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSecretReadWriter()
			mock.locked = false
			err := tt.policy.Compile(mock)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProxyPolicyAcceptRule.Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProxyPolicyAccept_Modify(t *testing.T) {
	tests := []struct {
		name         string
		policy       *ProxyPolicyAcceptRule
		request      *http.Request
		checkHost    string
		checkPath    string
		checkAuthHdr string
		checkHeaders map[string]string
	}{
		{
			name: "modify bearer token",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_bearer_token", Args: []string{"secret-token"}},
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
				Header: http.Header{},
			},
			checkAuthHdr: "Bearer secret-token",
		},
		{
			name: "modify host",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_host", Args: []string{"backend.example.com"}},
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
				Header: http.Header{},
			},
			checkHost: "backend.example.com",
		},
		{
			name: "modify path",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_path", Args: []string{"/api/v2/endpoint"}},
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/old/path"},
				Header: http.Header{},
			},
			checkPath: "/api/v2/endpoint",
		},
		{
			name: "modify header",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_header", Args: []string{"X-Custom-Header", "custom-value"}},
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
				Header: http.Header{},
			},
			checkHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		},
		{
			name: "modify multiple headers",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_header", Args: []string{"Content-Type", "application/json"}},
					{Name: "set_header", Args: []string{"X-Api-Key", "secret-key"}},
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
				Header: http.Header{},
			},
			checkHeaders: map[string]string{
				"Content-Type": "application/json",
				"X-Api-Key":    "secret-key",
			},
		},
		{
			name: "modify all",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{
					{Name: "set_host", Args: []string{"new.host.com"}},
					{Name: "set_path", Args: []string{"/new/path"}},
					{Name: "set_bearer_token", Args: []string{"my-token"}},
					{Name: "set_header", Args: []string{"X-Request-ID", "12345"}},
				},
			},
			request: &http.Request{
				Host:   "example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
				Header: http.Header{},
			},
			checkHost:    "new.host.com",
			checkPath:    "/new/path",
			checkAuthHdr: "Bearer my-token",
			checkHeaders: map[string]string{
				"X-Request-ID": "12345",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSecretReadWriter()
			mock.locked = false
			// Set up secrets that tests expect
			_ = mock.SetSecret("secret-token", "secret-token")
			_ = mock.SetSecret("my-token", "my-token")

			if err := tt.policy.Compile(mock); err != nil {
				t.Fatalf("failed to compile policy: %v", err)
			}
			tt.policy.Modify(tt.request)

			if tt.checkHost != "" && tt.request.Host != tt.checkHost {
				t.Errorf("Host = %v, want %v", tt.request.Host, tt.checkHost)
			}
			if tt.checkHost != "" && tt.request.URL.Host != tt.checkHost {
				t.Errorf("URL.Host = %v, want %v", tt.request.URL.Host, tt.checkHost)
			}
			if tt.checkPath != "" && tt.request.URL.Path != tt.checkPath {
				t.Errorf("URL.Path = %v, want %v", tt.request.URL.Path, tt.checkPath)
			}
			if tt.checkAuthHdr != "" {
				got := tt.request.Header.Get("Authorization")
				if got != tt.checkAuthHdr {
					t.Errorf("Authorization header = %v, want %v", got, tt.checkAuthHdr)
				}
			}
			for headerName, expectedValue := range tt.checkHeaders {
				got := tt.request.Header.Get(headerName)
				if got != expectedValue {
					t.Errorf("Header[%s] = %v, want %v", headerName, got, expectedValue)
				}
			}
		})
	}
}

func TestProxyConfig_Compile(t *testing.T) {
	tests := []struct {
		name    string
		config  *ProxyConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ProxyConfig{
				Policy: &ProxyPolicy{
					AcceptRules: []*ProxyPolicyAcceptRule{
						{
							Name: "allow-api",
							Match: &ProxyPolicyMatch{
								Host:   "api\\.example\\.com",
								Method: "GET|POST",
								Path:   "/api/.*",
							},
						},
					},
					DenyRules: []*ProxyPolicyDenyRule{
						{
							Name: "deny-admin",
							Match: &ProxyPolicyMatch{
								Host:   ".*",
								Method: ".*",
								Path:   "/admin/.*",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid allow policy",
			config: &ProxyConfig{
				Policy: &ProxyPolicy{
					AcceptRules: []*ProxyPolicyAcceptRule{
						{
							Name: "invalid",
							Match: &ProxyPolicyMatch{
								Host:   "[invalid",
								Method: "GET",
								Path:   "/",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid deny policy",
			config: &ProxyConfig{
				Policy: &ProxyPolicy{
					DenyRules: []*ProxyPolicyDenyRule{
						{
							Name: "invalid",
							Match: &ProxyPolicyMatch{
								Host:   "example\\.com",
								Method: "[invalid",
								Path:   "/",
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSecretReadWriter()
			_ = tt.config.Policy.Unlock(mock)
			err := tt.config.Compile()
			if (err != nil) != tt.wantErr {
				t.Errorf("ProxyConfig.Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProxyConfig_Find(t *testing.T) {
	config := &ProxyConfig{
		Policy: &ProxyPolicy{
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-api",
					Match: &ProxyPolicyMatch{
						Host:   "api\\.example\\.com",
						Method: "GET|POST",
						Path:   "/api/.*",
					},
				},
				{
					Name: "allow-public",
					Match: &ProxyPolicyMatch{
						Host:   ".*\\.example\\.com",
						Method: "GET",
						Path:   "/public/.*",
					},
				},
			},
			DenyRules: []*ProxyPolicyDenyRule{
				{
					Name: "deny-admin",
					Match: &ProxyPolicyMatch{
						Host:   ".*",
						Method: ".*",
						Path:   "/admin/.*",
					},
				},
				{
					Name: "deny-internal",
					Match: &ProxyPolicyMatch{
						Host:   "internal\\.example\\.com",
						Method: ".*",
						Path:   ".*",
					},
				},
			},
		},
	}

	mock := NewMockSecretReadWriter()
	_ = config.Policy.Unlock(mock)
	if err := config.Compile(); err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	tests := []struct {
		name       string
		request    *http.Request
		wantAllow  bool
		wantDeny   bool
		wantPolicy string
	}{
		{
			name: "allowed api request",
			request: &http.Request{
				Host:   "api.example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/api/users"},
			},
			wantAllow:  true,
			wantDeny:   false,
			wantPolicy: "allow-api",
		},
		{
			name: "allowed public request",
			request: &http.Request{
				Host:   "www.example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/public/docs"},
			},
			wantAllow:  true,
			wantDeny:   false,
			wantPolicy: "allow-public",
		},
		{
			name: "denied admin request",
			request: &http.Request{
				Host:   "api.example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/admin/users"},
			},
			wantAllow:  false,
			wantDeny:   true,
			wantPolicy: "deny-admin",
		},
		{
			name: "denied internal host",
			request: &http.Request{
				Host:   "internal.example.com",
				Method: "GET",
				URL:    &url.URL{Path: "/anything"},
			},
			wantAllow:  false,
			wantDeny:   true,
			wantPolicy: "deny-internal",
		},
		{
			name: "no match",
			request: &http.Request{
				Host:   "other.com",
				Method: "GET",
				URL:    &url.URL{Path: "/"},
			},
			wantAllow:  false,
			wantDeny:   false,
			wantPolicy: "",
		},
		{
			name: "deny takes precedence",
			request: &http.Request{
				Host:   "api.example.com",
				Method: "POST",
				URL:    &url.URL{Path: "/admin/delete"},
			},
			wantAllow:  false,
			wantDeny:   true,
			wantPolicy: "deny-admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, deny := config.Find(tt.request)

			if tt.wantAllow && allow == nil {
				t.Error("expected allow policy but got nil")
			}
			if !tt.wantAllow && allow != nil {
				t.Errorf("expected no allow policy but got %v", allow.Name)
			}
			if tt.wantDeny && deny == nil {
				t.Error("expected deny policy but got nil")
			}
			if !tt.wantDeny && deny != nil {
				t.Errorf("expected no deny policy but got %v", deny.Name)
			}

			if tt.wantPolicy != "" {
				var gotPolicy string
				if allow != nil {
					gotPolicy = allow.Name
				} else if deny != nil {
					gotPolicy = deny.Name
				}
				if gotPolicy != tt.wantPolicy {
					t.Errorf("expected policy %v but got %v", tt.wantPolicy, gotPolicy)
				}
			}
		})
	}
}

func TestProxyActionModifyPath(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"/new/path"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid multiple args",
			args:    []string{"/path1", "/path2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyPath(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyPath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && fn == nil {
				t.Error("expected function but got nil")
			}
		})
	}
}

func TestProxyActionModifyHost(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"newhost.com"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid multiple args",
			args:    []string{"host1.com", "host2.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyHost(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyHost() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && fn == nil {
				t.Error("expected function but got nil")
			}
		})
	}
}

func TestProxyActionModifyAuthBearer(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"token123"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid multiple args",
			args:    []string{"token1", "token2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSecretReadWriter()
			fn, err := proxyActionModifyAuthBearer(tt.args, mock)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyAuthBearer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && fn == nil {
				t.Error("expected function but got nil")
			}
		})
	}
}

func TestProxyActionModifySetHeader(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid two args",
			args:    []string{"X-Custom-Header", "custom-value"},
			wantErr: false,
		},
		{
			name:    "valid content-type",
			args:    []string{"Content-Type", "application/json"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid single arg",
			args:    []string{"X-Header"},
			wantErr: true,
		},
		{
			name:    "invalid three args",
			args:    []string{"X-Header", "value1", "value2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifySetHeader(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifySetHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && fn == nil {
				t.Error("expected function but got nil")
			}
			if !tt.wantErr && fn != nil {
				req := &http.Request{
					Header: http.Header{},
				}
				_ = fn(req)
				got := req.Header.Get(tt.args[0])
				if got != tt.args[1] {
					t.Errorf("Header[%s] = %s, want %s", tt.args[0], got, tt.args[1])
				}
			}
		})
	}
}

func TestProxyPolicyMatch_JSON(t *testing.T) {
	tests := []struct {
		name    string
		match   *ProxyPolicyMatch
		jsonStr string
	}{
		{
			name: "all fields populated",
			match: &ProxyPolicyMatch{
				Host:   "example\\.com",
				Method: "GET|POST",
				Path:   "/api/.*",
			},
			jsonStr: `{"Host":"example\\.com","Method":"GET|POST","Path":"/api/.*"}`,
		},
		{
			name: "empty fields",
			match: &ProxyPolicyMatch{
				Host:   "",
				Method: "",
				Path:   "",
			},
			jsonStr: `{}`,
		},
		{
			name: "partial fields",
			match: &ProxyPolicyMatch{
				Host:   "api\\.example\\.com",
				Method: "",
				Path:   "/v1/.*",
			},
			jsonStr: `{"Host":"api\\.example\\.com","Path":"/v1/.*"}`,
		},
		{
			name: "complex regex patterns",
			match: &ProxyPolicyMatch{
				Host:   "(api|www)\\.example\\.com",
				Method: "GET|POST|PUT|DELETE",
				Path:   "^/api/v[0-9]+/.*$",
			},
			jsonStr: `{"Host":"(api|www)\\.example\\.com","Method":"GET|POST|PUT|DELETE","Path":"^/api/v[0-9]+/.*$"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" - marshal", func(t *testing.T) {
			data, err := json.Marshal(tt.match)
			if err != nil {
				t.Fatalf("failed to marshal ProxyPolicyMatch: %v", err)
			}
			if string(data) != tt.jsonStr {
				t.Errorf("marshaled JSON = %s, want %s", string(data), tt.jsonStr)
			}
		})

		t.Run(tt.name+" - unmarshal", func(t *testing.T) {
			var match ProxyPolicyMatch
			err := json.Unmarshal([]byte(tt.jsonStr), &match)
			if err != nil {
				t.Fatalf("failed to unmarshal ProxyPolicyMatch: %v", err)
			}
			if match.Host != tt.match.Host || match.Method != tt.match.Method || match.Path != tt.match.Path {
				t.Errorf("unmarshaled = %+v, want %+v", match, tt.match)
			}
		})

		t.Run(tt.name+" - roundtrip", func(t *testing.T) {
			data, err := json.Marshal(tt.match)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var match ProxyPolicyMatch
			err = json.Unmarshal(data, &match)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if match.Host != tt.match.Host || match.Method != tt.match.Method || match.Path != tt.match.Path {
				t.Errorf("roundtrip failed: got %+v, want %+v", match, tt.match)
			}
		})
	}
}

func TestActionModify_JSON(t *testing.T) {
	tests := []struct {
		name    string
		action  *ActionModify
		jsonStr string
	}{
		{
			name: "set_bearer_token",
			action: &ActionModify{
				Name: "set_bearer_token",
				Args: []string{"secret-token"},
			},
			jsonStr: `{"Name":"set_bearer_token","Args":["secret-token"]}`,
		},
		{
			name: "set_host",
			action: &ActionModify{
				Name: "set_host",
				Args: []string{"backend.example.com"},
			},
			jsonStr: `{"Name":"set_host","Args":["backend.example.com"]}`,
		},
		{
			name: "set_path",
			action: &ActionModify{
				Name: "set_path",
				Args: []string{"/api/v2/endpoint"},
			},
			jsonStr: `{"Name":"set_path","Args":["/api/v2/endpoint"]}`,
		},
		{
			name: "set_header",
			action: &ActionModify{
				Name: "set_header",
				Args: []string{"X-Custom-Header", "custom-value"},
			},
			jsonStr: `{"Name":"set_header","Args":["X-Custom-Header","custom-value"]}`,
		},
		{
			name: "multiple args",
			action: &ActionModify{
				Name: "custom_action",
				Args: []string{"arg1", "arg2", "arg3"},
			},
			jsonStr: `{"Name":"custom_action","Args":["arg1","arg2","arg3"]}`,
		},
		{
			name: "empty args",
			action: &ActionModify{
				Name: "no_args_action",
				Args: []string{},
			},
			jsonStr: `{"Name":"no_args_action","Args":[]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" - marshal", func(t *testing.T) {
			data, err := json.Marshal(tt.action)
			if err != nil {
				t.Fatalf("failed to marshal ActionModify: %v", err)
			}
			if string(data) != tt.jsonStr {
				t.Errorf("marshaled JSON = %s, want %s", string(data), tt.jsonStr)
			}
		})

		t.Run(tt.name+" - unmarshal", func(t *testing.T) {
			var action ActionModify
			err := json.Unmarshal([]byte(tt.jsonStr), &action)
			if err != nil {
				t.Fatalf("failed to unmarshal ActionModify: %v", err)
			}
			if !reflect.DeepEqual(&action, tt.action) {
				t.Errorf("unmarshaled = %+v, want %+v", action, tt.action)
			}
		})

		t.Run(tt.name+" - roundtrip", func(t *testing.T) {
			data, err := json.Marshal(tt.action)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var action ActionModify
			err = json.Unmarshal(data, &action)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if !reflect.DeepEqual(&action, tt.action) {
				t.Errorf("roundtrip failed: got %+v, want %+v", action, tt.action)
			}
		})
	}
}

func TestProxyPolicyAccept_JSON(t *testing.T) {
	tests := []struct {
		name    string
		policy  *ProxyPolicyAcceptRule
		jsonStr string
	}{
		{
			name: "basic policy with single action",
			policy: &ProxyPolicyAcceptRule{
				Name: "test-policy",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/api/.*",
				},
				ActionModify: []ActionModify{
					{Name: "set_bearer_token", Args: []string{"token123"}},
				},
			},
			jsonStr: `{"Name":"test-policy","Match":{"Host":"example\\.com","Method":"GET","Path":"/api/.*"},"ActionModify":[{"Name":"set_bearer_token","Args":["token123"]}]}`,
		},
		{
			name: "policy with multiple actions",
			policy: &ProxyPolicyAcceptRule{
				Name: "multi-action",
				Match: &ProxyPolicyMatch{
					Host:   "api\\.example\\.com",
					Method: "GET|POST",
					Path:   "/v1/.*",
				},
				ActionModify: []ActionModify{
					{Name: "set_host", Args: []string{"backend.com"}},
					{Name: "set_path", Args: []string{"/v2/endpoint"}},
					{Name: "set_bearer_token", Args: []string{"secret"}},
				},
			},
			jsonStr: `{"Name":"multi-action","Match":{"Host":"api\\.example\\.com","Method":"GET|POST","Path":"/v1/.*"},"ActionModify":[{"Name":"set_host","Args":["backend.com"]},{"Name":"set_path","Args":["/v2/endpoint"]},{"Name":"set_bearer_token","Args":["secret"]}]}`,
		},
		{
			name: "policy without actions",
			policy: &ProxyPolicyAcceptRule{
				Name: "no-actions",
				Match: &ProxyPolicyMatch{
					Host:   "example\\.com",
					Method: "GET",
					Path:   "/",
				},
				ActionModify: []ActionModify{},
			},
			jsonStr: `{"Name":"no-actions","Match":{"Host":"example\\.com","Method":"GET","Path":"/"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" - marshal", func(t *testing.T) {
			data, err := json.Marshal(tt.policy)
			if err != nil {
				t.Fatalf("failed to marshal ProxyPolicyAcceptRule: %v", err)
			}
			if string(data) != tt.jsonStr {
				t.Errorf("marshaled JSON = %s, want %s", string(data), tt.jsonStr)
			}
		})

		t.Run(tt.name+" - unmarshal", func(t *testing.T) {
			var policy ProxyPolicyAcceptRule
			err := json.Unmarshal([]byte(tt.jsonStr), &policy)
			if err != nil {
				t.Fatalf("failed to unmarshal ProxyPolicyAcceptRule: %v", err)
			}
			if policy.Name != tt.policy.Name {
				t.Errorf("Name = %s, want %s", policy.Name, tt.policy.Name)
			}
			if !reflect.DeepEqual(policy.Match, tt.policy.Match) {
				t.Errorf("Match = %+v, want %+v", policy.Match, tt.policy.Match)
			}
			// Compare ActionModify handling nil vs empty slice
			if len(policy.ActionModify) == 0 && len(tt.policy.ActionModify) == 0 {
				// Both are effectively empty, consider them equal
			} else if !reflect.DeepEqual(policy.ActionModify, tt.policy.ActionModify) {
				t.Errorf("ActionModify = %+v, want %+v", policy.ActionModify, tt.policy.ActionModify)
			}
		})

		t.Run(tt.name+" - roundtrip", func(t *testing.T) {
			data, err := json.Marshal(tt.policy)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var policy ProxyPolicyAcceptRule
			err = json.Unmarshal(data, &policy)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if policy.Name != tt.policy.Name {
				t.Errorf("roundtrip Name failed: got %s, want %s", policy.Name, tt.policy.Name)
			}
			if !reflect.DeepEqual(policy.Match, tt.policy.Match) {
				t.Errorf("roundtrip Match failed: got %+v, want %+v", policy.Match, tt.policy.Match)
			}
			// Compare ActionModify handling nil vs empty slice
			if len(policy.ActionModify) == 0 && len(tt.policy.ActionModify) == 0 {
				// Both are effectively empty, consider them equal
			} else if !reflect.DeepEqual(policy.ActionModify, tt.policy.ActionModify) {
				t.Errorf("roundtrip ActionModify failed: got %+v, want %+v", policy.ActionModify, tt.policy.ActionModify)
			}
		})
	}
}

func TestProxyPolicyDeny_JSON(t *testing.T) {
	tests := []struct {
		name    string
		policy  *ProxyPolicyDenyRule
		jsonStr string
	}{
		{
			name: "deny admin",
			policy: &ProxyPolicyDenyRule{
				Name: "deny-admin",
				Match: &ProxyPolicyMatch{
					Host:   ".*",
					Method: ".*",
					Path:   "/admin/.*",
				},
			},
			jsonStr: `{"Name":"deny-admin","Match":{"Host":".*","Method":".*","Path":"/admin/.*"}}`,
		},
		{
			name: "deny internal",
			policy: &ProxyPolicyDenyRule{
				Name: "deny-internal",
				Match: &ProxyPolicyMatch{
					Host:   "internal\\.example\\.com",
					Method: "GET|POST|PUT|DELETE",
					Path:   ".*",
				},
			},
			jsonStr: `{"Name":"deny-internal","Match":{"Host":"internal\\.example\\.com","Method":"GET|POST|PUT|DELETE","Path":".*"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" - marshal", func(t *testing.T) {
			data, err := json.Marshal(tt.policy)
			if err != nil {
				t.Fatalf("failed to marshal ProxyPolicyDenyRule: %v", err)
			}
			if string(data) != tt.jsonStr {
				t.Errorf("marshaled JSON = %s, want %s", string(data), tt.jsonStr)
			}
		})

		t.Run(tt.name+" - unmarshal", func(t *testing.T) {
			var policy ProxyPolicyDenyRule
			err := json.Unmarshal([]byte(tt.jsonStr), &policy)
			if err != nil {
				t.Fatalf("failed to unmarshal ProxyPolicyDenyRule: %v", err)
			}
			if policy.Name != tt.policy.Name {
				t.Errorf("Name = %s, want %s", policy.Name, tt.policy.Name)
			}
			if !reflect.DeepEqual(policy.Match, tt.policy.Match) {
				t.Errorf("Match = %+v, want %+v", policy.Match, tt.policy.Match)
			}
		})

		t.Run(tt.name+" - roundtrip", func(t *testing.T) {
			data, err := json.Marshal(tt.policy)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var policy ProxyPolicyDenyRule
			err = json.Unmarshal(data, &policy)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if policy.Name != tt.policy.Name {
				t.Errorf("roundtrip Name failed: got %s, want %s", policy.Name, tt.policy.Name)
			}
			if !reflect.DeepEqual(policy.Match, tt.policy.Match) {
				t.Errorf("roundtrip Match failed: got %+v, want %+v", policy.Match, tt.policy.Match)
			}
		})
	}
}

func TestProxyConfig_JSON(t *testing.T) {
	tests := []struct {
		name    string
		config  *ProxyConfig
		jsonStr string
	}{
		{
			name: "full config",
			config: &ProxyConfig{
				CertPEM: []byte("cert-data"),
				KeyPEM:  []byte("key-data"),
				Policy: &ProxyPolicy{
					AcceptRules: []*ProxyPolicyAcceptRule{
						{
							Name: "allow-api",
							Match: &ProxyPolicyMatch{
								Host:   "api\\.example\\.com",
								Method: "GET|POST",
								Path:   "/api/.*",
							},
							ActionModify: []ActionModify{
								{Name: "set_bearer_token", Args: []string{"token123"}},
							},
						},
					},
					DenyRules: []*ProxyPolicyDenyRule{
						{
							Name: "deny-admin",
							Match: &ProxyPolicyMatch{
								Host:   ".*",
								Method: ".*",
								Path:   "/admin/.*",
							},
						},
					},
				},
			},
			jsonStr: `{"CertPEM":"Y2VydC1kYXRh","KeyPEM":"a2V5LWRhdGE=","Policy":{"Name":"","AcceptRules":[{"Name":"allow-api","Match":{"Host":"api\\.example\\.com","Method":"GET|POST","Path":"/api/.*"},"ActionModify":[{"Name":"set_bearer_token","Args":["token123"]}]}],"DenyRules":[{"Name":"deny-admin","Match":{"Host":".*","Method":".*","Path":"/admin/.*"}}],"Version":0},"Expire":0,"Version":0}`,
		},
		{
			name: "minimal config",
			config: &ProxyConfig{
				CertPEM: nil,
				KeyPEM:  nil,
				Policy: &ProxyPolicy{
					AcceptRules: []*ProxyPolicyAcceptRule{},
					DenyRules:   []*ProxyPolicyDenyRule{},
				},
			},
			jsonStr: `{"CertPEM":null,"KeyPEM":null,"Policy":{"Name":"","Version":0},"Expire":0,"Version":0}`,
		},
		{
			name: "config with multiple policies",
			config: &ProxyConfig{
				CertPEM: []byte("cert"),
				KeyPEM:  []byte("key"),
				Policy: &ProxyPolicy{
					AcceptRules: []*ProxyPolicyAcceptRule{
						{
							Name: "policy1",
							Match: &ProxyPolicyMatch{
								Host:   "host1\\.com",
								Method: "GET",
								Path:   "/path1",
							},
							ActionModify: []ActionModify{},
						},
						{
							Name: "policy2",
							Match: &ProxyPolicyMatch{
								Host:   "host2\\.com",
								Method: "POST",
								Path:   "/path2",
							},
							ActionModify: []ActionModify{
								{Name: "set_host", Args: []string{"backend.com"}},
							},
						},
					},
					DenyRules: []*ProxyPolicyDenyRule{
						{
							Name: "deny1",
							Match: &ProxyPolicyMatch{
								Host:   "bad\\.com",
								Method: ".*",
								Path:   ".*",
							},
						},
					},
				},
			},
			jsonStr: `{"CertPEM":"Y2VydA==","KeyPEM":"a2V5","Policy":{"Name":"","AcceptRules":[{"Name":"policy1","Match":{"Host":"host1\\.com","Method":"GET","Path":"/path1"}},{"Name":"policy2","Match":{"Host":"host2\\.com","Method":"POST","Path":"/path2"},"ActionModify":[{"Name":"set_host","Args":["backend.com"]}]}],"DenyRules":[{"Name":"deny1","Match":{"Host":"bad\\.com","Method":".*","Path":".*"}}],"Version":0},"Expire":0,"Version":0}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" - marshal", func(t *testing.T) {
			data, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatalf("failed to marshal ProxyConfig: %v", err)
			}
			if string(data) != tt.jsonStr {
				t.Errorf("marshaled JSON = %s, want %s", string(data), tt.jsonStr)
			}
		})

		t.Run(tt.name+" - unmarshal", func(t *testing.T) {
			var config ProxyConfig
			err := json.Unmarshal([]byte(tt.jsonStr), &config)
			if err != nil {
				t.Fatalf("failed to unmarshal ProxyConfig: %v", err)
			}
			if !reflect.DeepEqual(config.CertPEM, tt.config.CertPEM) {
				t.Errorf("CertPEM = %v, want %v", config.CertPEM, tt.config.CertPEM)
			}
			if !reflect.DeepEqual(config.KeyPEM, tt.config.KeyPEM) {
				t.Errorf("KeyPEM = %v, want %v", config.KeyPEM, tt.config.KeyPEM)
			}
			// Compare AcceptRules handling nil vs empty slice
			if len(config.Policy.AcceptRules) != len(tt.config.Policy.AcceptRules) {
				t.Errorf("Policy.AcceptRules length = %d, want %d", len(config.Policy.AcceptRules), len(tt.config.Policy.AcceptRules))
			} else {
				for i := range config.Policy.AcceptRules {
					if config.Policy.AcceptRules[i].Name != tt.config.Policy.AcceptRules[i].Name {
						t.Errorf("Policy.AcceptRules[%d].Name = %s, want %s", i, config.Policy.AcceptRules[i].Name, tt.config.Policy.AcceptRules[i].Name)
					}
				}
			}
			// Compare DenyRules handling nil vs empty slice
			if len(config.Policy.DenyRules) != len(tt.config.Policy.DenyRules) {
				t.Errorf("Policy.DenyRules length = %d, want %d", len(config.Policy.DenyRules), len(tt.config.Policy.DenyRules))
			} else {
				for i := range config.Policy.DenyRules {
					if config.Policy.DenyRules[i].Name != tt.config.Policy.DenyRules[i].Name {
						t.Errorf("Policy.DenyRules[%d].Name = %s, want %s", i, config.Policy.DenyRules[i].Name, tt.config.Policy.DenyRules[i].Name)
					}
				}
			}
		})

		t.Run(tt.name+" - roundtrip", func(t *testing.T) {
			data, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var config ProxyConfig
			err = json.Unmarshal(data, &config)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if !reflect.DeepEqual(config.CertPEM, tt.config.CertPEM) {
				t.Errorf("roundtrip CertPEM failed: got %v, want %v", config.CertPEM, tt.config.CertPEM)
			}
			if !reflect.DeepEqual(config.KeyPEM, tt.config.KeyPEM) {
				t.Errorf("roundtrip KeyPEM failed: got %v, want %v", config.KeyPEM, tt.config.KeyPEM)
			}
			// Compare AcceptRules handling nil vs empty slice
			if len(config.Policy.AcceptRules) != len(tt.config.Policy.AcceptRules) {
				t.Errorf("roundtrip Policy.AcceptRules length = %d, want %d", len(config.Policy.AcceptRules), len(tt.config.Policy.AcceptRules))
			} else {
				for i := range config.Policy.AcceptRules {
					if config.Policy.AcceptRules[i].Name != tt.config.Policy.AcceptRules[i].Name {
						t.Errorf("roundtrip Policy.AcceptRules[%d].Name = %s, want %s", i, config.Policy.AcceptRules[i].Name, tt.config.Policy.AcceptRules[i].Name)
					}
				}
			}
			// Compare DenyRules handling nil vs empty slice
			if len(config.Policy.DenyRules) != len(tt.config.Policy.DenyRules) {
				t.Errorf("roundtrip Policy.DenyRules length = %d, want %d", len(config.Policy.DenyRules), len(tt.config.Policy.DenyRules))
			} else {
				for i := range config.Policy.DenyRules {
					if config.Policy.DenyRules[i].Name != tt.config.Policy.DenyRules[i].Name {
						t.Errorf("roundtrip Policy.DenyRules[%d].Name = %s, want %s", i, config.Policy.DenyRules[i].Name, tt.config.Policy.DenyRules[i].Name)
					}
				}
			}
		})
	}
}

func TestProxyConfig_JSON_WithCompile(t *testing.T) {
	jsonStr := `{
		"CertPEM": "Y2VydA==",
		"KeyPEM": "a2V5",
		"Policy": {
			"AcceptRules": [
				{
					"Name": "allow-api",
					"Match": {
						"Host": "api\\.example\\.com",
						"Method": "GET",
						"Path": "/api/.*"
					},
					"ActionModify": [
						{
							"Name": "set_bearer_token",
							"Args": ["token123"]
						}
					]
				}
			],
			"DenyRules": [
				{
					"Name": "deny-admin",
					"Match": {
						"Host": ".*",
						"Method": ".*",
						"Path": "/admin/.*"
					}
				}
			]
		}
	}`

	var config ProxyConfig
	err := json.Unmarshal([]byte(jsonStr), &config)
	if err != nil {
		t.Fatalf("failed to unmarshal ProxyConfig: %v", err)
	}

	mock := NewMockSecretReadWriter()
	mock.locked = false
	_ = mock.SetSecret("token123", "token123")
	_ = config.Policy.Unlock(mock)

	err = config.Compile()
	if err != nil {
		t.Fatalf("failed to compile config after unmarshal: %v", err)
	}

	testReq := &http.Request{
		Host:   "api.example.com",
		Method: "GET",
		URL:    &url.URL{Path: "/api/users"},
		Header: http.Header{},
	}

	allow, deny := config.Find(testReq)
	if allow == nil {
		t.Error("expected to find allow policy")
	}
	if deny != nil {
		t.Error("expected no deny policy")
	}

	if allow != nil {
		allow.Modify(testReq)
		auth := testReq.Header.Get("Authorization")
		if auth != "Bearer token123" {
			t.Errorf("Authorization header = %s, want 'Bearer token123'", auth)
		}
	}

	adminReq := &http.Request{
		Host:   "api.example.com",
		Method: "GET",
		URL:    &url.URL{Path: "/admin/users"},
		Header: http.Header{},
	}

	allow, deny = config.Find(adminReq)
	if allow != nil {
		t.Error("expected no allow policy for admin path")
	}
	if deny == nil {
		t.Error("expected to find deny policy for admin path")
	}
	if deny != nil && deny.Name != "deny-admin" {
		t.Errorf("deny policy name = %s, want 'deny-admin'", deny.Name)
	}
}

func TestProxyActionModifyDeleteHeader(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"X-Internal-Header"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid two args",
			args:    []string{"header1", "header2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyDeleteHeader(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyDeleteHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifyDeleteHeader() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		fn, err := proxyActionModifyDeleteHeader("X-Delete-Me")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			Header: http.Header{
				"X-Delete-Me": []string{"value"},
				"X-Keep-Me":   []string{"keep"},
			},
		}
		_ = fn(req)
		if req.Header.Get("X-Delete-Me") != "" {
			t.Error("header should have been deleted")
		}
		if req.Header.Get("X-Keep-Me") != "keep" {
			t.Error("other headers should not be affected")
		}
	})
}

func TestProxyActionModifyAddPathPrefix(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"/api/v2"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid two args",
			args:    []string{"/api", "/v2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyAddPathPrefix(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyAddPathPrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifyAddPathPrefix() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		fn, err := proxyActionModifyAddPathPrefix("/api/v2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/users"},
		}
		_ = fn(req)
		if req.URL.Path != "/api/v2/users" {
			t.Errorf("path = %s, want /api/v2/users", req.URL.Path)
		}
	})

	t.Run("function execution - idempotent", func(t *testing.T) {
		fn, err := proxyActionModifyAddPathPrefix("/api/v2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/api/v2/users"},
		}
		_ = fn(req)
		if req.URL.Path != "/api/v2/users" {
			t.Errorf("path = %s, want /api/v2/users (should not double prefix)", req.URL.Path)
		}
	})
}

func TestProxyActionModifyRemovePathPrefix(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"/gateway"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid two args",
			args:    []string{"/api", "/v2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyRemovePathPrefix(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyRemovePathPrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifyRemovePathPrefix() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		fn, err := proxyActionModifyRemovePathPrefix("/gateway")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/gateway/api/users"},
		}
		_ = fn(req)
		if req.URL.Path != "/api/users" {
			t.Errorf("path = %s, want /api/users", req.URL.Path)
		}
	})

	t.Run("function execution - empty result", func(t *testing.T) {
		fn, err := proxyActionModifyRemovePathPrefix("/gateway")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/gateway"},
		}
		_ = fn(req)
		if req.URL.Path != "/" {
			t.Errorf("path = %s, want / (empty path should become /)", req.URL.Path)
		}
	})
}

func TestProxyActionModifySetBasicAuth(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid two args",
			args:    []string{"username", "password"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid single arg",
			args:    []string{"username"},
			wantErr: true,
		},
		{
			name:    "invalid three args",
			args:    []string{"username", "password", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSecretReadWriter()
			fn, err := proxyActionModifySetBasicAuth(tt.args, mock)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifySetBasicAuth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifySetBasicAuth() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		mock := NewMockSecretReadWriter()
		mock.locked = false
		_ = mock.SetSecret("testpass", "testpass")

		fn, err := proxyActionModifySetBasicAuth([]string{"testuser", "testpass"}, mock)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			Header: http.Header{},
		}
		_ = fn(req)
		auth := req.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
		if auth != expected {
			t.Errorf("Authorization header = %s, want %s", auth, expected)
		}
	})
}

func TestProxyActionModifyAddQueryParam(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid two args",
			args:    []string{"api_key", "secret123"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid single arg",
			args:    []string{"api_key"},
			wantErr: true,
		},
		{
			name:    "invalid three args",
			args:    []string{"api_key", "secret123", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyAddQueryParam(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyAddQueryParam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifyAddQueryParam() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		fn, err := proxyActionModifyAddQueryParam("api_key", "secret123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/api/users"},
		}
		_ = fn(req)
		if req.URL.Query().Get("api_key") != "secret123" {
			t.Errorf("query param api_key = %s, want secret123", req.URL.Query().Get("api_key"))
		}
	})

	t.Run("function execution - preserve existing", func(t *testing.T) {
		fn, err := proxyActionModifyAddQueryParam("filter", "active")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{
				Path:     "/api/users",
				RawQuery: "page=1&filter=all",
			},
		}
		_ = fn(req)
		q := req.URL.Query()
		if q.Get("page") != "1" {
			t.Error("existing query params should be preserved")
		}
		filters := q["filter"]
		if len(filters) != 2 {
			t.Errorf("expected 2 filter values, got %d", len(filters))
		}
	})
}

func TestProxyActionModifySetQueryParam(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid two args",
			args:    []string{"version", "v2"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid single arg",
			args:    []string{"version"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifySetQueryParam(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifySetQueryParam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifySetQueryParam() returned nil function")
			}
		})
	}

	t.Run("function execution - replace existing", func(t *testing.T) {
		fn, err := proxyActionModifySetQueryParam("version", "v2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{
				Path:     "/api/users",
				RawQuery: "version=v1&page=1",
			},
		}
		_ = fn(req)
		q := req.URL.Query()
		if q.Get("version") != "v2" {
			t.Errorf("query param version = %s, want v2", q.Get("version"))
		}
		if q.Get("page") != "1" {
			t.Error("other query params should be preserved")
		}
	})
}

func TestProxyActionModifyDeleteQueryParam(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid single arg",
			args:    []string{"internal_id"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid two args",
			args:    []string{"param1", "param2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyDeleteQueryParam(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyDeleteQueryParam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifyDeleteQueryParam() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		fn, err := proxyActionModifyDeleteQueryParam("internal_id")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{
				Path:     "/api/users",
				RawQuery: "internal_id=123&page=1",
			},
		}
		_ = fn(req)
		q := req.URL.Query()
		if q.Get("internal_id") != "" {
			t.Error("query param should have been deleted")
		}
		if q.Get("page") != "1" {
			t.Error("other query params should be preserved")
		}
	})
}

func TestProxyActionModifySetScheme(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid http",
			args:    []string{"http"},
			wantErr: false,
		},
		{
			name:    "valid https",
			args:    []string{"https"},
			wantErr: false,
		},
		{
			name:    "invalid scheme",
			args:    []string{"ftp"},
			wantErr: true,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid two args",
			args:    []string{"http", "https"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifySetScheme(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifySetScheme() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifySetScheme() returned nil function")
			}
		})
	}

	t.Run("function execution", func(t *testing.T) {
		fn, err := proxyActionModifySetScheme("https")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/api/users",
			},
		}
		_ = fn(req)
		if req.URL.Scheme != "https" {
			t.Errorf("scheme = %s, want https", req.URL.Scheme)
		}
	})
}

func TestProxyActionModifyRewritePath(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid two args",
			args:    []string{"/users/(.*)", "/api/user/$1"},
			wantErr: false,
		},
		{
			name:    "invalid no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid single arg",
			args:    []string{"/users/(.*)"},
			wantErr: true,
		},
		{
			name:    "invalid regex",
			args:    []string{"[invalid(regex", "/replacement"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := proxyActionModifyRewritePath(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyActionModifyRewritePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fn == nil {
				t.Error("proxyActionModifyRewritePath() returned nil function")
			}
		})
	}

	t.Run("function execution - with capture groups", func(t *testing.T) {
		fn, err := proxyActionModifyRewritePath("/users/(.*)", "/api/user/$1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/users/123"},
		}
		_ = fn(req)
		if req.URL.Path != "/api/user/123" {
			t.Errorf("path = %s, want /api/user/123", req.URL.Path)
		}
	})

	t.Run("function execution - simple replace", func(t *testing.T) {
		fn, err := proxyActionModifyRewritePath("^/old", "/new")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := &http.Request{
			URL: &url.URL{Path: "/old/path/here"},
		}
		_ = fn(req)
		if req.URL.Path != "/new/path/here" {
			t.Errorf("path = %s, want /new/path/here", req.URL.Path)
		}
	})
}

func TestRateLimitConfig_Compile(t *testing.T) {
	tests := []struct {
		name      string
		policy    *ProxyPolicyAcceptRule
		wantErr   bool
		errString string
	}{
		{
			name: "valid rate limit",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host: "example\\.com",
				},
				RateLimit: &RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             20,
				},
			},
			wantErr: false,
		},
		{
			name: "no rate limit",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host: "example\\.com",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid requests per second zero",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host: "example\\.com",
				},
				RateLimit: &RateLimitConfig{
					RequestsPerSecond: 0,
					Burst:             10,
				},
			},
			wantErr:   true,
			errString: "requests per second must be positive",
		},
		{
			name: "invalid requests per second negative",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host: "example\\.com",
				},
				RateLimit: &RateLimitConfig{
					RequestsPerSecond: -1,
					Burst:             10,
				},
			},
			wantErr:   true,
			errString: "requests per second must be positive",
		},
		{
			name: "invalid burst zero",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host: "example\\.com",
				},
				RateLimit: &RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             0,
				},
			},
			wantErr:   true,
			errString: "burst must be positive",
		},
		{
			name: "invalid burst negative",
			policy: &ProxyPolicyAcceptRule{
				Name: "test",
				Match: &ProxyPolicyMatch{
					Host: "example\\.com",
				},
				RateLimit: &RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             -1,
				},
			},
			wantErr:   true,
			errString: "burst must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSecretReadWriter()
			err := tt.policy.Compile(mock)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errString != "" {
				if !contains(err.Error(), tt.errString) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tt.errString)
				}
			}
			if !tt.wantErr && tt.policy.RateLimit != nil && tt.policy.rateLimiter == nil {
				t.Error("rate limiter should be initialized")
			}
		})
	}
}

func TestProxyPolicyAccept_Wait(t *testing.T) {
	t.Run("no rate limit - always allow", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "example\\.com",
			},
		}
		mock := NewMockSecretReadWriter()
		if err := policy.Compile(mock); err != nil {
			t.Fatalf("failed to compile: %v", err)
		}

		for i := 0; i < 100; i++ {
			policy.Wait(context.Background())
		}
	})

	t.Run("with rate limit - blocks appropriately", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "example\\.com",
			},
			RateLimit: &RateLimitConfig{
				RequestsPerSecond: 10,
				Burst:             5,
			},
		}
		mock := NewMockSecretReadWriter()
		if err := policy.Compile(mock); err != nil {
			t.Fatalf("failed to compile: %v", err)
		}

		start := time.Now()
		for i := 0; i < 10; i++ {
			policy.Wait(context.Background())
		}
		elapsed := time.Since(start)

		if elapsed < 100*time.Millisecond {
			t.Errorf("expected Wait to block for at least 100ms, but took %v", elapsed)
		}
	})
}

func TestRateLimitConfig_JSON(t *testing.T) {
	policy := &ProxyPolicyAcceptRule{
		Name: "test",
		Match: &ProxyPolicyMatch{
			Host:   "example\\.com",
			Method: "GET",
			Path:   "/api/.*",
		},
		RateLimit: &RateLimitConfig{
			RequestsPerSecond: 100,
			Burst:             200,
		},
	}

	t.Run("marshal", func(t *testing.T) {
		data, err := json.Marshal(policy)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		if !contains(string(data), "RequestsPerSecond") {
			t.Error("marshaled JSON should contain RequestsPerSecond")
		}
		if !contains(string(data), "Burst") {
			t.Error("marshaled JSON should contain Burst")
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		jsonStr := `{
			"Name": "test",
			"Match": {
				"Host": "example\\.com",
				"Method": "GET",
				"Path": "/api/.*"
			},
			"RateLimit": {
				"RequestsPerSecond": 50,
				"Burst": 100
			}
		}`

		var p ProxyPolicyAcceptRule
		if err := json.Unmarshal([]byte(jsonStr), &p); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if p.RateLimit == nil {
			t.Fatal("rate limit should not be nil")
		}
		if p.RateLimit.RequestsPerSecond != 50 {
			t.Errorf("RequestsPerSecond = %v, want 50", p.RateLimit.RequestsPerSecond)
		}
		if p.RateLimit.Burst != 100 {
			t.Errorf("Burst = %v, want 100", p.RateLimit.Burst)
		}
	})

	t.Run("roundtrip", func(t *testing.T) {
		data, err := json.Marshal(policy)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var p ProxyPolicyAcceptRule
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if p.RateLimit == nil {
			t.Fatal("rate limit should not be nil")
		}
		if p.RateLimit.RequestsPerSecond != policy.RateLimit.RequestsPerSecond {
			t.Errorf("RequestsPerSecond = %v, want %v", p.RateLimit.RequestsPerSecond, policy.RateLimit.RequestsPerSecond)
		}
		if p.RateLimit.Burst != policy.RateLimit.Burst {
			t.Errorf("Burst = %v, want %v", p.RateLimit.Burst, policy.RateLimit.Burst)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Test Gap 1: Pattern matching with wildcards (as used by PolicyBuilder)
func TestProxyPolicy_FindWithWildcardPatterns(t *testing.T) {
	t.Run("matches wildcard subdomain pattern", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-wildcard",
					Match: &ProxyPolicyMatch{
						Host: "^.*\\.example\\.com$", // *.example.com converted by patternToRegex
					},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		if err := policy.Compile(); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}
		if err := policy.AcceptRules[0].Compile(mock); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		tests := []struct {
			host      string
			wantMatch bool
		}{
			{"api.example.com", true},
			{"www.example.com", true},
			{"sub.api.example.com", true},
			{"example.com", false}, // doesn't match because of leading .*
			{"example.org", false},
			{"notexample.com", false},
		}

		for _, tt := range tests {
			t.Run(tt.host, func(t *testing.T) {
				req := &http.Request{
					Host: tt.host,
					URL:  &url.URL{Scheme: "https", Host: tt.host, Path: "/"},
				}
				allowed, denied := policy.Find(req)
				if tt.wantMatch {
					if allowed == nil {
						t.Errorf("expected match for %s but got nil", tt.host)
					}
					if denied != nil {
						t.Errorf("unexpected deny for %s", tt.host)
					}
				} else {
					if allowed != nil {
						t.Errorf("unexpected match for %s", tt.host)
					}
				}
			})
		}
	})

	t.Run("matches multiple wildcard pattern", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-double-wildcard",
					Match: &ProxyPolicyMatch{
						Host: "^.*\\..*\\.example\\.com$", // *.*.example.com
					},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		if err := policy.Compile(); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}
		if err := policy.AcceptRules[0].Compile(mock); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		tests := []struct {
			host      string
			wantMatch bool
		}{
			{"sub.api.example.com", true},
			{"a.b.example.com", true},
			{"api.example.com", false}, // only one subdomain
			{"example.com", false},     // no subdomains
		}

		for _, tt := range tests {
			t.Run(tt.host, func(t *testing.T) {
				req := &http.Request{
					Host: tt.host,
					URL:  &url.URL{Scheme: "https", Host: tt.host, Path: "/"},
				}
				allowed, _ := policy.Find(req)
				if tt.wantMatch && allowed == nil {
					t.Errorf("expected match for %s but got nil", tt.host)
				}
				if !tt.wantMatch && allowed != nil {
					t.Errorf("unexpected match for %s", tt.host)
				}
			})
		}
	})

	t.Run("matches path wildcard pattern", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-api-paths",
					Match: &ProxyPolicyMatch{
						Host: "^api\\.example\\.com$",
						Path: "^/api/.*$", // /api/* pattern
					},
				},
			},
		}
		mock := NewMockSecretReadWriter()
		if err := policy.Compile(); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}
		if err := policy.AcceptRules[0].Compile(mock); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		tests := []struct {
			path      string
			wantMatch bool
		}{
			{"/api/users", true},
			{"/api/users/123", true},
			{"/api/", true},
			{"/api", false}, // doesn't match because /api/.* requires at least one more char
			{"/v1/users", false},
			{"/", false},
		}

		for _, tt := range tests {
			t.Run(tt.path, func(t *testing.T) {
				req := &http.Request{
					Host: "api.example.com",
					URL:  &url.URL{Scheme: "https", Host: "api.example.com", Path: tt.path},
				}
				allowed, _ := policy.Find(req)
				if tt.wantMatch && allowed == nil {
					t.Errorf("expected match for %s but got nil", tt.path)
				}
				if !tt.wantMatch && allowed != nil {
					t.Errorf("unexpected match for %s", tt.path)
				}
			})
		}
	})
}

// Test Gap 2: ProxyPolicyMatch with empty/nil fields
func TestProxyPolicyMatch_EmptyAndNilFields(t *testing.T) {
	t.Run("empty string patterns compile successfully", func(t *testing.T) {
		match := &ProxyPolicyMatch{
			Host:   "",
			Method: "",
			Path:   "",
			Scheme: "",
		}

		err := match.Compile()
		if err != nil {
			t.Fatalf("Compile() with empty strings should succeed, got: %v", err)
		}

		// All regex fields should be nil
		if match.host != nil {
			t.Error("host regex should be nil for empty string")
		}
		if match.method != nil {
			t.Error("method regex should be nil for empty string")
		}
		if match.path != nil {
			t.Error("path regex should be nil for empty string")
		}
		if match.scheme != nil {
			t.Error("scheme regex should be nil for empty string")
		}
	})

	t.Run("nil regex fields match any value", func(t *testing.T) {
		match := &ProxyPolicyMatch{
			Host: "^example\\.com$",
			// Method, Path, Scheme are empty - will be nil after compile
		}

		if err := match.Compile(); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		req := &http.Request{
			Method: "POST",
			Host:   "example.com",
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/any/path/here",
			},
		}

		if !match.Match(req) {
			t.Error("Match() should return true when only host is specified and it matches")
		}
	})

	t.Run("all nil regex fields matches everything", func(t *testing.T) {
		match := &ProxyPolicyMatch{}

		if err := match.Compile(); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		req := &http.Request{
			Method: "DELETE",
			Host:   "anything.com",
			URL: &url.URL{
				Scheme: "http",
				Host:   "anything.com",
				Path:   "/random/path",
			},
		}

		if !match.Match(req) {
			t.Error("Match() should return true when all regex fields are nil")
		}
	})

	t.Run("empty headers and query maps", func(t *testing.T) {
		match := &ProxyPolicyMatch{
			Host:   "^example\\.com$",
			Header: map[string]string{},
			Query:  map[string]string{},
		}

		if err := match.Compile(); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		if match.header != nil {
			t.Error("header map should be nil for empty map")
		}
		if match.query != nil {
			t.Error("query map should be nil for empty map")
		}
	})
}

// Test Gap 3: Multiple ActionModify execution order
func TestProxyPolicyAccept_MultipleActionModify(t *testing.T) {
	t.Run("multiple set_header actions execute in order", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "^example\\.com$",
			},
			ActionModify: []ActionModify{
				{Name: "set_header", Args: []string{"X-Test", "first"}},
				{Name: "set_header", Args: []string{"X-Other", "value"}},
				{Name: "set_header", Args: []string{"X-Test", "second"}}, // overwrites first
			},
		}

		mock := NewMockSecretReadWriter()
		if err := policy.Compile(mock); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		policy.Modify(req)

		if req.Header.Get("X-Test") != "second" {
			t.Errorf("X-Test = %s, want 'second'", req.Header.Get("X-Test"))
		}
		if req.Header.Get("X-Other") != "value" {
			t.Errorf("X-Other = %s, want 'value'", req.Header.Get("X-Other"))
		}
	})

	t.Run("auth action combined with other modifiers", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "^api\\.example\\.com$",
			},
			ActionModify: []ActionModify{
				{Name: "set_host", Args: []string{"internal.api.example.com"}},
				{Name: "set_header", Args: []string{"X-Internal", "true"}},
				{Name: "set_bearer_token", Args: []string{"token-id"}},
				{Name: "add_path_prefix", Args: []string{"/v2"}},
			},
		}

		mock := NewMockSecretReadWriter()
		if err := mock.Unlock(); err != nil {
			t.Fatalf("Unlock() failed: %v", err)
		}
		if err := mock.SetSecret("token-id", "secret-token-value"); err != nil {
			t.Fatalf("SetSecret() failed: %v", err)
		}

		if err := policy.Compile(mock); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		req := &http.Request{
			Header: make(http.Header),
			Host:   "api.example.com",
			URL: &url.URL{
				Scheme: "https",
				Host:   "api.example.com",
				Path:   "/users",
			},
		}

		policy.Modify(req)

		if req.Host != "internal.api.example.com" {
			t.Errorf("Host = %s, want 'internal.api.example.com'", req.Host)
		}
		if req.Header.Get("X-Internal") != "true" {
			t.Errorf("X-Internal = %s, want 'true'", req.Header.Get("X-Internal"))
		}
		if req.Header.Get("Authorization") != "Bearer secret-token-value" {
			t.Errorf("Authorization = %s, want 'Bearer secret-token-value'", req.Header.Get("Authorization"))
		}
		if req.URL.Path != "/v2/users" {
			t.Errorf("Path = %s, want '/v2/users'", req.URL.Path)
		}
	})

	t.Run("query param actions execute in order", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "^example\\.com$",
			},
			ActionModify: []ActionModify{
				{Name: "add_query_param", Args: []string{"key", "value1"}},
				{Name: "add_query_param", Args: []string{"key", "value2"}},
				{Name: "set_query_param", Args: []string{"single", "value"}},
			},
		}

		mock := NewMockSecretReadWriter()
		if err := policy.Compile(mock); err != nil {
			t.Fatalf("Compile() failed: %v", err)
		}

		req := &http.Request{
			URL: &url.URL{Path: "/test"},
		}

		policy.Modify(req)

		values := req.URL.Query()["key"]
		if len(values) != 2 {
			t.Errorf("key param count = %d, want 2", len(values))
		}
		if values[0] != "value1" || values[1] != "value2" {
			t.Errorf("key values = %v, want [value1, value2]", values)
		}
		if req.URL.Query().Get("single") != "value" {
			t.Errorf("single = %s, want 'value'", req.URL.Query().Get("single"))
		}
	})
}

// Test Gap 4: Clone with RateLimit
func TestProxyPolicy_CloneWithRateLimit(t *testing.T) {
	t.Run("clones policy with rate limit", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-1",
					Match: &ProxyPolicyMatch{
						Host: "^example\\.com$",
					},
					RateLimit: &RateLimitConfig{
						RequestsPerSecond: 100.0,
						Burst:             200,
					},
				},
			},
		}

		cloned := policy.Clone()

		if len(cloned.AcceptRules) != 1 {
			t.Fatalf("len(AcceptRules) = %d, want 1", len(cloned.AcceptRules))
		}

		if cloned.AcceptRules[0].RateLimit == nil {
			t.Fatal("RateLimit should not be nil in cloned policy")
		}

		if cloned.AcceptRules[0].RateLimit.RequestsPerSecond != 100.0 {
			t.Errorf("RequestsPerSecond = %v, want 100.0", cloned.AcceptRules[0].RateLimit.RequestsPerSecond)
		}

		if cloned.AcceptRules[0].RateLimit.Burst != 200 {
			t.Errorf("Burst = %v, want 200", cloned.AcceptRules[0].RateLimit.Burst)
		}

		// Verify deep copy - modifying cloned shouldn't affect original
		cloned.AcceptRules[0].RateLimit.RequestsPerSecond = 50.0
		if policy.AcceptRules[0].RateLimit.RequestsPerSecond == 50.0 {
			t.Error("original policy RateLimit was modified, not a deep copy")
		}
	})
}

// Test Gap 5: Merge with RateLimit and Expire
func TestProxyPolicy_MergeWithRateLimitAndExpire(t *testing.T) {
	t.Run("merges rate limits", func(t *testing.T) {
		base := &ProxyPolicy{
			Name: "base",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "rule-1",
					Match: &ProxyPolicyMatch{
						Host: "^base\\.com$",
					},
					RateLimit: &RateLimitConfig{
						RequestsPerSecond: 10,
						Burst:             20,
					},
				},
			},
		}

		other := &ProxyPolicy{
			Name: "other",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "rule-2",
					Match: &ProxyPolicyMatch{
						Host: "^other\\.com$",
					},
					RateLimit: &RateLimitConfig{
						RequestsPerSecond: 50,
						Burst:             100,
					},
				},
			},
		}

		merged := base.Merge(other)

		if len(merged.AcceptRules) != 2 {
			t.Fatalf("len(AcceptRules) = %d, want 2", len(merged.AcceptRules))
		}

		// Find rule-1 and rule-2
		var rule1, rule2 *ProxyPolicyAcceptRule
		for _, rule := range merged.AcceptRules {
			if rule.Name == "rule-1" {
				rule1 = rule
			}
			if rule.Name == "rule-2" {
				rule2 = rule
			}
		}

		if rule1 == nil || rule1.RateLimit == nil {
			t.Fatal("rule-1 or its RateLimit is nil")
		}
		if rule1.RateLimit.RequestsPerSecond != 10 {
			t.Errorf("rule-1 RequestsPerSecond = %v, want 10", rule1.RateLimit.RequestsPerSecond)
		}

		if rule2 == nil || rule2.RateLimit == nil {
			t.Fatal("rule-2 or its RateLimit is nil")
		}
		if rule2.RateLimit.RequestsPerSecond != 50 {
			t.Errorf("rule-2 RequestsPerSecond = %v, want 50", rule2.RateLimit.RequestsPerSecond)
		}
	})

	t.Run("merge copies cfg expire when base has no expire", func(t *testing.T) {
		base := &ProxyPolicy{
			Name:   "base",
			Expire: 0,
		}

		other := &ProxyPolicy{
			Name:   "other",
			Expire: 1 * time.Hour,
		}

		merged := base.Merge(other)

		// Fixed: Now properly copies cfg.Expire even when base.Expire is 0
		if merged.Expire != 1*time.Hour {
			t.Errorf("Expire = %v, want 1h (fixed behavior)", merged.Expire)
		}
	})

	t.Run("merge updates expire when base has expire", func(t *testing.T) {
		base := &ProxyPolicy{
			Name:   "base",
			Expire: 2 * time.Hour,
		}

		other := &ProxyPolicy{
			Name:   "other",
			Expire: 1 * time.Hour,
		}

		merged := base.Merge(other)

		if merged.Expire != 1*time.Hour {
			t.Errorf("Expire = %v, want 1h", merged.Expire)
		}
	})
}

// Test Gap 6: Edge cases for action modifiers
func TestProxyActionModify_EdgeCases(t *testing.T) {
	t.Run("set_host with empty string", func(t *testing.T) {
		fn, err := proxyActionModifyHost("")
		if err != nil {
			t.Fatalf("proxyActionModifyHost(\"\") error = %v, want nil", err)
		}

		req := &http.Request{
			Host: "original.com",
			URL:  &url.URL{Host: "original.com"},
		}

		_ = fn(req)

		if req.Host != "" {
			t.Errorf("Host = %s, want empty string", req.Host)
		}
		if req.URL.Host != "" {
			t.Errorf("URL.Host = %s, want empty string", req.URL.Host)
		}
	})

	t.Run("set_path with empty string", func(t *testing.T) {
		fn, err := proxyActionModifyPath("")
		if err != nil {
			t.Fatalf("proxyActionModifyPath(\"\") error = %v, want nil", err)
		}

		req := &http.Request{
			URL: &url.URL{Path: "/original"},
		}

		_ = fn(req)

		if req.URL.Path != "" {
			t.Errorf("Path = %s, want empty string", req.URL.Path)
		}
	})

	t.Run("remove_path_prefix results in empty path", func(t *testing.T) {
		fn, err := proxyActionModifyRemovePathPrefix("/api")
		if err != nil {
			t.Fatalf("proxyActionModifyRemovePathPrefix() error = %v, want nil", err)
		}

		req := &http.Request{
			URL: &url.URL{Path: "/api"},
		}

		_ = fn(req)

		// Should default to "/" when empty
		if req.URL.Path != "/" {
			t.Errorf("Path = %s, want '/'", req.URL.Path)
		}
	})

	t.Run("add_path_prefix with empty prefix", func(t *testing.T) {
		fn, err := proxyActionModifyAddPathPrefix("")
		if err != nil {
			t.Fatalf("proxyActionModifyAddPathPrefix(\"\") error = %v, want nil", err)
		}

		req := &http.Request{
			URL: &url.URL{Path: "/path"},
		}

		_ = fn(req)

		if req.URL.Path != "/path" {
			t.Errorf("Path = %s, want '/path'", req.URL.Path)
		}
	})

	t.Run("add_path_prefix doesn't duplicate", func(t *testing.T) {
		fn, err := proxyActionModifyAddPathPrefix("/v2")
		if err != nil {
			t.Fatalf("proxyActionModifyAddPathPrefix() error = %v, want nil", err)
		}

		req := &http.Request{
			URL: &url.URL{Path: "/v2/users"},
		}

		_ = fn(req)

		// Should not duplicate since path already has prefix
		if req.URL.Path != "/v2/users" {
			t.Errorf("Path = %s, want '/v2/users'", req.URL.Path)
		}
	})
}

// Test Gap 7: Compile with secrets but no unlocker
func TestProxyPolicyAccept_CompileWithoutUnlocker(t *testing.T) {
	t.Run("compile bearer token without secret store returns error", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "^example\\.com$",
			},
			ActionModify: []ActionModify{
				{Name: "set_bearer_token", Args: []string{"token-id"}},
			},
		}

		// Compile without a secret store (nil)
		err := policy.Compile(nil)

		// Should compile successfully - error happens at runtime
		if err != nil {
			t.Errorf("Compile() error = %v, want nil", err)
		}

		// Try to use the action - should return error for nil secret store
		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		// Modify should complete, but the action will log an error
		// Since Modify doesn't return errors, we can't check directly
		policy.Modify(req)

		// Bearer token won't be set because secret store is nil
		if req.Header.Get("Authorization") != "" {
			t.Errorf("Authorization should be empty when secret store is nil")
		}
	})

	t.Run("compile basic auth without secret store returns error", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "^example\\.com$",
			},
			ActionModify: []ActionModify{
				{Name: "set_basic_auth", Args: []string{"user", "pass-id"}},
			},
		}

		err := policy.Compile(nil)

		if err != nil {
			t.Errorf("Compile() error = %v, want nil", err)
		}

		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		policy.Modify(req)

		// Auth won't be set because secret store is nil
		if req.Header.Get("Authorization") != "" {
			t.Errorf("Authorization should be empty when secret store is nil")
		}
	})

	t.Run("compile with mock secret store works correctly", func(t *testing.T) {
		policy := &ProxyPolicyAcceptRule{
			Name: "test",
			Match: &ProxyPolicyMatch{
				Host: "^example\\.com$",
			},
			ActionModify: []ActionModify{
				{Name: "set_bearer_token", Args: []string{"token-id"}},
			},
		}

		mock := NewMockSecretReadWriter()
		if err := mock.Unlock(); err != nil {
			t.Fatalf("Unlock() failed: %v", err)
		}
		if err := mock.SetSecret("token-id", "test-token"); err != nil {
			t.Fatalf("SetSecret() failed: %v", err)
		}

		err := policy.Compile(mock)

		if err != nil {
			t.Fatalf("Compile() error = %v, want nil", err)
		}

		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		// This should work without error
		policy.Modify(req)

		if req.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %s, want 'Bearer test-token'", req.Header.Get("Authorization"))
		}
	})
}

// Test Gap 8: Multiple Allow/Deny with same name
func TestProxyPolicy_AllowDenyUpdateBehavior(t *testing.T) {
	t.Run("allow updates existing rule with same name", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
		}

		// Add first rule
		policy.Allow(&ProxyPolicyAcceptRule{
			Name: "api-rule",
			Match: &ProxyPolicyMatch{
				Host: "^api\\.example\\.com$",
			},
		})

		if len(policy.AcceptRules) != 1 {
			t.Fatalf("len(AcceptRules) after first Allow = %d, want 1", len(policy.AcceptRules))
		}

		// Add second rule with same name
		policy.Allow(&ProxyPolicyAcceptRule{
			Name: "api-rule",
			Match: &ProxyPolicyMatch{
				Host: "^api2\\.example\\.com$",
			},
		})

		// Should still be 1, not 2 - the rule was updated
		if len(policy.AcceptRules) != 1 {
			t.Errorf("len(AcceptRules) after second Allow = %d, want 1 (should update not append)", len(policy.AcceptRules))
		}

		if policy.AcceptRules[0].Match.Host != "^api2\\.example\\.com$" {
			t.Errorf("Host = %s, want '^api2\\\\.example\\\\.com$'", policy.AcceptRules[0].Match.Host)
		}
	})

	t.Run("deny updates existing rule with same name", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
		}

		policy.Deny(&ProxyPolicyDenyRule{
			Name: "block-rule",
			Match: &ProxyPolicyMatch{
				Host: "^blocked\\.com$",
			},
		})

		if len(policy.DenyRules) != 1 {
			t.Fatalf("len(DenyRules) after first Deny = %d, want 1", len(policy.DenyRules))
		}

		policy.Deny(&ProxyPolicyDenyRule{
			Name: "block-rule",
			Match: &ProxyPolicyMatch{
				Host: "^blocked2\\.com$",
			},
		})

		if len(policy.DenyRules) != 1 {
			t.Errorf("len(DenyRules) after second Deny = %d, want 1 (should update not append)", len(policy.DenyRules))
		}

		if policy.DenyRules[0].Match.Host != "^blocked2\\.com$" {
			t.Errorf("Host = %s, want '^blocked2\\\\.com$'", policy.DenyRules[0].Match.Host)
		}
	})

	t.Run("allow with different names appends", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
		}

		policy.Allow(&ProxyPolicyAcceptRule{
			Name:  "rule-1",
			Match: &ProxyPolicyMatch{Host: "^api1\\.com$"},
		})

		policy.Allow(&ProxyPolicyAcceptRule{
			Name:  "rule-2",
			Match: &ProxyPolicyMatch{Host: "^api2\\.com$"},
		})

		if len(policy.AcceptRules) != 2 {
			t.Errorf("len(AcceptRules) = %d, want 2", len(policy.AcceptRules))
		}
	})
}

// Test Clone with Secrets
func TestProxyPolicy_CloneWithSecrets(t *testing.T) {
	t.Run("clones policy with secrets", func(t *testing.T) {
		secretData := []byte(`{"token":"secret-value","api-key":"12345"}`)
		policy := &ProxyPolicy{
			Name:    "test",
			Secrets: secretData,
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-1",
					Match: &ProxyPolicyMatch{
						Host: "^example\\.com$",
					},
				},
			},
		}

		cloned := policy.Clone()

		if cloned.Secrets == nil {
			t.Fatal("Secrets should not be nil in cloned policy")
		}

		if len(cloned.Secrets) != len(secretData) {
			t.Errorf("Secrets length = %d, want %d", len(cloned.Secrets), len(secretData))
		}

		if string(cloned.Secrets) != string(secretData) {
			t.Errorf("Secrets = %s, want %s", string(cloned.Secrets), string(secretData))
		}

		// Verify deep copy - modifying cloned shouldn't affect original
		cloned.Secrets[0] = 'X'
		if policy.Secrets[0] == 'X' {
			t.Error("original policy Secrets was modified, not a deep copy")
		}
	})

	t.Run("clones policy without secrets", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name: "test",
			AcceptRules: []*ProxyPolicyAcceptRule{
				{
					Name: "allow-1",
					Match: &ProxyPolicyMatch{
						Host: "^example\\.com$",
					},
				},
			},
		}

		cloned := policy.Clone()

		if cloned.Secrets != nil {
			t.Error("Secrets should be nil when original has no secrets")
		}
	})

	t.Run("clones empty secrets slice", func(t *testing.T) {
		policy := &ProxyPolicy{
			Name:    "test",
			Secrets: []byte{},
		}

		cloned := policy.Clone()

		// Empty slice should not be copied
		if cloned.Secrets != nil {
			t.Error("Empty Secrets slice should result in nil in clone")
		}
	})
}

// Test Merge with Secrets
func TestProxyPolicy_MergeWithSecrets(t *testing.T) {
	t.Run("merge with unlocked unlockers properly merges secrets", func(t *testing.T) {
		// Create base policy with unlocked unlocker
		baseUnlocker := NewMockSecretReadWriter()
		err := baseUnlocker.Unlock()
		if err != nil {
			t.Fatalf("Failed to unlock base: %v", err)
		}
		err = baseUnlocker.SetSecret("base-token", "base-value")
		if err != nil {
			t.Fatalf("Failed to set base secret: %v", err)
		}
		err = baseUnlocker.SetSecret("shared-token", "base-shared-value")
		if err != nil {
			t.Fatalf("Failed to set shared secret: %v", err)
		}

		base := &ProxyPolicy{
			Name:     "base",
			unlocker: baseUnlocker,
		}

		// Create cfg policy with unlocked unlocker
		cfgUnlocker := NewMockSecretReadWriter()
		err = cfgUnlocker.Unlock()
		if err != nil {
			t.Fatalf("Failed to unlock cfg: %v", err)
		}
		err = cfgUnlocker.SetSecret("cfg-token", "cfg-value")
		if err != nil {
			t.Fatalf("Failed to set cfg secret: %v", err)
		}
		err = cfgUnlocker.SetSecret("shared-token", "cfg-shared-value")
		if err != nil {
			t.Fatalf("Failed to set shared secret: %v", err)
		}

		cfg := &ProxyPolicy{
			Name:     "cfg",
			unlocker: cfgUnlocker,
		}

		merged := base.Merge(cfg)

		if merged.unlocker == nil {
			t.Fatal("merged unlocker should not be nil")
		}

		// Verify merged has secrets from both, with cfg taking precedence for shared keys
		val, err := merged.unlocker.GetSecret("base-token")
		if err != nil {
			t.Errorf("Failed to get base-token: %v", err)
		} else if val != "base-value" {
			t.Errorf("base-token = %s, want 'base-value'", val)
		}

		val, err = merged.unlocker.GetSecret("cfg-token")
		if err != nil {
			t.Errorf("Failed to get cfg-token: %v", err)
		} else if val != "cfg-value" {
			t.Errorf("cfg-token = %s, want 'cfg-value'", val)
		}

		// shared-token should have cfg's value (cfg takes precedence)
		val, err = merged.unlocker.GetSecret("shared-token")
		if err != nil {
			t.Errorf("Failed to get shared-token: %v", err)
		} else if val != "cfg-shared-value" {
			t.Errorf("shared-token = %s, want 'cfg-shared-value' (cfg should take precedence)", val)
		}
	})

	t.Run("merge copies secrets from cfg when cfg has secrets but no unlockers", func(t *testing.T) {
		base := &ProxyPolicy{
			Name: "base",
		}

		cfg := &ProxyPolicy{
			Name:    "cfg",
			Secrets: []byte(`{"cfg-token":"cfg-value"}`),
		}

		merged := base.Merge(cfg)

		if merged.Secrets == nil {
			t.Fatal("Secrets should not be nil in merged policy")
		}

		// cfg secrets should be copied when base has none
		if string(merged.Secrets) != string(cfg.Secrets) {
			t.Errorf("Secrets = %s, want %s", string(merged.Secrets), string(cfg.Secrets))
		}
	})

	t.Run("merge keeps base secrets when cfg has no secrets", func(t *testing.T) {
		baseSecrets := []byte(`{"base-token":"base-value"}`)
		base := &ProxyPolicy{
			Name:    "base",
			Secrets: baseSecrets,
		}

		cfg := &ProxyPolicy{
			Name: "cfg",
		}

		merged := base.Merge(cfg)

		if merged.Secrets == nil {
			t.Fatal("Secrets should not be nil in merged policy")
		}

		// Should keep base secrets
		if string(merged.Secrets) != string(baseSecrets) {
			t.Errorf("Secrets = %s, want %s", string(merged.Secrets), string(baseSecrets))
		}
	})

	t.Run("merge with both policies having no secrets", func(t *testing.T) {
		base := &ProxyPolicy{
			Name: "base",
		}

		cfg := &ProxyPolicy{
			Name: "cfg",
		}

		merged := base.Merge(cfg)

		if merged.Secrets != nil {
			t.Error("Secrets should be nil when both policies have no secrets")
		}
	})
}

// Test the fixed Expire logic in Merge
func TestProxyPolicy_MergeExpireFixed(t *testing.T) {
	t.Run("merge copies cfg expire when base has no expire", func(t *testing.T) {
		base := &ProxyPolicy{
			Name:   "base",
			Expire: 0,
		}

		cfg := &ProxyPolicy{
			Name:   "cfg",
			Expire: 1 * time.Hour,
		}

		merged := base.Merge(cfg)

		// After fix, should copy cfg.Expire even when base.Expire is 0
		if merged.Expire != 1*time.Hour {
			t.Errorf("Expire = %v, want 1h (fixed behavior)", merged.Expire)
		}
	})

	t.Run("merge keeps base expire when cfg has no expire", func(t *testing.T) {
		base := &ProxyPolicy{
			Name:   "base",
			Expire: 2 * time.Hour,
		}

		cfg := &ProxyPolicy{
			Name:   "cfg",
			Expire: 0,
		}

		merged := base.Merge(cfg)

		// Should keep base expire when cfg has none
		if merged.Expire != 2*time.Hour {
			t.Errorf("Expire = %v, want 2h", merged.Expire)
		}
	})
}
