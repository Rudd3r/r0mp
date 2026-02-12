package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyBuilder(t *testing.T) {
	t.Run("creates new policy builder", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")

		builder := NewPolicyBuilder(tmpDir, store)

		require.NotNil(t, builder)
		assert.Equal(t, tmpDir, builder.storePath)
		assert.NotNil(t, builder.unlocker)
	})
}

func TestPolicyBuilderNew(t *testing.T) {
	t.Run("creates new policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.New("test-policy")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, "test-policy", policy.Name)
		assert.NotNil(t, policy.AcceptRules)
		assert.NotNil(t, policy.DenyRules)
		assert.Empty(t, policy.AcceptRules)
		assert.Empty(t, policy.DenyRules)

		// Verify policy was saved to disk
		policyPath := filepath.Join(tmpDir, "test-policy.json")
		assert.FileExists(t, policyPath)
	})

	t.Run("returns error for empty name", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.New("")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "policy name cannot be empty")
	})

	t.Run("returns error for built-in policy name", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.New("linux_all")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "built in policy")
		assert.Contains(t, err.Error(), "cannot be created")
	})

	t.Run("creates policy directory if not exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		storePath := filepath.Join(tmpDir, "policies", "nested", "dir")
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(storePath, store)

		policy, err := builder.New("test-policy")

		require.NoError(t, err)
		require.NotNil(t, policy)

		// Verify directory was created
		info, err := os.Stat(storePath)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
}

func TestPolicyBuilderGet(t *testing.T) {
	t.Run("gets built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Get("linux_all")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.NotNil(t, policy.AcceptRules)
	})

	t.Run("gets custom policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create a policy
		_, err := builder.New("custom-policy")
		require.NoError(t, err)

		// Get the policy
		policy, err := builder.Get("custom-policy")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, "custom-policy", policy.Name)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Get("non-existent")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("returns clone of built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy1, err := builder.Get("linux_all")
		require.NoError(t, err)

		policy2, err := builder.Get("linux_all")
		require.NoError(t, err)

		// Modify policy1 and ensure policy2 is not affected
		policy1.Name = "modified"
		assert.NotEqual(t, policy1.Name, policy2.Name)
	})

	t.Run("returns error for corrupted policy file", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Write invalid JSON to a policy file
		policyPath := filepath.Join(tmpDir, "corrupted.json")
		err := os.WriteFile(policyPath, []byte("invalid json {{{"), 0644)
		require.NoError(t, err)

		policy, err := builder.Get("corrupted")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "unmarshalling")
	})
}

func TestPolicyBuilderList(t *testing.T) {
	t.Run("lists only built-in policies when no custom policies exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policies, err := builder.List()

		require.NoError(t, err)
		require.NotEmpty(t, policies)

		// Should have at least the "linux_all" built-in policy
		found := false
		for _, p := range policies {
			if p.Name == "linux_all" {
				found = true
				break
			}
		}
		assert.True(t, found, "linux policy should be in list")
	})

	t.Run("lists built-in and custom policies", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create custom policies
		_, err := builder.New("custom1")
		require.NoError(t, err)
		_, err = builder.New("custom2")
		require.NoError(t, err)

		policies, err := builder.List()

		require.NoError(t, err)
		require.NotEmpty(t, policies)
		assert.GreaterOrEqual(t, len(policies), 3) // linux + custom1 + custom2

		names := make(map[string]bool)
		for _, p := range policies {
			names[p.Name] = true
		}
		assert.True(t, names["linux_all"])
		assert.True(t, names["custom1"])
		assert.True(t, names["custom2"])
	})

	t.Run("works when store directory does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		storePath := filepath.Join(tmpDir, "non-existent")
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(storePath, store)

		policies, err := builder.List()

		require.NoError(t, err)
		require.NotEmpty(t, policies)
		// Should still return built-in policies
	})

	t.Run("ignores non-json files in policy directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create a non-JSON file
		err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("test"), 0644)
		require.NoError(t, err)

		// Create a subdirectory
		err = os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755)
		require.NoError(t, err)

		policies, err := builder.List()

		require.NoError(t, err)
		// Should only have built-in policies
		for _, p := range policies {
			assert.NotEqual(t, "readme", p.Name)
		}
	})

	t.Run("skips corrupted policy files", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create a valid policy
		_, err := builder.New("valid-policy")
		require.NoError(t, err)

		// Create a corrupted policy file
		err = os.WriteFile(filepath.Join(tmpDir, "corrupted.json"), []byte("invalid"), 0644)
		require.NoError(t, err)

		policies, err := builder.List()

		require.NoError(t, err)
		require.NotEmpty(t, policies)

		// Should have valid-policy but not corrupted
		names := make(map[string]bool)
		for _, p := range policies {
			names[p.Name] = true
		}
		assert.True(t, names["valid-policy"])
		assert.False(t, names["corrupted"])
	})
}

func TestPolicyBuilderRemove(t *testing.T) {
	t.Run("removes custom policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create a policy
		_, err := builder.New("to-remove")
		require.NoError(t, err)

		// Remove it
		err = builder.Remove("to-remove")

		require.NoError(t, err)

		// Verify it's gone
		policyPath := filepath.Join(tmpDir, "to-remove.json")
		_, err = os.Stat(policyPath)
		assert.True(t, os.IsNotExist(err))

		// Verify Get returns error
		_, err = builder.Get("to-remove")
		assert.Error(t, err)
	})

	t.Run("returns error when removing built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		err := builder.Remove("linux_all")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "built in policy")
		assert.Contains(t, err.Error(), "cannot be changed")
	})

	t.Run("returns error when removing non-existent policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		err := builder.Remove("non-existent")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestPolicyBuilderAllow(t *testing.T) {
	t.Run("adds allow rule to policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("test-policy")
		require.NoError(t, err)

		policy, err := builder.Allow("test-policy", "example.com",
			[]string{"example.com"},
			[]string{"GET", "POST"},
			[]string{"/api/*"},
			[]string{"https"})

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Len(t, policy.AcceptRules, 1)
		assert.Equal(t, "example.com", policy.AcceptRules[0].Name)
		assert.Equal(t, "^example\\.com$", policy.AcceptRules[0].Match.Host)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Allow("non-existent", "example.com", []string{"example.com"}, nil, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, policy)
	})

	t.Run("cannot modify built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Allow("linux_all", "example.com", []string{"example.com"}, nil, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "built in policy")
	})

	t.Run("handles empty methods, paths, and schemes", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("test-policy")
		require.NoError(t, err)

		policy, err := builder.Allow("test-policy", "example.com", []string{"example.com"}, nil, nil, nil)

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Len(t, policy.AcceptRules, 1)
	})
}

func TestPolicyBuilderDeny(t *testing.T) {
	t.Run("adds deny rule to policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("test-policy")
		require.NoError(t, err)

		policy, err := builder.Deny("test-policy", "blocked.com", []string{"blocked.com"},
			[]string{"GET"},
			[]string{"/admin/*"},
			[]string{"http"})

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Len(t, policy.DenyRules, 1)
		assert.Equal(t, "blocked.com", policy.DenyRules[0].Name)
		assert.Equal(t, "^blocked\\.com$", policy.DenyRules[0].Match.Host)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Deny("non-existent", "blocked.com", []string{"blocked.com"}, nil, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, policy)
	})

	t.Run("cannot modify built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Deny("linux_all", "blocked.com", []string{"blocked.com"}, nil, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "built in policy")
	})
}

func TestPolicyBuilderMerge(t *testing.T) {
	t.Run("merges two custom policies", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create source policy with allow rule
		_, err := builder.New("source")
		require.NoError(t, err)
		_, err = builder.Allow("source", "source.com", []string{"source.com"}, []string{"GET"}, nil, nil)
		require.NoError(t, err)

		// Create target policy with different allow rule
		_, err = builder.New("target")
		require.NoError(t, err)
		_, err = builder.Allow("target", "target.com", []string{"target.com"}, []string{"POST"}, nil, nil)
		require.NoError(t, err)

		// Merge source into target
		policy, err := builder.Merge("source", "target")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Len(t, policy.AcceptRules, 2)
	})

	t.Run("can merge built-in into custom policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("custom")
		require.NoError(t, err)

		policy, err := builder.Merge("linux_all", "custom")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.NotEmpty(t, policy.AcceptRules)
	})

	t.Run("cannot merge into built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("custom")
		require.NoError(t, err)

		policy, err := builder.Merge("custom", "linux_all")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "built in policy")
	})

	t.Run("returns error when source policy does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("target")
		require.NoError(t, err)

		policy, err := builder.Merge("non-existent", "target")

		assert.Error(t, err)
		assert.Nil(t, policy)
	})

	t.Run("returns error when target policy does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("source")
		require.NoError(t, err)

		policy, err := builder.Merge("source", "non-existent")

		assert.Error(t, err)
		assert.Nil(t, policy)
	})
}

func TestPolicyBuilderAuth(t *testing.T) {
	t.Run("adds bearer token auth to policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		err := store.Unlock()
		require.NoError(t, err)

		builder := NewPolicyBuilder(tmpDir, store)

		_, err = builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "api.example.com", []string{"api.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		policy, err := builder.Auth("test-policy", "bearer", "api.example.com", "", "my-secret-token")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Len(t, policy.AcceptRules, 1)
		assert.Len(t, policy.AcceptRules[0].ActionModify, 1)
		assert.Equal(t, "set_bearer_token", policy.AcceptRules[0].ActionModify[0].Name)
		assert.NotEmpty(t, policy.Secrets)
	})

	t.Run("adds basic auth to policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		err := store.Unlock()
		require.NoError(t, err)

		builder := NewPolicyBuilder(tmpDir, store)

		_, err = builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "api.example.com", []string{"api.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		policy, err := builder.Auth("test-policy", "basic", "api.example.com", "username", "password")

		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Len(t, policy.AcceptRules, 1)
		assert.Len(t, policy.AcceptRules[0].ActionModify, 1)
		assert.Equal(t, "set_basic_auth", policy.AcceptRules[0].ActionModify[0].Name)
		assert.NotEmpty(t, policy.Secrets)
	})

	t.Run("returns error for unsupported auth type", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		err := store.Unlock()
		require.NoError(t, err)

		builder := NewPolicyBuilder(tmpDir, store)

		_, err = builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "api.example.com", []string{"api.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		policy, err := builder.Auth("test-policy", "oauth", "api.example.com", "", "token")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "unsupported auth method")
	})

	t.Run("returns error when domain not in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		err := store.Unlock()
		require.NoError(t, err)

		builder := NewPolicyBuilder(tmpDir, store)

		_, err = builder.New("test-policy")
		require.NoError(t, err)

		policy, err := builder.Auth("test-policy", "bearer", "api.example.com", "", "token")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "domain name not in proxy policy")
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		policy, err := builder.Auth("non-existent", "bearer", "api.example.com", "", "token")

		assert.Error(t, err)
		assert.Nil(t, policy)
	})

	t.Run("cannot modify built-in policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		err := store.Unlock()
		require.NoError(t, err)

		builder := NewPolicyBuilder(tmpDir, store)

		// Get linux_all to see what rules actually exist
		linuxPolicy, err := builder.Get("linux_all")
		require.NoError(t, err)
		require.NotEmpty(t, linuxPolicy.AcceptRules, "linux_all should have rules")

		// Try to add auth to an actual rule in linux_all
		actualRuleName := linuxPolicy.AcceptRules[0].Name

		policy, err := builder.Auth("linux_all", "bearer", actualRuleName, "", "token")

		assert.Error(t, err)
		assert.Nil(t, policy)
		assert.Contains(t, err.Error(), "built in policy")
	})
}

func TestPatternToRegex(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		{
			name:     "simple domain",
			pattern:  "example.com",
			expected: "^example\\.com$",
		},
		{
			name:     "wildcard domain",
			pattern:  "*.example.com",
			expected: "^.*\\.example\\.com$",
		},
		{
			name:     "multiple wildcards",
			pattern:  "*.*.example.com",
			expected: "^.*\\..*\\.example\\.com$",
		},
		{
			name:     "path with wildcard",
			pattern:  "/api/*/users",
			expected: "^/api/.*/users$",
		},
		{
			name:     "empty string",
			pattern:  "",
			expected: "^$",
		},
		{
			name:     "multiple dots",
			pattern:  "sub.api.example.com",
			expected: "^sub\\.api\\.example\\.com$",
		},
		{
			name:     "wildcard at start",
			pattern:  "*.com",
			expected: "^.*\\.com$",
		},
		{
			name:     "wildcard at end",
			pattern:  "example.*",
			expected: "^example\\..*$",
		},
		{
			name:     "multiple wildcards in path",
			pattern:  "/api/*/v*/users",
			expected: "^/api/.*/v.*/users$",
		},
		{
			name:     "only wildcard",
			pattern:  "*",
			expected: "^.*$",
		},
		{
			name:     "path with trailing slash",
			pattern:  "/api/*",
			expected: "^/api/.*$",
		},
		{
			name:     "subdomain with numbers",
			pattern:  "api123.example.com",
			expected: "^api123\\.example\\.com$",
		},
		{
			name:     "path with multiple segments",
			pattern:  "/v1/api/users/*/profile",
			expected: "^/v1/api/users/.*/profile$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := patternToRegex(tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test that generated patterns actually match as expected
func TestPatternToRegex_Matching(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		matches []string
		rejects []string
	}{
		{
			name:    "wildcard subdomain",
			pattern: "*.example.com",
			matches: []string{
				"api.example.com",
				"www.example.com",
				"test.example.com",
			},
			rejects: []string{
				"example.com",
				"example.org",
				"notexample.com",
			},
		},
		{
			name:    "double wildcard subdomain",
			pattern: "*.*.example.com",
			matches: []string{
				"a.b.example.com",
				"api.v1.example.com",
			},
			rejects: []string{
				"api.example.com",
				"example.com",
			},
		},
		{
			name:    "path wildcard",
			pattern: "/api/*/users",
			matches: []string{
				"/api/v1/users",
				"/api/v2/users",
				"/api/123/users",
			},
			rejects: []string{
				"/api/users",
				"/api/v1/posts",
				"/v1/api/users",
			},
		},
		{
			name:    "simple exact match",
			pattern: "example.com",
			matches: []string{
				"example.com",
			},
			rejects: []string{
				"api.example.com",
				"example.org",
				"notexample.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexPattern := patternToRegex(tt.pattern)
			re, err := regexp.Compile(regexPattern)
			require.NoError(t, err, "generated pattern should be valid regex")

			for _, match := range tt.matches {
				assert.True(t, re.MatchString(match),
					"pattern %q should match %q", tt.pattern, match)
			}

			for _, reject := range tt.rejects {
				assert.False(t, re.MatchString(reject),
					"pattern %q should not match %q", tt.pattern, reject)
			}
		})
	}
}

func TestBuiltInPolicies(t *testing.T) {
	t.Run("all individual distro policies are accessible", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		distros := []string{
			"linux_all",
			"linux_alpine",
			"linux_debian",
			"linux_ubuntu",
			"linux_fedora",
			"linux_centos",
			"linux_rocky",
			"linux_almalinux",
			"linux_rhel",
			"linux_arch",
			"linux_opensuse",
			"linux_gentoo",
			"linux_kali",
			"linux_linuxmint",
			"linux_manjaro",
			"linux_amazonlinux",
		}

		for _, distro := range distros {
			policy, err := builder.Get(distro)
			require.NoError(t, err, "Should be able to get %s policy", distro)
			require.NotNil(t, policy, "%s policy should not be nil", distro)
			assert.NotEmpty(t, policy.AcceptRules, "%s policy should have allowed rules", distro)
		}
	})

	t.Run("all individual LLM provider policies are accessible", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		providers := []string{
			"llm_all",
			"llm_openai",
			"llm_anthropic",
			"llm_googleai",
			"llm_cohere",
			"llm_openrouter",
			"llm_together",
			"llm_anyscale",
			"llm_replicate",
			"llm_huggingface",
			"llm_mistral",
			"llm_perplexity",
			"llm_ai21",
			"llm_awsbedrock",
			"llm_azureopenai",
			"llm_groq",
			"llm_fireworks",
			"llm_deepseek",
			"llm_stability",
		}

		for _, provider := range providers {
			policy, err := builder.Get(provider)
			require.NoError(t, err, "Should be able to get %s policy", provider)
			require.NotNil(t, policy, "%s policy should not be nil", provider)
			assert.NotEmpty(t, policy.AcceptRules, "%s policy should have allowed rules", provider)
		}
	})

	t.Run("individual distro policies cannot be modified", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		distros := []string{"linux_alpine", "linux_debian", "linux_ubuntu", "linux_fedora"}

		for _, distro := range distros {
			_, err := builder.Allow(distro, "test.example.com", []string{"test.example.com"}, nil, nil, nil)
			assert.Error(t, err, "Should not be able to modify built-in %s policy", distro)
			assert.Contains(t, err.Error(), "built in policy", "Error should mention built-in policy")
		}
	})

	t.Run("individual distro policies can be merged into custom policies", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create a custom policy
		_, err := builder.New("my-custom")
		require.NoError(t, err)

		// Merge debian into custom
		policy, err := builder.Merge("linux_debian", "my-custom")
		require.NoError(t, err)
		assert.NotEmpty(t, policy.AcceptRules, "Custom policy should have debian rules")

		// Merge ubuntu into custom
		policy, err = builder.Merge("linux_ubuntu", "my-custom")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(policy.AcceptRules), 2, "Custom policy should have rules from both distros")
	})

	t.Run("linux policy contains all individual distros", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		linuxPolicy, err := builder.Get("linux_all")
		require.NoError(t, err)

		// The linux policy should have more rules than any individual distro
		alpinePolicy, err := builder.Get("linux_alpine")
		require.NoError(t, err)

		assert.Greater(t, len(linuxPolicy.AcceptRules), len(alpinePolicy.AcceptRules),
			"Linux policy should have more rules than alpine alone")

		// Verify linux_all contains a reasonable number of rules
		assert.Greater(t, len(linuxPolicy.AcceptRules), 10,
			"Linux policy should have at least 10 rules from various distros")
	})
}

func TestPolicyBuilderIntegration(t *testing.T) {
	t.Run("complete workflow: create, modify, list, remove", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		err := store.Unlock()
		require.NoError(t, err)

		builder := NewPolicyBuilder(tmpDir, store)

		// Create a new policy
		policy, err := builder.New("my-api")
		require.NoError(t, err)
		assert.Equal(t, "my-api", policy.Name)

		// Add allow rules
		policy, err = builder.Allow("my-api", "api.example.com", []string{"api.example.com"},
			[]string{"GET", "POST"},
			[]string{"/api/*"},
			[]string{"https"})
		require.NoError(t, err)
		assert.Len(t, policy.AcceptRules, 1)

		// Add deny rules
		policy, err = builder.Deny("my-api", "api.example.com", []string{"api.example.com"},
			[]string{"DELETE"},
			[]string{"/api/admin/*"},
			nil)
		require.NoError(t, err)
		assert.Len(t, policy.DenyRules, 1)

		// Add auth
		policy, err = builder.Auth("my-api", "bearer", "api.example.com", "", "secret-token")
		require.NoError(t, err)
		assert.NotEmpty(t, policy.Secrets)

		// List policies
		policies, err := builder.List()
		require.NoError(t, err)
		found := false
		for _, p := range policies {
			if p.Name == "my-api" {
				found = true
				break
			}
		}
		assert.True(t, found)

		// Get policy
		retrieved, err := builder.Get("my-api")
		require.NoError(t, err)
		assert.Equal(t, "my-api", retrieved.Name)
		assert.Len(t, retrieved.AcceptRules, 1)
		assert.Len(t, retrieved.DenyRules, 1)

		// Remove policy
		err = builder.Remove("my-api")
		require.NoError(t, err)

		// Verify it's gone
		_, err = builder.Get("my-api")
		assert.Error(t, err)
	})

	t.Run("merge multiple policies", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create policy 1
		_, err := builder.New("policy1")
		require.NoError(t, err)
		_, err = builder.Allow("policy1", "api1.example.com", []string{"api1.example.com"}, []string{"GET"}, nil, nil)
		require.NoError(t, err)

		// Create policy 2
		_, err = builder.New("policy2")
		require.NoError(t, err)
		_, err = builder.Allow("policy2", "api2.example.com", []string{"api2.example.com"}, []string{"POST"}, nil, nil)
		require.NoError(t, err)

		// Create target policy
		_, err = builder.New("combined")
		require.NoError(t, err)

		// Merge policy1 into combined
		_, err = builder.Merge("policy1", "combined")
		require.NoError(t, err)

		// Merge policy2 into combined
		policy, err := builder.Merge("policy2", "combined")
		require.NoError(t, err)

		// Verify combined has rules from both
		assert.Len(t, policy.AcceptRules, 2)
	})

	t.Run("policy persistence across builder instances", func(t *testing.T) {
		tmpDir := t.TempDir()
		store1 := secrets.NewSecretStore("test-pass")
		builder1 := NewPolicyBuilder(tmpDir, store1)

		// Create policy with first builder
		_, err := builder1.New("persistent")
		require.NoError(t, err)
		_, err = builder1.Allow("persistent", "api.example.com", []string{"api.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		// Create second builder with same path
		store2 := secrets.NewSecretStore("test-pass")
		builder2 := NewPolicyBuilder(tmpDir, store2)

		// Retrieve policy with second builder
		policy, err := builder2.Get("persistent")
		require.NoError(t, err)
		assert.Equal(t, "persistent", policy.Name)
		assert.Len(t, policy.AcceptRules, 1)
	})
}

func TestPolicyBuilderMoveRule(t *testing.T) {
	t.Run("moves allow rule forward", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create policy with three rules
		_, err := builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule1", []string{"api1.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule2", []string{"api2.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule3", []string{"api3.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		// Move rule1 to position 2
		policy, err := builder.MoveRule("test-policy", "rule1", 2)
		require.NoError(t, err)
		assert.Equal(t, "rule2", policy.AcceptRules[0].Name)
		assert.Equal(t, "rule3", policy.AcceptRules[1].Name)
		assert.Equal(t, "rule1", policy.AcceptRules[2].Name)
	})

	t.Run("moves allow rule backward", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create policy with three rules
		_, err := builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule1", []string{"api1.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule2", []string{"api2.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule3", []string{"api3.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		// Move rule3 to position 0
		policy, err := builder.MoveRule("test-policy", "rule3", 0)
		require.NoError(t, err)
		assert.Equal(t, "rule3", policy.AcceptRules[0].Name)
		assert.Equal(t, "rule1", policy.AcceptRules[1].Name)
		assert.Equal(t, "rule2", policy.AcceptRules[2].Name)
	})

	t.Run("moves deny rule", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		// Create policy with deny rules
		_, err := builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Deny("test-policy", "block1", []string{"bad1.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Deny("test-policy", "block2", []string{"bad2.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Deny("test-policy", "block3", []string{"bad3.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		// Move block1 to last position
		policy, err := builder.MoveRule("test-policy", "block1", 2)
		require.NoError(t, err)
		assert.Equal(t, "block2", policy.DenyRules[0].Name)
		assert.Equal(t, "block3", policy.DenyRules[1].Name)
		assert.Equal(t, "block1", policy.DenyRules[2].Name)
	})

	t.Run("no-op when already in position", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule1", []string{"api1.example.com"}, nil, nil, nil)
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule2", []string{"api2.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		// Move rule1 to its current position
		policy, err := builder.MoveRule("test-policy", "rule1", 0)
		require.NoError(t, err)
		assert.Equal(t, "rule1", policy.AcceptRules[0].Name)
		assert.Equal(t, "rule2", policy.AcceptRules[1].Name)
	})

	t.Run("returns error for invalid position", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("test-policy")
		require.NoError(t, err)
		_, err = builder.Allow("test-policy", "rule1", []string{"api1.example.com"}, nil, nil, nil)
		require.NoError(t, err)

		// Try to move to invalid position
		_, err = builder.MoveRule("test-policy", "rule1", 5)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "out of range")
	})

	t.Run("returns error for non-existent rule", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.New("test-policy")
		require.NoError(t, err)

		_, err = builder.MoveRule("test-policy", "nonexistent", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := secrets.NewSecretStore("test-pass")
		builder := NewPolicyBuilder(tmpDir, store)

		_, err := builder.MoveRule("nonexistent-policy", "rule", 0)
		assert.Error(t, err)
	})
}
