package defaults

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionControlSystems(t *testing.T) {
	policy := VersionControlSystems()
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
		// GitHub
		{"github git clone", "github.com", "/torvalds/linux.git", "github-git"},
		{"github git info", "github.com", "/torvalds/linux.git/info/refs", "github-git"},
		{"github api repos", "api.github.com", "/repos/torvalds/linux", "github-api"},
		{"github api user", "api.github.com", "/user", "github-api"},
		{"github api search", "api.github.com", "/search/repositories?q=test", "github-api"},
		{"github raw", "raw.githubusercontent.com", "/torvalds/linux/master/README", "github-raw"},
		{"github codeload", "codeload.github.com", "/torvalds/linux/zip/master", "github-codeload"},

		// GitLab
		{"gitlab git clone", "gitlab.com", "/gitlab-org/gitlab.git", "gitlab-git"},
		{"gitlab git info", "gitlab.com", "/gitlab-org/gitlab.git/info/refs", "gitlab-git"},
		{"gitlab api projects", "gitlab.com", "/api/v4/projects/1", "gitlab-api"},
		{"gitlab api users", "gitlab.com", "/api/v4/users/1", "gitlab-api"},

		// Bitbucket
		{"bitbucket git clone", "bitbucket.org", "/atlassian/jira.git", "bitbucket-git"},
		{"bitbucket git info", "bitbucket.org", "/atlassian/jira.git/info/refs", "bitbucket-git"},
		{"bitbucket api repos", "api.bitbucket.org", "/2.0/repositories/atlassian/jira", "bitbucket-api"},
		{"bitbucket api users", "api.bitbucket.org", "/2.0/users/username", "bitbucket-api"},
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

func TestVersionControlSystemsRejectsInvalidPaths(t *testing.T) {
	policy := VersionControlSystems()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"github settings", "github.com", "/settings/profile"},
		{"github billing", "github.com", "/settings/billing"},
		{"github api admin", "api.github.com", "/admin/users"},
		{"gitlab admin", "gitlab.com", "/admin"},
		{"bitbucket admin", "api.bitbucket.org", "/admin/users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				Host:   tt.host,
				URL:    &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, _ := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s should not be allowed (invalid path)", tt.host, tt.path)
		})
	}
}

func TestVersionControlSystemsRejectsUnknownHosts(t *testing.T) {
	policy := VersionControlSystems()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"random domain", "example.com", "/repo.git"},
		{"malicious github", "github.com.evil.com", "/torvalds/linux.git"},
		{"wrong gitlab", "fake.gitlab.com", "/project.git"},
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

func TestIndividualVersionControlSystems(t *testing.T) {
	tests := []struct {
		name         string
		policyFunc   func() *domain.ProxyPolicy
		expectedHost string
		expectedPath string
		policyName   string
	}{
		{"GitHub", GitHubVCS, "github.com", "/torvalds/linux.git", "github-git"},
		{"GitLab", GitLabVCS, "gitlab.com", "/gitlab-org/gitlab.git", "gitlab-git"},
		{"Bitbucket", BitbucketVCS, "bitbucket.org", "/atlassian/jira.git", "bitbucket-git"},
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
