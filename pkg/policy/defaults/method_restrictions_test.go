package defaults

import (
"net/http"
"net/url"
"testing"

"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
)

// Test that package registries block write operations
func TestPackageRegistriesRejectsWriteMethods(t *testing.T) {
policy := PackageRegistries()
require.NotNil(t, policy)

err := policy.Compile()
require.NoError(t, err)

tests := []struct {
name   string
method string
host   string
path   string
}{
{"npm POST", "POST", "registry.npmjs.org", "/express"},
{"npm PUT", "PUT", "registry.npmjs.org", "/express"},
{"npm DELETE", "DELETE", "registry.npmjs.org", "/express"},
{"pypi POST", "POST", "pypi.org", "/simple/flask/"},
{"rubygems POST", "POST", "rubygems.org", "/gems/rails.gem"},
{"crates POST", "POST", "crates.io", "/api/v1/crates/tokio"},
{"maven PUT", "PUT", "repo1.maven.org", "/maven2/test.jar"},
{"go POST", "POST", "proxy.golang.org", "/github.com/test/test@v1.0.0.zip"},
{"nuget PUT", "PUT", "api.nuget.org", "/v3/package/Test/1.0.0.nupkg"},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
req := &http.Request{
Method: tt.method,
Host:   tt.host,
URL:    &url.URL{Host: tt.host, Path: tt.path},
}

allowed, _ := policy.Find(req)
assert.Nil(t, allowed, "Host %s path %s with method %s should not be allowed (write operation)", tt.host, tt.path, tt.method)
})
}
}

// Test that package registries allow HEAD requests
func TestPackageRegistriesAllowsHEAD(t *testing.T) {
policy := PackageRegistries()
require.NotNil(t, policy)

err := policy.Compile()
require.NoError(t, err)

tests := []struct {
name     string
host     string
path     string
expected string
}{
{"npm HEAD", "registry.npmjs.org", "/express", "npm"},
{"pypi HEAD", "pypi.org", "/simple/flask/", "pypi"},
{"rubygems HEAD", "rubygems.org", "/gems/rails.gem", "rubygems"},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
req := &http.Request{
Method: "HEAD",
Host:   tt.host,
URL:    &url.URL{Host: tt.host, Path: tt.path},
}

allowed, denied := policy.Find(req)
assert.Nil(t, denied)
require.NotNil(t, allowed, "Host %s path %s with HEAD should be allowed", tt.host, tt.path)
assert.Equal(t, tt.expected, allowed.Name)
})
}
}

// Test that Linux repositories block write operations
func TestLinuxRepositoriesRejectsWriteMethods(t *testing.T) {
policy := LinuxRepositories()
require.NotNil(t, policy)

err := policy.Compile()
require.NoError(t, err)

tests := []struct {
name   string
method string
host   string
}{
{"alpine POST", "POST", "dl-cdn.alpinelinux.org"},
{"debian PUT", "PUT", "deb.debian.org"},
{"ubuntu DELETE", "DELETE", "archive.ubuntu.com"},
{"fedora POST", "POST", "download.fedoraproject.org"},
{"centos PUT", "PUT", "mirror.centos.org"},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
req := &http.Request{
Method: tt.method,
Host:   tt.host,
URL:    &url.URL{Host: tt.host, Path: "/"},
}

allowed, _ := policy.Find(req)
assert.Nil(t, allowed, "Host %s with method %s should not be allowed (write operation)", tt.host, tt.method)
})
}
}

// Test that VCS APIs block write operations
func TestVCSAPIRejectsWriteMethods(t *testing.T) {
policy := VersionControlSystems()
require.NotNil(t, policy)

err := policy.Compile()
require.NoError(t, err)

tests := []struct {
name   string
method string
host   string
path   string
}{
{"github API POST", "POST", "api.github.com", "/repos/owner/repo/issues"},
{"github API PUT", "PUT", "api.github.com", "/repos/owner/repo/contents/file.txt"},
{"github API DELETE", "DELETE", "api.github.com", "/repos/owner/repo"},
{"gitlab API POST", "POST", "gitlab.com", "/api/v4/projects/1/issues"},
{"gitlab API PUT", "PUT", "gitlab.com", "/api/v4/projects/1"},
{"gitlab API DELETE", "DELETE", "gitlab.com", "/api/v4/projects/1"},
{"bitbucket API POST", "POST", "api.bitbucket.org", "/2.0/repositories/owner/repo/issues"},
{"bitbucket API PUT", "PUT", "api.bitbucket.org", "/2.0/repositories/owner/repo"},
{"bitbucket API DELETE", "DELETE", "api.bitbucket.org", "/2.0/repositories/owner/repo"},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
req := &http.Request{
Method: tt.method,
Host:   tt.host,
URL:    &url.URL{Host: tt.host, Path: tt.path},
}

allowed, _ := policy.Find(req)
assert.Nil(t, allowed, "API %s with method %s should not be allowed (write operation)", tt.host, tt.method)
})
}
}

// Test that VCS git operations allow POST (for smart HTTP)
func TestVCSGitOperationsAllowsPOST(t *testing.T) {
policy := VersionControlSystems()
require.NotNil(t, policy)

err := policy.Compile()
require.NoError(t, err)

tests := []struct {
name     string
host     string
path     string
expected string
}{
{"github git POST", "github.com", "/torvalds/linux.git/git-upload-pack", "github-git"},
{"gitlab git POST", "gitlab.com", "/gitlab-org/gitlab.git/git-upload-pack", "gitlab-git"},
{"bitbucket git POST", "bitbucket.org", "/atlassian/jira.git/git-upload-pack", "bitbucket-git"},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
req := &http.Request{
Method: "POST",
Host:   tt.host,
URL:    &url.URL{Host: tt.host, Path: tt.path},
}

allowed, denied := policy.Find(req)
assert.Nil(t, denied)
require.NotNil(t, allowed, "Git operation %s with POST should be allowed", tt.path)
assert.Equal(t, tt.expected, allowed.Name)
})
}
}

// Test that VCS raw/codeload endpoints block write operations
func TestVCSRawEndpointsRejectsWriteMethods(t *testing.T) {
policy := GitHubVCS()
require.NotNil(t, policy)

err := policy.Compile()
require.NoError(t, err)

tests := []struct {
name   string
method string
host   string
path   string
}{
{"github raw POST", "POST", "raw.githubusercontent.com", "/owner/repo/main/README.md"},
{"github codeload POST", "POST", "codeload.github.com", "/owner/repo/zip/main"},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
req := &http.Request{
Method: tt.method,
Host:   tt.host,
URL:    &url.URL{Host: tt.host, Path: tt.path},
}

allowed, _ := policy.Find(req)
assert.Nil(t, allowed, "Raw endpoint %s with method %s should not be allowed", tt.host, tt.method)
})
}
}
