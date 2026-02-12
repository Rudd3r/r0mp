package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	// GitHubVCS provides access to GitHub for version control operations
	// Git operations (*.git paths): GET/POST allowed for smart HTTP protocol
	// API operations: GET only for read-only access
	GitHubVCS = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "github-git",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^github.com$",
						Method: "^(GET|POST)$",
						Path:   "^/[^/]+/[^/]+\\.git(/.*)?$",
					},
				},
				{
					Name: "github-api",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^api.github.com$",
						Method: "^GET$",
						Path:   "^/(repos/.*|user.*|orgs/.*|search/.*|gists/.*)$",
					},
				},
				{
					Name: "github-raw",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^raw.githubusercontent.com$",
						Method: "^GET$",
						Path:   "^/.*$",
					},
				},
				{
					Name: "github-codeload",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^codeload.github.com$",
						Method: "^GET$",
						Path:   "^/[^/]+/[^/]+/(zip|tar\\.gz)/.*$",
					},
				},
			},
		}
	}

	// GitLabVCS provides access to GitLab for version control operations
	// Git operations: GET/POST allowed for smart HTTP protocol
	// API operations: GET only for read-only access
	GitLabVCS = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "gitlab-git",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^gitlab.com$",
						Method: "^(GET|POST)$",
						Path:   "^/[^/]+/[^/]+\\.git(/.*)?$",
					},
				},
				{
					Name: "gitlab-api",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^gitlab.com$",
						Method: "^GET$",
						Path:   "^/api/v4/(projects|users|groups|search)/.*$",
					},
				},
			},
		}
	}

	// BitbucketVCS provides access to Bitbucket for version control operations
	// Git operations: GET/POST allowed for smart HTTP protocol
	// API operations: GET only for read-only access
	BitbucketVCS = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "bitbucket-git",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^bitbucket.org$",
						Method: "^(GET|POST)$",
						Path:   "^/[^/]+/[^/]+\\.git(/.*)?$",
					},
				},
				{
					Name: "bitbucket-api",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^api.bitbucket.org$",
						Method: "^GET$",
						Path:   "^/2.0/(repositories|users|teams|workspaces|snippets)/.*$",
					},
				},
			},
		}
	}

	// VersionControlSystems aggregates all VCS policies
	VersionControlSystems = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(GitHubVCS()).
			Merge(GitLabVCS()).
			Merge(BitbucketVCS())
	}
)
