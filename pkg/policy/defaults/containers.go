package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	// DockerHubRegistry provides access to Docker Hub container registry (read-only: GET/HEAD)
	DockerHubRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "docker-hub-registry",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(registry-1.docker.io|registry.hub.docker.com)$",
						Method: "^(GET|HEAD)$",
						Path:   "^/v2/.*$",
					},
				},
				{
					Name: "docker-hub-auth",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^auth.docker.io$",
						Method: "^GET$",
						Path:   "^/token$",
					},
				},
				{
					Name: "docker-hub-cdn",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(production.cloudflare.docker.com|registry.docker.io)$",
						Method: "^(GET|HEAD)$",
						Path:   "^/.*$",
					},
				},
			},
		}
	}

	// GitHubContainerRegistry provides access to GitHub Container Registry (read-only: GET/HEAD)
	GitHubContainerRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "ghcr",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^ghcr.io$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(v2/.*|token)$",
					},
				},
			},
		}
	}

	// GoogleContainerRegistry provides access to Google Container Registry (read-only: GET/HEAD)
	GoogleContainerRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "gcr",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(gcr\\.io|[a-z]+-docker\\.pkg\\.dev|(us|eu|asia)\\.gcr\\.io)$",
						Method: "^(GET|HEAD)$",
						Path:   "^/v2/.*$",
					},
				},
			},
		}
	}

	// AWSContainerRegistry provides access to AWS Elastic Container Registry (read-only: GET/HEAD)
	AWSContainerRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "ecr",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^[0-9]+.dkr.ecr.[a-z0-9-]+.amazonaws.com$",
						Method: "^(GET|HEAD)$",
						Path:   "^/v2/.*$",
					},
				},
				{
					Name: "ecr-public",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^public.ecr.aws$",
						Method: "^(GET|HEAD)$",
						Path:   "^/v2/.*$",
					},
				},
			},
		}
	}

	// QuayRegistry provides access to Quay.io container registry (read-only: GET/HEAD)
	QuayRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "quay",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^quay.io$",
						Method: "^(GET|HEAD)$",
						Path:   "^/v2/.*$",
					},
				},
			},
		}
	}

	// AzureContainerRegistry provides access to Azure Container Registry (read-only: GET/HEAD)
	AzureContainerRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "acr",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^[a-z0-9]+.azurecr.io$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(v2|oauth2)/.*$",
					},
				},
			},
		}
	}

	// ContainerRegistries aggregates all container registry policies
	ContainerRegistries = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(DockerHubRegistry()).
			Merge(GitHubContainerRegistry()).
			Merge(GoogleContainerRegistry()).
			Merge(AWSContainerRegistry()).
			Merge(QuayRegistry()).
			Merge(AzureContainerRegistry())
	}
)
