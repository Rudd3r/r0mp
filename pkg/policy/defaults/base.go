package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	AllowAll = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "allow-all",
					Match: &domain.ProxyPolicyMatch{
						Host: ".*",
					},
				},
			},
		}
	}
	DenyAll = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{}
	}
	Default = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(LinuxRepositories()).
			Merge(OpenAIProvider()).
			Merge(AnthropicProvider()).
			Merge(GoogleAIProvider()).
			Merge(OpenRouterProvider()).
			Merge(PackageRegistries())
	}
)
