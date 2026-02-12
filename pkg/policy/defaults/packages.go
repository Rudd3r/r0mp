package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	// NPMRegistry provides access to Node.js package manager (read-only: GET/HEAD)
	NPMRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "npm",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^registry.npmjs.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(.*\\.tgz|[^/]+|@[^/]+/[^/]+|@[^/]+/[^/]+/-.*)$",
					},
				},
			},
		}
	}

	// PyPIRegistry provides access to Python package index (read-only: GET/HEAD)
	PyPIRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "pypi",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^pypi.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(simple|pypi)/.*$",
					},
				},
				{
					Name: "pypi-files",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^files.pythonhosted.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/packages/.*$",
					},
				},
			},
		}
	}

	// RubyGemsRegistry provides access to Ruby gems (read-only: GET/HEAD)
	RubyGemsRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "rubygems",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^rubygems.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(gems|api/v1/(gems|versions|dependencies)).*$",
					},
				},
			},
		}
	}

	// CratesIORegistry provides access to Rust packages (read-only: GET/HEAD)
	CratesIORegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "crates-io",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^crates.io$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(api/v1/crates.*|crates/.*)$",
					},
				},
				{
					Name: "crates-io-static",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^static.crates.io$",
						Method: "^(GET|HEAD)$",
						Path:   "^/crates/.*$",
					},
				},
				{
					Name: "crates-io-index",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^index.crates.io$",
						Method: "^(GET|HEAD)$",
						Path:   "^/.*$",
					},
				},
			},
		}
	}

	// MavenCentralRegistry provides access to Java/Maven packages (read-only: GET/HEAD)
	MavenCentralRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "maven-central",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^repo1.maven.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/maven2/.*$",
					},
				},
				{
					Name: "maven-apache",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^repo.maven.apache.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/maven2/.*$",
					},
				},
			},
		}
	}

	// GoModulesRegistry provides access to Go modules (read-only: GET/HEAD)
	GoModulesRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "go-proxy",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^proxy.golang.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/.*$",
					},
				},
				{
					Name: "go-sum",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^sum.golang.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/(lookup/.*|latest|tile/.*)$",
					},
				},
			},
		}
	}

	// NuGetRegistry provides access to .NET packages (read-only: GET/HEAD)
	NuGetRegistry = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "nuget",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^api.nuget.org$",
						Method: "^(GET|HEAD)$",
						Path:   "^/v3/(index.json|registration.*|package.*|query.*|autocomplete.*)$",
					},
				},
			},
		}
	}

	// PackageRegistries aggregates all package registry policies
	PackageRegistries = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(NPMRegistry()).
			Merge(PyPIRegistry()).
			Merge(RubyGemsRegistry()).
			Merge(CratesIORegistry()).
			Merge(MavenCentralRegistry()).
			Merge(GoModulesRegistry()).
			Merge(NuGetRegistry())
	}
)
