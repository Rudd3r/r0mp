package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	// CDNJS provides access to cdnjs.cloudflare.com (GET only)
	CDNJS = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "cdnjs",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^cdnjs.cloudflare.com$",
						Method: "^GET$",
						Path:   "^/ajax/libs/.*\\.(js|css|woff|woff2|ttf|eot|svg|map)$",
					},
				},
			},
		}
	}

	// UnpkgCDN provides access to unpkg.com (GET only)
	UnpkgCDN = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "unpkg",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^unpkg.com$",
						Method: "^GET$",
						Path:   "^/.*$",
					},
				},
			},
		}
	}

	// JsDelivrCDN provides access to jsDelivr CDN (GET only)
	JsDelivrCDN = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "jsdelivr",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^cdn.jsdelivr.net$",
						Method: "^GET$",
						Path:   "^/(npm|gh|wp|combine)/.*$",
					},
				},
			},
		}
	}

	// GoogleFontsCDN provides access to Google Fonts (GET only)
	GoogleFontsCDN = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "google-fonts-api",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^fonts.googleapis.com$",
						Method: "^GET$",
						Path:   "^/(css|css2|icon).*$",
					},
				},
				{
					Name: "google-fonts-static",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^fonts.gstatic.com$",
						Method: "^GET$",
						Path:   "^/.*\\.(woff|woff2|ttf|eot|svg)$",
					},
				},
			},
		}
	}

	// BootstrapCDN provides access to Bootstrap CDN (GET only)
	BootstrapCDN = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "bootstrap-cdn",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(maxcdn.bootstrapcdn.com|stackpath.bootstrapcdn.com)$",
						Method: "^GET$",
						Path:   "^/.*\\.(js|css|woff|woff2|ttf|eot|svg|map)$",
					},
				},
			},
		}
	}

	// CloudflareCDNJS provides additional Cloudflare CDN resources (GET only)
	CloudflareCDNJS = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "cloudflare-cdn",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(ajax.cloudflare.com|www.cloudflare.com)$",
						Method: "^GET$",
						Path:   "^/cdn-cgi/.*$",
					},
				},
			},
		}
	}

	// CDNServices aggregates all CDN service policies
	CDNServices = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(CDNJS()).
			Merge(UnpkgCDN()).
			Merge(JsDelivrCDN()).
			Merge(GoogleFontsCDN()).
			Merge(BootstrapCDN()).
			Merge(CloudflareCDNJS())
	}
)
