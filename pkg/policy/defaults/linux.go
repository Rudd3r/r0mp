package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	AlpineRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "alpinelinux",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(dl-cdn|uk.alpinelinux|nl.alpinelinux|mirrors).alpinelinux.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	DebianRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "debian",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(deb|ftp.[a-z]{2}|security).debian.org$",
						Method: "^(GET|HEAD)$",
					},
				},
				{
					Name: "debian-cdn",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^cdn-[a-z]+.deb.debian.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	UbuntuRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "ubuntu",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(security|archive|ports|old-releases).ubuntu.com$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	FedoraRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "fedora",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^download.fedoraproject.org$",
						Method: "^(GET|HEAD)$",
					},
				},
				{
					Name: "fedora-mirrors",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^mirrors.fedoraproject.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	CentOSRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "centos",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^mirror(s)?.centos.org$",
						Method: "^(GET|HEAD)$",
					},
				},
				{
					Name: "centos-vault",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^vault.centos.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	RockyLinuxRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "rockylinux",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(dl|download).rockylinux.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	AlmaLinuxRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "almalinux",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^repo.almalinux.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	RHELRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "rhel",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^cdn.redhat.com$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	ArchLinuxRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "archlinux",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(mirror|geo.mirror|america.mirror).archlinux.org$",
						Method: "^(GET|HEAD)$",
					},
				},
				{
					Name: "archlinux-arm",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(mirror|[a-z]{2}.mirror).archlinuxarm.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	OpenSUSERepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "opensuse",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^download.opensuse.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	GentooRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "gentoo",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(distfiles|mirrors|rsync).gentoo.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	KaliLinuxRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "kali",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(http|kali.download).kali.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	LinuxMintRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "linuxmint",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^packages.linuxmint.com$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	ManjaroRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "manjaro",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(repo|mirror).manjaro.org$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	AmazonLinuxRepositories = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "amazonlinux",
					Match: &domain.ProxyPolicyMatch{
						Host:   "^(cdn|al[0-9]+-repos-[a-z]+-[a-z]+-[0-9]+-[a-z0-9]+).amazonlinux.com$",
						Method: "^(GET|HEAD)$",
					},
				},
			},
		}
	}
	LinuxRepositories = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(UbuntuRepositories()).
			Merge(DebianRepositories()).
			Merge(AlpineRepositories()).
			Merge(FedoraRepositories()).
			Merge(CentOSRepositories()).
			Merge(RockyLinuxRepositories()).
			Merge(AlmaLinuxRepositories()).
			Merge(RHELRepositories()).
			Merge(ArchLinuxRepositories()).
			Merge(OpenSUSERepositories()).
			Merge(GentooRepositories()).
			Merge(KaliLinuxRepositories()).
			Merge(LinuxMintRepositories()).
			Merge(ManjaroRepositories()).
			Merge(AmazonLinuxRepositories())
	}
)
