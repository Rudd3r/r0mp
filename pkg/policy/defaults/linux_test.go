package defaults

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxRepositories(t *testing.T) {
	policy := LinuxRepositories()
	require.NotNil(t, policy)
	require.NotEmpty(t, policy.AcceptRules)

	// Compile the policy to prepare regex patterns
	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		expected string // the name of the policy that should match
	}{
		// Alpine Linux
		{"Alpine main CDN", "dl-cdn.alpinelinux.org", "alpinelinux"},
		{"Alpine UK mirror", "uk.alpinelinux.alpinelinux.org", "alpinelinux"},
		{"Alpine NL mirror", "nl.alpinelinux.alpinelinux.org", "alpinelinux"},
		{"Alpine mirrors", "mirrors.alpinelinux.org", "alpinelinux"},

		// Debian
		{"Debian main", "deb.debian.org", "debian"},
		{"Debian security", "security.debian.org", "debian"},
		{"Debian FTP US", "ftp.us.debian.org", "debian"},
		{"Debian FTP UK", "ftp.uk.debian.org", "debian"},
		{"Debian CDN", "cdn-fastly.deb.debian.org", "debian-cdn"},

		// Ubuntu
		{"Ubuntu archive", "archive.ubuntu.com", "ubuntu"},
		{"Ubuntu security", "security.ubuntu.com", "ubuntu"},
		{"Ubuntu ports", "ports.ubuntu.com", "ubuntu"},
		{"Ubuntu old releases", "old-releases.ubuntu.com", "ubuntu"},

		// Fedora
		{"Fedora download", "download.fedoraproject.org", "fedora"},
		{"Fedora mirrors", "mirrors.fedoraproject.org", "fedora-mirrors"},

		// CentOS
		{"CentOS mirror", "mirror.centos.org", "centos"},
		{"CentOS mirrors", "mirrors.centos.org", "centos"},
		{"CentOS vault", "vault.centos.org", "centos-vault"},

		// Rocky Linux
		{"Rocky Linux dl", "dl.rockylinux.org", "rockylinux"},
		{"Rocky Linux download", "download.rockylinux.org", "rockylinux"},

		// AlmaLinux
		{"AlmaLinux repo", "repo.almalinux.org", "almalinux"},

		// RHEL
		{"RHEL CDN", "cdn.redhat.com", "rhel"},

		// Arch Linux
		{"Arch mirror", "mirror.archlinux.org", "archlinux"},
		{"Arch geo mirror", "geo.mirror.archlinux.org", "archlinux"},
		{"Arch America mirror", "america.mirror.archlinux.org", "archlinux"},
		{"Arch ARM mirror", "mirror.archlinuxarm.org", "archlinux-arm"},
		{"Arch ARM US mirror", "us.mirror.archlinuxarm.org", "archlinux-arm"},

		// OpenSUSE
		{"OpenSUSE download", "download.opensuse.org", "opensuse"},

		// Gentoo
		{"Gentoo distfiles", "distfiles.gentoo.org", "gentoo"},
		{"Gentoo mirrors", "mirrors.gentoo.org", "gentoo"},
		{"Gentoo rsync", "rsync.gentoo.org", "gentoo"},

		// Kali Linux
		{"Kali http", "http.kali.org", "kali"},
		{"Kali download", "kali.download.kali.org", "kali"},

		// Linux Mint
		{"Linux Mint packages", "packages.linuxmint.com", "linuxmint"},

		// Manjaro
		{"Manjaro repo", "repo.manjaro.org", "manjaro"},
		{"Manjaro mirror", "mirror.manjaro.org", "manjaro"},

		// Amazon Linux
		{"Amazon Linux CDN", "cdn.amazonlinux.com", "amazonlinux"},
		{"Amazon Linux AL2023 repo", "al2023-repos-us-east-1-9761ab97.amazonlinux.com", "amazonlinux"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				Host:   tt.host,
				URL:    &url.URL{Host: tt.host},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied, "Host %s should not be denied", tt.host)
			require.NotNil(t, allowed, "Host %s should be allowed", tt.host)
			assert.Equal(t, tt.expected, allowed.Name, "Host %s should match policy %s", tt.host, tt.expected)
		})
	}
}

func TestLinuxRepositoriesRejectsUnknownHosts(t *testing.T) {
	policy := LinuxRepositories()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
	}{
		{"Random domain", "example.com"},
		{"Malicious subdomain", "evil.debian.org.malicious.com"},
		{"Wrong TLD", "deb.debian.net"},
		{"Typo in domain", "debb.debian.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				Host:   tt.host,
				URL:    &url.URL{Host: tt.host},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, allowed, "Host %s should not be allowed", tt.host)
			assert.Nil(t, denied, "Host %s should not match any rule", tt.host)
		})
	}
}

func TestIndividualDistroRepositories(t *testing.T) {
	tests := []struct {
		name     string
		policy   func() *http.Request
		repoFunc func() interface{}
	}{
		{
			name: "AlpineRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "dl-cdn.alpinelinux.org", URL: &url.URL{Host: "dl-cdn.alpinelinux.org"}}
			},
		},
		{
			name: "DebianRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "deb.debian.org", URL: &url.URL{Host: "deb.debian.org"}}
			},
		},
		{
			name: "UbuntuRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "archive.ubuntu.com", URL: &url.URL{Host: "archive.ubuntu.com"}}
			},
		},
		{
			name: "FedoraRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "download.fedoraproject.org", URL: &url.URL{Host: "download.fedoraproject.org"}}
			},
		},
		{
			name: "CentOSRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "mirror.centos.org", URL: &url.URL{Host: "mirror.centos.org"}}
			},
		},
		{
			name: "RockyLinuxRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "dl.rockylinux.org", URL: &url.URL{Host: "dl.rockylinux.org"}}
			},
		},
		{
			name: "AlmaLinuxRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "repo.almalinux.org", URL: &url.URL{Host: "repo.almalinux.org"}}
			},
		},
		{
			name: "RHELRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "cdn.redhat.com", URL: &url.URL{Host: "cdn.redhat.com"}}
			},
		},
		{
			name: "ArchLinuxRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "mirror.archlinux.org", URL: &url.URL{Host: "mirror.archlinux.org"}}
			},
		},
		{
			name: "OpenSUSERepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "download.opensuse.org", URL: &url.URL{Host: "download.opensuse.org"}}
			},
		},
		{
			name: "GentooRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "distfiles.gentoo.org", URL: &url.URL{Host: "distfiles.gentoo.org"}}
			},
		},
		{
			name: "KaliLinuxRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "http.kali.org", URL: &url.URL{Host: "http.kali.org"}}
			},
		},
		{
			name: "LinuxMintRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "packages.linuxmint.com", URL: &url.URL{Host: "packages.linuxmint.com"}}
			},
		},
		{
			name: "ManjaroRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "repo.manjaro.org", URL: &url.URL{Host: "repo.manjaro.org"}}
			},
		},
		{
			name: "AmazonLinuxRepositories",
			policy: func() *http.Request {
				return &http.Request{Host: "cdn.amazonlinux.com", URL: &url.URL{Host: "cdn.amazonlinux.com"}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy interface{}
			switch tt.name {
			case "AlpineRepositories":
				policy = AlpineRepositories()
			case "DebianRepositories":
				policy = DebianRepositories()
			case "UbuntuRepositories":
				policy = UbuntuRepositories()
			case "FedoraRepositories":
				policy = FedoraRepositories()
			case "CentOSRepositories":
				policy = CentOSRepositories()
			case "RockyLinuxRepositories":
				policy = RockyLinuxRepositories()
			case "AlmaLinuxRepositories":
				policy = AlmaLinuxRepositories()
			case "RHELRepositories":
				policy = RHELRepositories()
			case "ArchLinuxRepositories":
				policy = ArchLinuxRepositories()
			case "OpenSUSERepositories":
				policy = OpenSUSERepositories()
			case "GentooRepositories":
				policy = GentooRepositories()
			case "KaliLinuxRepositories":
				policy = KaliLinuxRepositories()
			case "LinuxMintRepositories":
				policy = LinuxMintRepositories()
			case "ManjaroRepositories":
				policy = ManjaroRepositories()
			case "AmazonLinuxRepositories":
				policy = AmazonLinuxRepositories()
			}

			require.NotNil(t, policy, "Policy function should return a non-nil policy")
		})
	}
}

func TestLinuxRepositoriesCompleteness(t *testing.T) {
	policy := LinuxRepositories()
	require.NotNil(t, policy)

	// Verify that LinuxRepositories merges all distro policies
	expectedPolicies := []string{
		"alpinelinux",
		"debian", "debian-cdn",
		"ubuntu",
		"fedora", "fedora-mirrors",
		"centos", "centos-vault",
		"rockylinux",
		"almalinux",
		"rhel",
		"archlinux", "archlinux-arm",
		"opensuse",
		"gentoo",
		"kali",
		"linuxmint",
		"manjaro",
		"amazonlinux",
	}

	policyNames := make(map[string]bool)
	for _, allowed := range policy.AcceptRules {
		policyNames[allowed.Name] = true
	}

	for _, expected := range expectedPolicies {
		assert.True(t, policyNames[expected], "LinuxRepositories should include %s policy", expected)
	}

	// Verify total count
	assert.Equal(t, len(expectedPolicies), len(policy.AcceptRules),
		"LinuxRepositories should have exactly %d policies", len(expectedPolicies))
}
