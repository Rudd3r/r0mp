package domain

import (
	"net/http"
	"time"
)

type ProxyConfig struct {
	CertPEM []byte
	KeyPEM  []byte
	Policy  *ProxyPolicy
	Expire  time.Duration
	Version int
}

func (p *ProxyConfig) Compile() (err error) {
	if p.Policy == nil {
		return nil
	}
	return p.Policy.Compile()
}

func (p *ProxyConfig) Find(r *http.Request) (allowed *ProxyPolicyAcceptRule, denied *ProxyPolicyDenyRule) {
	if p.Policy == nil {
		return nil, nil
	}
	return p.Policy.Find(r)
}

type IngressProxyPort struct {
	HostIP     string
	HostPort   uint64
	Scheme     string
	GuestPort  uint64
	PolicyName string
}
