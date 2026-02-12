package domain

type ProxyPolicyDenyRule struct {
	Name  string
	Match *ProxyPolicyMatch
}
