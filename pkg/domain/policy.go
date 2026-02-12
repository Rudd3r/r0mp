package domain

type PolicyBuilder interface {
	Get(name string) (*ProxyPolicy, error)
	Merge(source, target string) (*ProxyPolicy, error)
	Allow(policyName, ruleName string, domainPattern, methods, paths, schemes []string) (*ProxyPolicy, error)
	Deny(policyName, ruleName string, domainPattern, methods, paths, schemes []string) (*ProxyPolicy, error)
	Auth(name, authType, ruleName, username, secret string) (*ProxyPolicy, error)
	RemoveAuth(name, ruleName string) (*ProxyPolicy, error)
	RemoveRule(name, ruleName string) (*ProxyPolicy, error)
	MoveRule(name, ruleName string, newPosition int) (*ProxyPolicy, error)
	Show(name string) (*ProxyPolicy, error)
	Remove(name string) error
}
