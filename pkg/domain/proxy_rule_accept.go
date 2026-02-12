package domain

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/time/rate"
)

type ProxyPolicyAcceptRule struct {
	Name         string
	Match        *ProxyPolicyMatch
	ActionModify []ActionModify   `json:",omitempty"`
	RateLimit    *RateLimitConfig `json:",omitempty"`

	actionModify []func(r *http.Request) error
	rateLimiter  *rate.Limiter
	secretstore  SecretReadWriter
}

type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

func (p *ProxyPolicyAcceptRule) Modify(r *http.Request) {
	for i, action := range p.actionModify {
		if err := action(r); err != nil {
			fmt.Printf("ERROR: modify proxy allow %s action (%d): %v", p.Name, i, err) // TODO return error
		}
	}
}

func (p *ProxyPolicyAcceptRule) Wait(ctx context.Context) {
	if p.rateLimiter != nil {
		_ = p.rateLimiter.Wait(ctx)
	}
}

func (p *ProxyPolicyAcceptRule) Compile(secretstore SecretReadWriter) (err error) {
	p.secretstore = secretstore
	for _, action := range p.ActionModify {
		var a func(r *http.Request) error
		switch action.Name {
		case "set_bearer_token":
			a, err = proxyActionModifyAuthBearer(action.Args, p.secretstore)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "set_host":
			a, err = proxyActionModifyHost(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "set_path":
			a, err = proxyActionModifyPath(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "set_header":
			a, err = proxyActionModifySetHeader(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "delete_header":
			a, err = proxyActionModifyDeleteHeader(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "add_path_prefix":
			a, err = proxyActionModifyAddPathPrefix(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "remove_path_prefix":
			a, err = proxyActionModifyRemovePathPrefix(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "set_basic_auth":
			a, err = proxyActionModifySetBasicAuth(action.Args, p.secretstore)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "add_query_param":
			a, err = proxyActionModifyAddQueryParam(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "set_query_param":
			a, err = proxyActionModifySetQueryParam(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "delete_query_param":
			a, err = proxyActionModifyDeleteQueryParam(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "set_scheme":
			a, err = proxyActionModifySetScheme(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		case "rewrite_path":
			a, err = proxyActionModifyRewritePath(action.Args...)
			if err != nil {
				return fmt.Errorf("compile proxy action (%s): %w", action.Name, err)
			}
			p.actionModify = append(p.actionModify, a)
		}
	}

	if p.RateLimit != nil {
		if p.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("rate limit requests per second must be positive")
		}
		if p.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate limit burst must be positive")
		}
		p.rateLimiter = rate.NewLimiter(rate.Limit(p.RateLimit.RequestsPerSecond), p.RateLimit.Burst)
	}

	return p.Match.Compile()
}
