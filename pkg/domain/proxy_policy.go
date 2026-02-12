package domain

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"time"
)

type ProxyPolicy struct {
	Name        string
	AcceptRules []*ProxyPolicyAcceptRule `json:",omitempty"`
	DenyRules   []*ProxyPolicyDenyRule   `json:",omitempty"`
	Expire      time.Duration            `json:",omitempty"`
	Secrets     []byte                   `json:",omitempty"`
	Version     int

	unlocker SecretReadWriter
}

func (s *ProxyPolicy) Unlock(unlocker SecretReadWriter) (err error) {
	unlocker.Reset()
	s.unlocker = unlocker
	_, err = io.Copy(s.unlocker, bytes.NewReader(s.Secrets))
	if err != nil {
		return err
	}
	return s.unlocker.Unlock()
}

func (p *ProxyPolicy) Allow(allow *ProxyPolicyAcceptRule) {
	if i := slices.IndexFunc(p.AcceptRules, func(x *ProxyPolicyAcceptRule) bool { return x.Name == allow.Name }); i > -1 {
		p.AcceptRules[i] = allow
	} else {
		p.AcceptRules = append(p.AcceptRules, allow)
	}
}

func (p *ProxyPolicy) Deny(deny *ProxyPolicyDenyRule) {
	if i := slices.IndexFunc(p.DenyRules, func(x *ProxyPolicyDenyRule) bool { return x.Name == deny.Name }); i > -1 {
		p.DenyRules[i] = deny
	} else {
		p.DenyRules = append(p.DenyRules, deny)
	}
}

func (p *ProxyPolicy) Merge(cfg *ProxyPolicy) *ProxyPolicy {
	merged := p.Clone()
	if merged.Name == "" {
		merged.Name = cfg.Name
	}
	// Fix: Check if cfg has Expire, not merged
	if cfg.Expire > 0 {
		merged.Expire = cfg.Expire
	}

	// Handle secrets merging using SecretReadWriter.Merge()
	// Both original policies must have unlocked unlockers to merge secrets
	if p.unlocker != nil && cfg.unlocker != nil {
		// Merge secrets from cfg into base's unlocker
		if err := p.unlocker.Merge(cfg.unlocker); err != nil {
			// Log error but continue - secrets merging failure shouldn't break policy merge
			fmt.Printf("WARNING: failed to merge secrets: %v\n", err)
		} else {
			// Lock to save the merged secrets
			if err := p.unlocker.Lock(); err != nil {
				fmt.Printf("WARNING: failed to lock merged secrets: %v\n", err)
			} else {
				// Update the Secrets field with the merged data
				merged.Secrets = p.unlocker.Bytes()
				merged.unlocker = p.unlocker
				// Unlock again so the merged policy can be used
				if err := p.unlocker.Unlock(); err != nil {
					fmt.Printf("WARNING: failed to unlock merged secrets: %v\n", err)
				}
			}
		}
	} else if len(cfg.Secrets) > 0 && len(merged.Secrets) == 0 {
		// If merged has no secrets but cfg does, copy them directly
		merged.Secrets = make([]byte, len(cfg.Secrets))
		copy(merged.Secrets, cfg.Secrets)
		if cfg.unlocker != nil {
			merged.unlocker = cfg.unlocker
		}
	}
	// If merged has secrets but cfg doesn't, keep merged's secrets (from Clone)

	for _, policy := range cfg.AcceptRules {
		cp := &ProxyPolicyAcceptRule{
			Name:         policy.Name,
			ActionModify: policy.ActionModify,
		}
		if policy.Match != nil {
			cp.Match = &ProxyPolicyMatch{
				Host:        policy.Match.Host,
				Method:      policy.Match.Method,
				Path:        policy.Match.Path,
				Header:      maps.Clone(policy.Match.Header),
				Query:       maps.Clone(policy.Match.Query),
				Fragment:    policy.Match.Fragment,
				ContentType: policy.Match.ContentType,
			}
		}
		if policy.RateLimit != nil {
			cp.RateLimit = &RateLimitConfig{
				RequestsPerSecond: policy.RateLimit.RequestsPerSecond,
				Burst:             policy.RateLimit.Burst,
			}
		}
		merged.Allow(cp)
	}
	for _, denied := range cfg.DenyRules {
		cp := &ProxyPolicyDenyRule{
			Name: denied.Name,
		}
		if denied.Match != nil {
			cp.Match = &ProxyPolicyMatch{
				Host:        denied.Match.Host,
				Method:      denied.Match.Method,
				Path:        denied.Match.Path,
				Header:      maps.Clone(denied.Match.Header),
				Query:       maps.Clone(denied.Match.Query),
				Fragment:    denied.Match.Fragment,
				ContentType: denied.Match.ContentType,
			}
		}
		merged.Deny(cp)
	}
	return merged
}

func (p *ProxyPolicy) Clone() *ProxyPolicy {
	cloned := &ProxyPolicy{
		Name:    p.Name,
		Expire:  p.Expire,
		Version: p.Version,
	}
	// Copy Secrets byte slice
	if len(p.Secrets) > 0 {
		cloned.Secrets = make([]byte, len(p.Secrets))
		copy(cloned.Secrets, p.Secrets)
	}
	for _, policy := range p.AcceptRules {
		cp := &ProxyPolicyAcceptRule{
			Name:         policy.Name,
			ActionModify: policy.ActionModify,
		}
		if policy.Match != nil {
			cp.Match = &ProxyPolicyMatch{
				Host:        policy.Match.Host,
				Method:      policy.Match.Method,
				Path:        policy.Match.Path,
				Header:      maps.Clone(policy.Match.Header),
				Query:       maps.Clone(policy.Match.Query),
				Fragment:    policy.Match.Fragment,
				ContentType: policy.Match.ContentType,
			}
		}
		if policy.RateLimit != nil {
			cp.RateLimit = &RateLimitConfig{
				RequestsPerSecond: policy.RateLimit.RequestsPerSecond,
				Burst:             policy.RateLimit.Burst,
			}
		}
		cloned.AcceptRules = append(cloned.AcceptRules, cp)
	}
	for _, denied := range p.DenyRules {
		cp := &ProxyPolicyDenyRule{
			Name: denied.Name,
		}
		if denied.Match != nil {
			cp.Match = &ProxyPolicyMatch{
				Host:        denied.Match.Host,
				Method:      denied.Match.Method,
				Path:        denied.Match.Path,
				Header:      maps.Clone(denied.Match.Header),
				Query:       maps.Clone(denied.Match.Query),
				Fragment:    denied.Match.Fragment,
				ContentType: denied.Match.ContentType,
			}
		}
		cloned.DenyRules = append(cloned.DenyRules, cp)
	}
	return cloned
}

func (p *ProxyPolicy) Compile() (err error) {
	for _, policy := range p.AcceptRules {
		if err = policy.Compile(p.unlocker); err != nil {
			return fmt.Errorf("compile proxy allow policy (%s): %w", policy.Name, err)
		}
	}
	for _, policy := range p.DenyRules {
		if err = policy.Match.Compile(); err != nil {
			return fmt.Errorf("compile proxy deny policy (%s): %w", policy.Name, err)
		}
	}
	return nil
}

func (p *ProxyPolicy) Find(r *http.Request) (allowed *ProxyPolicyAcceptRule, denied *ProxyPolicyDenyRule) {
	for _, policy := range p.DenyRules {
		if policy.Match.Match(r) {
			return nil, policy
		}
	}
	for _, policy := range p.AcceptRules {
		if policy.Match.Match(r) {
			return policy, nil
		}
	}
	return nil, nil
}
