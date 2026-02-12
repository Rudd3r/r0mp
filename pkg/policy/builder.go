package policy

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/policy/defaults"
	"github.com/google/uuid"
)

var builtInPolicies = func() map[string]*domain.ProxyPolicy {
	m := map[string]*domain.ProxyPolicy{

		"default":   defaults.Default(),
		"allow_all": defaults.AllowAll(),
		"deny_all":  defaults.DenyAll(),

		// Linux distributions
		"linux_all":         defaults.LinuxRepositories(),
		"linux_alpine":      defaults.AlpineRepositories(),
		"linux_debian":      defaults.DebianRepositories(),
		"linux_ubuntu":      defaults.UbuntuRepositories(),
		"linux_fedora":      defaults.FedoraRepositories(),
		"linux_centos":      defaults.CentOSRepositories(),
		"linux_rocky":       defaults.RockyLinuxRepositories(),
		"linux_almalinux":   defaults.AlmaLinuxRepositories(),
		"linux_rhel":        defaults.RHELRepositories(),
		"linux_arch":        defaults.ArchLinuxRepositories(),
		"linux_opensuse":    defaults.OpenSUSERepositories(),
		"linux_gentoo":      defaults.GentooRepositories(),
		"linux_kali":        defaults.KaliLinuxRepositories(),
		"linux_linuxmint":   defaults.LinuxMintRepositories(),
		"linux_manjaro":     defaults.ManjaroRepositories(),
		"linux_amazonlinux": defaults.AmazonLinuxRepositories(),

		// LLM providers
		"llm_all":         defaults.LLMProviders(),
		"llm_openai":      defaults.OpenAIProvider(),
		"llm_anthropic":   defaults.AnthropicProvider(),
		"llm_googleai":    defaults.GoogleAIProvider(),
		"llm_cohere":      defaults.CohereProvider(),
		"llm_openrouter":  defaults.OpenRouterProvider(),
		"llm_together":    defaults.TogetherAIProvider(),
		"llm_anyscale":    defaults.AnyscaleProvider(),
		"llm_replicate":   defaults.ReplicateProvider(),
		"llm_huggingface": defaults.HuggingFaceProvider(),
		"llm_mistral":     defaults.MistralAIProvider(),
		"llm_perplexity":  defaults.PerplexityProvider(),
		"llm_ai21":        defaults.AI21Provider(),
		"llm_awsbedrock":  defaults.AWSBedrockProvider(),
		"llm_azureopenai": defaults.AzureOpenAIProvider(),
		"llm_groq":        defaults.GroqProvider(),
		"llm_fireworks":   defaults.FireworksAIProvider(),
		"llm_deepseek":    defaults.DeepSeekProvider(),
		"llm_stability":   defaults.StabilityAIProvider(),

		// Package registries
		"packages_all":       defaults.PackageRegistries(),
		"packages_npm":       defaults.NPMRegistry(),
		"packages_pypi":      defaults.PyPIRegistry(),
		"packages_rubygems":  defaults.RubyGemsRegistry(),
		"packages_crates":    defaults.CratesIORegistry(),
		"packages_maven":     defaults.MavenCentralRegistry(),
		"packages_gomodules": defaults.GoModulesRegistry(),
		"packages_nuget":     defaults.NuGetRegistry(),

		// Container registries
		"containers_all":       defaults.ContainerRegistries(),
		"containers_dockerhub": defaults.DockerHubRegistry(),
		"containers_ghcr":      defaults.GitHubContainerRegistry(),
		"containers_gcr":       defaults.GoogleContainerRegistry(),
		"containers_ecr":       defaults.AWSContainerRegistry(),
		"containers_quay":      defaults.QuayRegistry(),
		"containers_acr":       defaults.AzureContainerRegistry(),

		// Version control systems
		"vcs_all":       defaults.VersionControlSystems(),
		"vcs_github":    defaults.GitHubVCS(),
		"vcs_gitlab":    defaults.GitLabVCS(),
		"vcs_bitbucket": defaults.BitbucketVCS(),

		// CDN services
		"cdn_all":          defaults.CDNServices(),
		"cdn_cdnjs":        defaults.CDNJS(),
		"cdn_unpkg":        defaults.UnpkgCDN(),
		"cdn_jsdelivr":     defaults.JsDelivrCDN(),
		"cdn_googlefonts":  defaults.GoogleFontsCDN(),
		"cdn_bootstrapcdn": defaults.BootstrapCDN(),
	}
	for name, policy := range m {
		policy.Name = name
	}
	return m
}()

type PolicyBuilder struct {
	storePath string
	unlocker  domain.SecretReadWriter
}

func NewPolicyBuilder(storePath string, unlocker domain.SecretReadWriter) *PolicyBuilder {
	return &PolicyBuilder{
		storePath: storePath,
		unlocker:  unlocker,
	}
}

func (b *PolicyBuilder) New(name string) (*domain.ProxyPolicy, error) {
	if name == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}
	if _, found := builtInPolicies[name]; found {
		return nil, fmt.Errorf("built in policy %s cannot be created", name)
	}
	policy := &domain.ProxyPolicy{
		Name:        name,
		AcceptRules: []*domain.ProxyPolicyAcceptRule{},
		DenyRules:   []*domain.ProxyPolicyDenyRule{},
	}
	return b.store(name, policy)
}

func (b *PolicyBuilder) store(name string, policy *domain.ProxyPolicy) (*domain.ProxyPolicy, error) {
	if _, found := builtInPolicies[name]; found {
		return nil, fmt.Errorf("built in policy %s cannot be changed", name)
	}
	if err := os.MkdirAll(b.storePath, 0755); err != nil {
		return nil, fmt.Errorf("creating policy directory: %w", err)
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling policy: %w", err)
	}
	policyPath := filepath.Join(b.storePath, name+".json")
	if err := os.WriteFile(policyPath, data, 0644); err != nil {
		return nil, fmt.Errorf("writing policy file: %w", err)
	}
	return policy, nil
}

func (b *PolicyBuilder) Get(name string) (*domain.ProxyPolicy, error) {
	if policy, found := builtInPolicies[name]; found {
		return policy.Clone(), nil
	}
	policyPath := filepath.Join(b.storePath, name+".json")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("policy %s not found", name)
		}
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	policy := &domain.ProxyPolicy{}
	if err := json.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("unmarshalling policy: %w", err)
	}
	return policy, nil
}

func (b *PolicyBuilder) Merge(source, target string) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(target)
	if err != nil {
		return nil, err
	}
	sourcePolicy, err := b.Get(source)
	if err != nil {
		return nil, err
	}
	proxyPolicy = proxyPolicy.Merge(sourcePolicy)
	return b.store(target, proxyPolicy)
}

func (b *PolicyBuilder) Allow(policyName, ruleName string, domainPattern, methods, paths, schemes []string) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(policyName)
	if err != nil {
		return nil, err
	}
	var method, path, scheme string
	if len(methods) > 0 {
		method = patternToRegex(strings.Join(methods, "|"))
	}
	if len(paths) > 0 {
		path = patternToRegex(strings.Join(paths, "|"))
	}
	if len(schemes) > 0 {
		scheme = patternToRegex(strings.Join(schemes, "|"))
	}
	proxyPolicy.Allow(&domain.ProxyPolicyAcceptRule{
		Name: ruleName,
		Match: &domain.ProxyPolicyMatch{
			Host:   patternToRegex(strings.Join(domainPattern, "|")),
			Method: method,
			Path:   path,
			Scheme: scheme,
		},
		ActionModify: nil,
		RateLimit:    nil,
	})
	return b.store(policyName, proxyPolicy)
}

func (b *PolicyBuilder) Deny(policyName, ruleName string, domainPattern, methods, paths, schemes []string) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(policyName)
	if err != nil {
		return nil, err
	}
	var method, path, scheme string
	if len(methods) > 0 {
		method = patternToRegex(strings.Join(methods, "|"))
	}
	if len(paths) > 0 {
		path = patternToRegex(strings.Join(paths, "|"))
	}
	if len(schemes) > 0 {
		scheme = patternToRegex(strings.Join(schemes, "|"))
	}
	proxyPolicy.Deny(&domain.ProxyPolicyDenyRule{
		Name: ruleName,
		Match: &domain.ProxyPolicyMatch{
			Host:   patternToRegex(strings.Join(domainPattern, "|")),
			Method: method,
			Path:   path,
			Scheme: scheme,
		},
	})
	return b.store(policyName, proxyPolicy)
}

func (b *PolicyBuilder) Auth(name, authType, ruleName, username, secret string) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(name)
	if err != nil {
		return nil, err
	}

	i := slices.IndexFunc(proxyPolicy.AcceptRules, func(x *domain.ProxyPolicyAcceptRule) bool { return x.Name == ruleName })
	if i < 0 {
		return nil, fmt.Errorf("domain name not in proxy policy %s", name)
	}

	if err = proxyPolicy.Unlock(b.unlocker); err != nil {
		return nil, err
	}

	allow := proxyPolicy.AcceptRules[i]

	// Find and remove any existing auth for this rule
	var existingAuthIndex = -1
	for j, action := range allow.ActionModify {
		if action.Name == "set_bearer_token" || action.Name == "set_basic_auth" {
			existingAuthIndex = j
			break
		}
	}

	// Remove existing auth if found
	if existingAuthIndex >= 0 {
		allow.ActionModify = append(allow.ActionModify[:existingAuthIndex], allow.ActionModify[existingAuthIndex+1:]...)
	}

	secretID := uuid.New().String()
	if err = b.unlocker.SetSecret(secretID, secret); err != nil {
		return nil, fmt.Errorf("failed to set secret for rule %s: %v", ruleName, err)
	}
	if err = b.unlocker.Lock(); err != nil {
		return nil, fmt.Errorf("failed to lock rule %s: %v", ruleName, err)
	}
	proxyPolicy.Secrets = b.unlocker.Bytes()
	b.unlocker.Reset()

	// Add new auth
	switch authType {
	case "bearer":
		allow.ActionModify = append(allow.ActionModify, domain.ActionModify{
			Name: "set_bearer_token",
			Args: []string{secretID},
		})
	case "basic":
		allow.ActionModify = append(allow.ActionModify, domain.ActionModify{
			Name: "set_basic_auth",
			Args: []string{username, secretID},
		})
	default:
		return nil, fmt.Errorf("unsupported auth method")
	}
	return b.store(name, proxyPolicy)
}

func (b *PolicyBuilder) RemoveAuth(name, ruleName string) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(name)
	if err != nil {
		return nil, err
	}

	i := slices.IndexFunc(proxyPolicy.AcceptRules, func(x *domain.ProxyPolicyAcceptRule) bool { return x.Name == ruleName })
	if i < 0 {
		return nil, fmt.Errorf("rule %s not found in policy %s", ruleName, name)
	}

	allow := proxyPolicy.AcceptRules[i]

	// Find and remove any existing auth for this rule
	var authIndex = -1
	for j, action := range allow.ActionModify {
		if action.Name == "set_bearer_token" || action.Name == "set_basic_auth" {
			authIndex = j
			break
		}
	}

	if authIndex < 0 {
		return nil, fmt.Errorf("no auth found for rule %s in policy %s", ruleName, name)
	}

	// Remove the auth action
	allow.ActionModify = append(allow.ActionModify[:authIndex], allow.ActionModify[authIndex+1:]...)

	return b.store(name, proxyPolicy)
}

func (b *PolicyBuilder) RemoveRule(name, ruleName string) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(name)
	if err != nil {
		return nil, err
	}

	// Try to find and remove from AcceptRules rules
	allowedIndex := slices.IndexFunc(proxyPolicy.AcceptRules, func(x *domain.ProxyPolicyAcceptRule) bool { return x.Name == ruleName })
	if allowedIndex >= 0 {
		proxyPolicy.AcceptRules = append(proxyPolicy.AcceptRules[:allowedIndex], proxyPolicy.AcceptRules[allowedIndex+1:]...)
		return b.store(name, proxyPolicy)
	}

	// Try to find and remove from DenyRules rules
	deniedIndex := slices.IndexFunc(proxyPolicy.DenyRules, func(x *domain.ProxyPolicyDenyRule) bool { return x.Name == ruleName })
	if deniedIndex >= 0 {
		proxyPolicy.DenyRules = append(proxyPolicy.DenyRules[:deniedIndex], proxyPolicy.DenyRules[deniedIndex+1:]...)
		return b.store(name, proxyPolicy)
	}

	return nil, fmt.Errorf("rule %s not found in policy %s", ruleName, name)
}

func (b *PolicyBuilder) MoveRule(name, ruleName string, newPosition int) (*domain.ProxyPolicy, error) {
	proxyPolicy, err := b.Get(name)
	if err != nil {
		return nil, err
	}

	// Try to find and move in allowed rules
	allowedIndex := slices.IndexFunc(proxyPolicy.AcceptRules, func(x *domain.ProxyPolicyAcceptRule) bool { return x.Name == ruleName })
	if allowedIndex >= 0 {
		if newPosition < 0 || newPosition >= len(proxyPolicy.AcceptRules) {
			return nil, fmt.Errorf("position %d out of range (0-%d)", newPosition, len(proxyPolicy.AcceptRules)-1)
		}

		if allowedIndex == newPosition {
			return proxyPolicy, nil // Already in correct position
		}

		// Remove from current position
		removed := proxyPolicy.AcceptRules[allowedIndex]
		proxyPolicy.AcceptRules = append(proxyPolicy.AcceptRules[:allowedIndex], proxyPolicy.AcceptRules[allowedIndex+1:]...)

		// Insert at new position
		// newPosition represents the final desired position
		// Ensure it's within bounds of the shortened array
		insertPos := newPosition
		if insertPos > len(proxyPolicy.AcceptRules) {
			insertPos = len(proxyPolicy.AcceptRules)
		}

		proxyPolicy.AcceptRules = append(proxyPolicy.AcceptRules[:insertPos], append([]*domain.ProxyPolicyAcceptRule{removed}, proxyPolicy.AcceptRules[insertPos:]...)...)
		return b.store(name, proxyPolicy)
	}

	// Try to find and move in denied rules
	deniedIndex := slices.IndexFunc(proxyPolicy.DenyRules, func(x *domain.ProxyPolicyDenyRule) bool { return x.Name == ruleName })
	if deniedIndex >= 0 {
		if newPosition < 0 || newPosition >= len(proxyPolicy.DenyRules) {
			return nil, fmt.Errorf("position %d out of range (0-%d)", newPosition, len(proxyPolicy.DenyRules)-1)
		}

		if deniedIndex == newPosition {
			return proxyPolicy, nil // Already in correct position
		}

		// Remove from current position
		removed := proxyPolicy.DenyRules[deniedIndex]
		proxyPolicy.DenyRules = append(proxyPolicy.DenyRules[:deniedIndex], proxyPolicy.DenyRules[deniedIndex+1:]...)

		// Insert at new position
		// newPosition represents the final desired position
		// Ensure it's within bounds of the shortened array
		insertPos := newPosition
		if insertPos > len(proxyPolicy.DenyRules) {
			insertPos = len(proxyPolicy.DenyRules)
		}

		proxyPolicy.DenyRules = append(proxyPolicy.DenyRules[:insertPos], append([]*domain.ProxyPolicyDenyRule{removed}, proxyPolicy.DenyRules[insertPos:]...)...)
		return b.store(name, proxyPolicy)
	}

	return nil, fmt.Errorf("rule %s not found in policy %s", ruleName, name)
}

func (b *PolicyBuilder) Show(name string) (*domain.ProxyPolicy, error) {
	return b.Get(name)
}

func sortName(name string) int {
	switch name {
	case "deny_all":
		return 1
	case "allow_all":
		return 2
	case "default":
		return 3
	default:
		return 0
	}
}

func (b *PolicyBuilder) List() ([]*domain.ProxyPolicy, error) {
	policies := []*domain.ProxyPolicy{}
	defer func() {
		slices.SortFunc(policies, func(a, b *domain.ProxyPolicy) int {
			sortInt := sortName(b.Name) - sortName(a.Name)
			if sortInt != 0 {
				return sortInt
			}
			return cmp.Compare(a.Name, b.Name)
		})
	}()

	// Add built-in policies
	for _, policy := range builtInPolicies {
		p := policy.Clone()
		policies = append(policies, p)
	}

	// Add custom policies from disk
	entries, err := os.ReadDir(b.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return policies, nil
		}
		return nil, fmt.Errorf("reading policy directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		policy, err := b.Get(name)
		if err != nil {
			continue
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func (b *PolicyBuilder) Remove(name string) error {
	if _, found := builtInPolicies[name]; found {
		return fmt.Errorf("built in policy %s cannot be changed", name)
	}
	policyPath := filepath.Join(b.storePath, name+".json")
	if err := os.Remove(policyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policy %s not found", name)
		}
		return fmt.Errorf("removing policy file: %w", err)
	}
	return nil
}

func patternToRegex(pattern string) string {
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	return fmt.Sprintf("^%s$", pattern)
}
