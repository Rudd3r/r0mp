package defaults

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLLMProviders(t *testing.T) {
	policy := LLMProviders()
	require.NotNil(t, policy)
	require.NotEmpty(t, policy.AcceptRules)

	// Compile the policy to prepare regex patterns
	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		path     string
		expected string // the name of the policy that should match
	}{
		// OpenAI
		{"OpenAI Chat", "api.openai.com", "/v1/chat/completions", "openai"},
		{"OpenAI Embeddings", "api.openai.com", "/v1/embeddings", "openai"},
		{"OpenAI Images", "api.openai.com", "/v1/images/generations", "openai"},

		// Anthropic
		{"Anthropic Messages", "api.anthropic.com", "/v1/messages", "anthropic"},

		// Google AI
		{"Google AI Generate", "generativelanguage.googleapis.com", "/v1/models/gemini-pro:generateContent", "google-ai"},
		{"Google AI Dev", "ai.google.dev", "/v1beta/models/gemini-pro:streamGenerateContent", "google-ai"},

		// Cohere
		{"Cohere Chat", "api.cohere.ai", "/v1/chat", "cohere"},
		{"Cohere Embed", "api.cohere.com", "/v2/embed", "cohere"},

		// OpenRouter
		{"OpenRouter Chat", "openrouter.ai", "/api/v1/chat/completions", "openrouter"},

		// Together AI
		{"Together AI Chat", "api.together.xyz", "/v1/chat/completions", "together"},

		// Anyscale
		{"Anyscale Chat", "api.endpoints.anyscale.com", "/v1/chat/completions", "anyscale"},

		// Replicate
		{"Replicate Predictions", "api.replicate.com", "/v1/predictions", "replicate"},

		// Hugging Face
		{"Hugging Face Model", "api-inference.huggingface.co", "/models/gpt2", "huggingface"},
		{"Hugging Face Chat", "huggingface.co", "/v1/chat/completions", "huggingface"},

		// Mistral AI
		{"Mistral Chat", "api.mistral.ai", "/v1/chat/completions", "mistral"},

		// Perplexity
		{"Perplexity Chat", "api.perplexity.ai", "/chat/completions", "perplexity"},

		// AI21 Labs
		{"AI21 Complete", "api.ai21.com", "/studio/v1/complete", "ai21"},

		// AWS Bedrock (regional)
		{"AWS Bedrock Invoke", "bedrock-runtime.us-east-1.amazonaws.com", "/model/anthropic.claude-v2/invoke", "aws-bedrock"},
		{"AWS Bedrock Converse", "bedrock-runtime.eu-west-1.amazonaws.com", "/model/meta.llama3/converse", "aws-bedrock"},
		{"AWS Bedrock Stream", "bedrock-runtime.ap-southeast-1.amazonaws.com", "/model/amazon.titan/invoke-with-response-stream", "aws-bedrock"},

		// Azure OpenAI (custom deployments)
		{"Azure OpenAI Chat", "my-resource.openai.azure.com", "/openai/deployments/gpt-4/chat/completions", "azure-openai"},
		{"Azure OpenAI Embed", "eu-deployment.openai.azure.com", "/openai/deployments/text-embedding-ada/embeddings", "azure-openai"},

		// Groq
		{"Groq Chat", "api.groq.com", "/openai/v1/chat/completions", "groq"},

		// Fireworks AI
		{"Fireworks Chat", "api.fireworks.ai", "/inference/v1/chat/completions", "fireworks"},

		// DeepSeek
		{"DeepSeek Chat", "api.deepseek.com", "/v1/chat/completions", "deepseek"},

		// Stability AI
		{"Stability Gen", "api.stability.ai", "/v1/generation/stable-diffusion-xl-1024-v1-0/text-to-image", "stability"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host: tt.host,
				URL:  &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied, "Host %s path %s should not be denied", tt.host, tt.path)
			require.NotNil(t, allowed, "Host %s path %s should be allowed", tt.host, tt.path)
			assert.Equal(t, tt.expected, allowed.Name, "Host %s path %s should match policy %s", tt.host, tt.path, tt.expected)
		})
	}
}

func TestLLMProvidersRejectsUnknownHosts(t *testing.T) {
	policy := LLMProviders()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"Random domain", "example.com", "/v1/chat/completions"},
		{"Malicious subdomain", "api.openai.com.malicious.com", "/v1/chat/completions"},
		{"Wrong subdomain", "fake.openai.com", "/v1/chat/completions"},
		{"Typo in domain", "api.opena1.com", "/v1/chat/completions"},
		{"Non-API subdomain", "www.anthropic.com", "/v1/messages"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host: tt.host,
				URL:  &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s should not be allowed", tt.host, tt.path)
			assert.Nil(t, denied, "Host %s path %s should not match any rule", tt.host, tt.path)
		})
	}
}

func TestLLMProvidersRejectsInvalidPaths(t *testing.T) {
	policy := LLMProviders()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	tests := []struct {
		name string
		host string
		path string
	}{
		{"OpenAI admin endpoint", "api.openai.com", "/admin/users"},
		{"OpenAI billing", "api.openai.com", "/v1/billing/usage"},
		{"Anthropic invalid path", "api.anthropic.com", "/admin/keys"},
		{"Random path on valid host", "api.openai.com", "/random/path"},
		{"Path traversal attempt", "api.anthropic.com", "/../etc/passwd"},
		{"Groq wrong path", "api.groq.com", "/v1/chat/completions"}, // should be /openai/v1/
		{"Together wrong version", "api.together.xyz", "/v2/chat/completions"},
		{"Mistral admin path", "api.mistral.ai", "/admin/users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host: tt.host,
				URL:  &url.URL{Host: tt.host, Path: tt.path},
			}

			allowed, _ := policy.Find(req)
			assert.Nil(t, allowed, "Host %s path %s should not be allowed (invalid path)", tt.host, tt.path)
		})
	}
}

func TestIndividualLLMProviders(t *testing.T) {
	tests := []struct {
		name         string
		policyFunc   func() *domain.ProxyPolicy
		expectedHost string
		expectedPath string
		policyName   string
	}{
		{"OpenAI", OpenAIProvider, "api.openai.com", "/v1/chat/completions", "openai"},
		{"Anthropic", AnthropicProvider, "api.anthropic.com", "/v1/messages", "anthropic"},
		{"Google AI", GoogleAIProvider, "generativelanguage.googleapis.com", "/v1/models/test:generateContent", "google-ai"},
		{"Cohere", CohereProvider, "api.cohere.ai", "/v1/chat", "cohere"},
		{"OpenRouter", OpenRouterProvider, "openrouter.ai", "/api/v1/chat/completions", "openrouter"},
		{"Together AI", TogetherAIProvider, "api.together.xyz", "/v1/chat/completions", "together"},
		{"Anyscale", AnyscaleProvider, "api.endpoints.anyscale.com", "/v1/chat/completions", "anyscale"},
		{"Replicate", ReplicateProvider, "api.replicate.com", "/v1/predictions", "replicate"},
		{"Hugging Face", HuggingFaceProvider, "api-inference.huggingface.co", "/models/test", "huggingface"},
		{"Mistral AI", MistralAIProvider, "api.mistral.ai", "/v1/chat/completions", "mistral"},
		{"Perplexity", PerplexityProvider, "api.perplexity.ai", "/chat/completions", "perplexity"},
		{"AI21", AI21Provider, "api.ai21.com", "/studio/v1/chat/completions", "ai21"},
		{"AWS Bedrock", AWSBedrockProvider, "bedrock-runtime.us-east-1.amazonaws.com", "/model/test/invoke", "aws-bedrock"},
		{"Azure OpenAI", AzureOpenAIProvider, "my-resource.openai.azure.com", "/openai/deployments/gpt-4/chat/completions", "azure-openai"},
		{"Groq", GroqProvider, "api.groq.com", "/openai/v1/chat/completions", "groq"},
		{"Fireworks AI", FireworksAIProvider, "api.fireworks.ai", "/inference/v1/chat/completions", "fireworks"},
		{"DeepSeek", DeepSeekProvider, "api.deepseek.com", "/v1/chat/completions", "deepseek"},
		{"Stability AI", StabilityAIProvider, "api.stability.ai", "/v1/generation/test", "stability"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.policyFunc()
			require.NotNil(t, policy, "Policy function should return a non-nil policy")
			require.NotEmpty(t, policy.AcceptRules, "Policy should have allowed rules")

			err := policy.Compile()
			require.NoError(t, err)

			req := &http.Request{
				Host: tt.expectedHost,
				URL:  &url.URL{Host: tt.expectedHost, Path: tt.expectedPath},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied)
			require.NotNil(t, allowed, "Request to %s%s should be allowed", tt.expectedHost, tt.expectedPath)
			assert.Equal(t, tt.policyName, allowed.Name)
		})
	}
}

func TestLLMProvidersCompleteness(t *testing.T) {
	policy := LLMProviders()
	require.NotNil(t, policy)

	// Verify that LLMProviders merges all provider policies
	expectedPolicies := []string{
		"openai",
		"anthropic",
		"google-ai",
		"cohere",
		"openrouter",
		"together",
		"anyscale",
		"replicate",
		"huggingface",
		"mistral",
		"perplexity",
		"ai21",
		"aws-bedrock",
		"azure-openai",
		"groq",
		"fireworks",
		"deepseek",
		"stability",
	}

	policyNames := make(map[string]bool)
	for _, allowed := range policy.AcceptRules {
		policyNames[allowed.Name] = true
	}

	for _, expected := range expectedPolicies {
		assert.True(t, policyNames[expected], "LLMProviders should include %s policy", expected)
	}

	// Verify total count
	assert.Equal(t, len(expectedPolicies), len(policy.AcceptRules),
		"LLMProviders should have exactly %d policies", len(expectedPolicies))
}

func TestLLMProvidersHTTPSOnly(t *testing.T) {
	// LLM APIs should only be accessed over HTTPS
	// This test verifies the policies don't explicitly allow HTTP
	policy := LLMProviders()
	require.NotNil(t, policy)

	for _, allowed := range policy.AcceptRules {
		// Verify no explicit HTTP scheme is set (should default to HTTPS)
		if allowed.Match != nil && allowed.Match.Scheme != "" {
			assert.NotEqual(t, "^http$", allowed.Match.Scheme,
				"Policy %s should not explicitly allow HTTP", allowed.Name)
		}
	}
}

func TestAWSBedrockRegionalEndpoints(t *testing.T) {
	policy := AWSBedrockProvider()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	regions := []string{
		"us-east-1",
		"us-west-2",
		"eu-west-1",
		"eu-central-1",
		"ap-southeast-1",
		"ap-northeast-1",
	}

	for _, region := range regions {
		t.Run(region, func(t *testing.T) {
			host := "bedrock-runtime." + region + ".amazonaws.com"
			path := "/model/anthropic.claude-v2/invoke"
			req := &http.Request{
				Host: host,
				URL:  &url.URL{Host: host, Path: path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied)
			require.NotNil(t, allowed, "AWS Bedrock should support region %s", region)
			assert.Equal(t, "aws-bedrock", allowed.Name)
		})
	}
}

func TestAzureOpenAICustomDeployments(t *testing.T) {
	policy := AzureOpenAIProvider()
	require.NotNil(t, policy)

	err := policy.Compile()
	require.NoError(t, err)

	deployments := []string{
		"my-company.openai.azure.com",
		"prod-gpt4.openai.azure.com",
		"dev-deployment.openai.azure.com",
		"test-123.openai.azure.com",
	}

	for _, deployment := range deployments {
		t.Run(deployment, func(t *testing.T) {
			path := "/openai/deployments/gpt-4/chat/completions"
			req := &http.Request{
				Host: deployment,
				URL:  &url.URL{Host: deployment, Path: path},
			}

			allowed, denied := policy.Find(req)
			assert.Nil(t, denied)
			require.NotNil(t, allowed, "Azure OpenAI should support custom deployment %s", deployment)
			assert.Equal(t, "azure-openai", allowed.Name)
		})
	}
}
