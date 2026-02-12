package defaults

import "github.com/Rudd3r/r0mp/pkg/domain"

var (
	OpenAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "openai",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.openai.com$",
						Path: "^/v1/(chat/completions|completions|embeddings|models|images/generations|images/edits|images/variations|audio/transcriptions|audio/translations|audio/speech|files|fine_tuning/.*|batches.*|moderations)$",
					},
				},
			},
		}
	}
	AnthropicProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "anthropic",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.anthropic.com$",
						Path: "^/v1/(messages|messages/count_tokens|complete)$",
					},
				},
			},
		}
	}
	GoogleAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "google-ai",
					Match: &domain.ProxyPolicyMatch{
						Host: "^(generativelanguage.googleapis.com|ai.google.dev)$",
						Path: "^/(v1beta|v1)/.*:(generateContent|streamGenerateContent|countTokens|embedContent|batchEmbedContents)$",
					},
				},
			},
		}
	}
	CohereProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "cohere",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.cohere.(ai|com)$",
						Path: "^/(v1|v2)/(chat|generate|embed|rerank|classify|tokenize|detokenize|models)$",
					},
				},
			},
		}
	}
	OpenRouterProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "openrouter",
					Match: &domain.ProxyPolicyMatch{
						Host: "^openrouter.ai$",
						Path: "^/api/v1/(chat/completions|generation|models.*)$",
					},
				},
			},
		}
	}
	TogetherAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "together",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.together.xyz$",
						Path: "^/(v1|inference)/(chat/completions|completions|embeddings|models|images/generations)$",
					},
				},
			},
		}
	}
	AnyscaleProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "anyscale",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.endpoints.anyscale.com$",
						Path: "^/v1/(chat/completions|completions|embeddings|models)$",
					},
				},
			},
		}
	}
	ReplicateProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "replicate",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.replicate.com$",
						Path: "^/v1/(predictions|models/.*/(predictions|versions)|trainings|deployments/.*/predictions)$",
					},
				},
			},
		}
	}
	HuggingFaceProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "huggingface",
					Match: &domain.ProxyPolicyMatch{
						Host: "^(api-inference.huggingface.co|huggingface.co)$",
						Path: "^/(models/.*|api/models/.*|v1/chat/completions|v1/completions)$",
					},
				},
			},
		}
	}
	MistralAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "mistral",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.mistral.ai$",
						Path: "^/v1/(chat/completions|completions|embeddings|models|fim/completions)$",
					},
				},
			},
		}
	}
	PerplexityProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "perplexity",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.perplexity.ai$",
						Path: "^/(chat/completions|search)$",
					},
				},
			},
		}
	}
	AI21Provider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "ai21",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.ai21.com$",
						Path: "^/studio/v1/(chat/completions|complete|answer|summarize|paraphrase|gec|improvements|segmentation|library/.*)$",
					},
				},
			},
		}
	}
	AWSBedrockProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "aws-bedrock",
					Match: &domain.ProxyPolicyMatch{
						Host: "^bedrock-runtime.[a-z0-9-]+.amazonaws.com$",
						Path: "^/(model/.*/invoke.*|model/.*/converse.*|agent.*|knowledge-base.*)$",
					},
				},
			},
		}
	}
	AzureOpenAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "azure-openai",
					Match: &domain.ProxyPolicyMatch{
						Host: "^[a-z0-9-]+.openai.azure.com$",
						Path: "^/openai/deployments/.*/(chat/completions|completions|embeddings|images/generations|audio/.*)$",
					},
				},
			},
		}
	}
	GroqProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "groq",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.groq.com$",
						Path: "^/openai/v1/(chat/completions|completions|models|audio/.*|responses/.*)$",
					},
				},
			},
		}
	}
	FireworksAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "fireworks",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.fireworks.ai$",
						Path: "^/inference/v1/(chat/completions|completions|embeddings|images/generations|responses/.*)$",
					},
				},
			},
		}
	}
	DeepSeekProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "deepseek",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.deepseek.com$",
						Path: "^/v1/(chat/completions|completions|models)$",
					},
				},
			},
		}
	}
	StabilityAIProvider = func() *domain.ProxyPolicy {
		return &domain.ProxyPolicy{
			AcceptRules: []*domain.ProxyPolicyAcceptRule{
				{
					Name: "stability",
					Match: &domain.ProxyPolicyMatch{
						Host: "^api.stability.ai$",
						Path: "^/v(1|2beta)/(generation/.*|stable-image/.*|user/.*|engines/.*)$",
					},
				},
			},
		}
	}
	LLMProviders = func() *domain.ProxyPolicy {
		return (&domain.ProxyPolicy{}).
			Merge(OpenAIProvider()).
			Merge(AnthropicProvider()).
			Merge(GoogleAIProvider()).
			Merge(CohereProvider()).
			Merge(OpenRouterProvider()).
			Merge(TogetherAIProvider()).
			Merge(AnyscaleProvider()).
			Merge(ReplicateProvider()).
			Merge(HuggingFaceProvider()).
			Merge(MistralAIProvider()).
			Merge(PerplexityProvider()).
			Merge(AI21Provider()).
			Merge(AWSBedrockProvider()).
			Merge(AzureOpenAIProvider()).
			Merge(GroqProvider()).
			Merge(FireworksAIProvider()).
			Merge(DeepSeekProvider()).
			Merge(StabilityAIProvider())
	}
)
