package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// OpenAIEmbedder backs the semantic cache. It satisfies cache.Embedder.
type OpenAIEmbedder struct {
	client openai.Client
	model  string
}

// DefaultEmbeddingModel is the cheapest OpenAI embedding model. A cache lookup
// is paid on every miss, so the embedding has to cost a small fraction of the
// completion it might save -- at $0.02/MTok it is roughly 1% of a small chat
// model's input rate.
const DefaultEmbeddingModel = "text-embedding-3-small"

func NewOpenAIEmbedder(apiKey, model string) (*OpenAIEmbedder, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("%w: embeddings need OPENAI_API_KEY", ErrNotConfigured)
	}
	if model == "" {
		model = DefaultEmbeddingModel
	}
	return &OpenAIEmbedder{
		client: openai.NewClient(option.WithAPIKey(apiKey), option.WithMaxRetries(2)),
		model:  model,
	}, nil
}

func (e *OpenAIEmbedder) Model() string { return e.model }

func (e *OpenAIEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, int, error) {
	if len(texts) == 0 {
		return nil, 0, nil
	}
	resp, err := e.client.Embeddings.New(ctx, openai.EmbeddingNewParams{
		Model: openai.EmbeddingModel(e.model),
		Input: openai.EmbeddingNewParamsInputUnion{OfArrayOfStrings: texts},
	})
	if err != nil {
		return nil, 0, classifyOpenAIError(err)
	}
	if len(resp.Data) != len(texts) {
		return nil, 0, errors.New("embeddings: response size mismatch")
	}
	out := make([][]float32, len(texts))
	for _, d := range resp.Data {
		v := make([]float32, len(d.Embedding))
		for i, x := range d.Embedding {
			v[i] = float32(x)
		}
		if int(d.Index) < len(out) {
			out[d.Index] = v
		}
	}
	return out, int(resp.Usage.PromptTokens), nil
}

// Moderation is OpenAI's free content-moderation endpoint, used as one of the
// semantic-tier classifiers and as a baseline in the detector experiment.
type Moderation struct {
	client openai.Client
	model  string
}

func NewModeration(apiKey string) (*Moderation, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("%w: moderation needs OPENAI_API_KEY", ErrNotConfigured)
	}
	return &Moderation{
		client: openai.NewClient(option.WithAPIKey(apiKey), option.WithMaxRetries(3)),
		model:  "omni-moderation-latest",
	}, nil
}

// ModerationResult is the projection of one moderation verdict.
type ModerationResult struct {
	Flagged    bool
	TopLabel   string
	TopScore   float64
	Categories []string
}

func (m *Moderation) Moderate(ctx context.Context, text string) (*ModerationResult, error) {
	resp, err := m.client.Moderations.New(ctx, openai.ModerationNewParams{
		Model: openai.ModerationModel(m.model),
		Input: openai.ModerationNewParamsInputUnion{OfString: openai.String(text)},
	})
	if err != nil {
		return nil, classifyOpenAIError(err)
	}
	if len(resp.Results) == 0 {
		return nil, errors.New("moderation: empty result")
	}
	r := resp.Results[0]
	out := &ModerationResult{Flagged: r.Flagged}

	// The SDK models categories as a struct; walking its JSON form keeps this
	// independent of which categories a given SDK version knows about.
	scores := map[string]float64{}
	if raw := r.CategoryScores.RawJSON(); raw != "" {
		_ = json.Unmarshal([]byte(raw), &scores)
	}
	flags := map[string]bool{}
	if raw := r.Categories.RawJSON(); raw != "" {
		_ = json.Unmarshal([]byte(raw), &flags)
	}
	for k, v := range scores {
		if v > out.TopScore {
			out.TopLabel, out.TopScore = k, v
		}
	}
	for k, v := range flags {
		if v {
			out.Categories = append(out.Categories, k)
		}
	}
	return out, nil
}
