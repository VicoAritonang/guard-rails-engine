package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/judge"
	"go.vicoworks.com/guard-rails-engine/internal/media"
	"go.vicoworks.com/guard-rails-engine/internal/providers"
	"go.vicoworks.com/guard-rails-engine/internal/telemetry"
)

// BuildMedia constructs the model-backed attachment readers from the
// environment. A backend that cannot be built is logged and skipped: the
// ingest step then reports the affected parts as unscannable, and the policy
// decides what that means, rather than the gateway refusing to start.
func BuildMedia(cfg *config.Config, r *providers.Router, pricing *telemetry.Pricing, logger *slog.Logger) media.Backends {
	if logger == nil {
		logger = slog.Default()
	}
	var b media.Backends

	switch ocr := strings.TrimSpace(cfg.MediaOCR); {
	case ocr == "" || ocr == "off":
	case strings.HasPrefix(ocr, "http://") || strings.HasPrefix(ocr, "https://"):
		b.OCR = &media.HTTPOCR{URL: ocr, Token: cfg.MediaOCRToken}
	default:
		if r == nil {
			logger.Warn("media OCR needs the router", "route", ocr)
			break
		}
		if _, err := r.Resolve(ocr); err != nil {
			logger.Warn("media OCR route unavailable", "route", ocr, "error", err)
			break
		}
		b.OCR = &media.VisionOCR{Router: r, Route: ocr}
	}

	if t, err := buildTranscriber(cfg); err != nil {
		logger.Warn("speech-to-text unavailable", "error", err)
	} else if t != nil {
		b.Transcriber = t
	}

	for _, name := range cfg.MediaImageClassifiers {
		c, err := BuildClassifier(name, r, cfg, pricing)
		if err != nil {
			logger.Warn("image classifier unavailable", "classifier", name, "error", err)
			continue
		}
		ic, ok := c.(judge.ImageClassifier)
		if !ok {
			logger.Warn("classifier cannot judge images", "classifier", name)
			continue
		}
		if gm, ok := c.(*judge.GuardModel); ok && gm.Format != judge.FormatLlamaGuard {
			logger.Warn("classifier cannot judge images; only Llama Guard 4 and moderation are multimodal",
				"classifier", name, "format", gm.Format)
			continue
		}
		b.ImageSafety = append(b.ImageSafety, imageAdapter{ic})
	}

	logger.Info("media ingest ready",
		"ocr", backendName(b.OCR), "transcribe", backendName(b.Transcriber), "image_classifiers", len(b.ImageSafety))
	return b
}

func buildTranscriber(cfg *config.Config) (media.Transcriber, error) {
	mode := strings.TrimSpace(cfg.MediaTranscribe)
	model := cfg.MediaTranscribeModel
	switch {
	case mode == "" || mode == "off":
		return nil, nil
	case mode == "openai":
		key := firstNonEmpty(cfg.MediaTranscribeKey, cfg.OpenAIAPIKey)
		if key == "" {
			return nil, fmt.Errorf("GUARDRAILS_MEDIA_TRANSCRIBE=openai needs OPENAI_API_KEY")
		}
		base := firstNonEmpty(cfg.OpenAIBaseURL, "https://api.openai.com/v1")
		return &media.OpenAITranscriber{BaseURL: base, APIKey: key, Model: firstNonEmpty(model, "gpt-4o-mini-transcribe"), Label: "openai"}, nil
	case mode == "groq":
		key := firstNonEmpty(cfg.MediaTranscribeKey, cfg.GroqAPIKey)
		if key == "" {
			return nil, fmt.Errorf("GUARDRAILS_MEDIA_TRANSCRIBE=groq needs GROQ_API_KEY")
		}
		base := firstNonEmpty(cfg.GroqBaseURL, providers.GroqBaseURL)
		return &media.OpenAITranscriber{BaseURL: base, APIKey: key, Model: firstNonEmpty(model, "whisper-large-v3-turbo"), Label: "groq"}, nil
	case mode == "local":
		if cfg.LocalBaseURL == "" {
			return nil, fmt.Errorf("GUARDRAILS_MEDIA_TRANSCRIBE=local needs LOCAL_BASE_URL")
		}
		return &media.OpenAITranscriber{BaseURL: cfg.LocalBaseURL, APIKey: firstNonEmpty(cfg.MediaTranscribeKey, cfg.LocalAPIKey),
			Model: firstNonEmpty(model, "whisper-1"), Label: "local"}, nil
	case strings.HasPrefix(mode, "http://") || strings.HasPrefix(mode, "https://"):
		// A dedicated speech server (speaches, faster-whisper-server, LocalAI).
		return &media.OpenAITranscriber{BaseURL: mode, APIKey: cfg.MediaTranscribeKey,
			Model: firstNonEmpty(model, "Systran/faster-whisper-small"), Label: "whisper"}, nil
	}
	return nil, fmt.Errorf("GUARDRAILS_MEDIA_TRANSCRIBE %q must be off, openai, groq, local or a URL", mode)
}

// imageAdapter lets a semantic-tier classifier serve as an image classifier.
type imageAdapter struct{ c judge.ImageClassifier }

func (a imageAdapter) Name() string { return a.c.Name() }

func (a imageAdapter) ClassifyImage(ctx context.Context, data []byte, mime string) (media.ImageVerdict, error) {
	v, err := a.c.ClassifyImage(ctx, data, mime)
	return media.ImageVerdict{Unsafe: v.Unsafe, Score: v.Score, Category: v.Category, Rationale: v.Rationale, Model: v.Model}, err
}

func backendName(x interface{ Name() string }) string {
	if x == nil {
		return "none"
	}
	return x.Name()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
