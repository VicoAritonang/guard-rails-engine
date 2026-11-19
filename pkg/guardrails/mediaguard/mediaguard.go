// Package mediaguard is the attachment module of the embeddable engine. It
// turns every part (PDF, Office, ODF, HTML, SVG, RTF, images, audio) into the
// text the other guards read, and reports what only exists in files: macros,
// active content, hidden text, decompression bombs, unreadable content.
//
//	g, err := engine.New(engine.Options{}, textguard.Module(), mediaguard.Module(mediaguard.Backends{}))
//	res, err := g.ScanFile(ctx, "contract.pdf", data)
//
// Documents and image metadata are read with no setup. Pixels and speech
// need a backend (see Backends); without one the part is reported as
// media.partial_coverage or media.unscannable and the policy decides.
//
// This is the heaviest module: it links net/http and the PDF and HTML
// parsers. An engine without it refuses attachments with engine.ErrNotLoaded
// rather than passing them unread.
package mediaguard

import (
	"context"

	"go.vicoworks.com/guard-rails/internal/media"
	"go.vicoworks.com/guard-rails/pkg/guardrails/engine"
)

type (
	// Backends are the optional model-backed readers for attachments.
	Backends = media.Backends
	// TextReader reads the text in an image (OCR).
	TextReader = media.TextReader
	// Transcriber turns speech into text.
	Transcriber = media.Transcriber
	// ImageClassifier judges an image's content directly.
	ImageClassifier = media.ImageClassifier
	// ImageVerdict is an image classifier's answer.
	ImageVerdict = media.ImageVerdict
)

// Module returns the ingest step and the media and media_result guards that
// report its findings. Every field of b is optional.
func Module(b Backends) engine.Module { return media.Module(b) }

// OCRFunc adapts a function to TextReader, so any OCR library or service can
// be plugged in without a wrapper type:
//
//	mediaguard.Module(mediaguard.Backends{OCR: mediaguard.OCRFunc("tesseract", myOCR)})
func OCRFunc(name string, fn func(ctx context.Context, data []byte, mime string) (string, error)) TextReader {
	return ocrFunc{name, fn}
}

type ocrFunc struct {
	name string
	fn   func(context.Context, []byte, string) (string, error)
}

func (o ocrFunc) Name() string { return o.name }
func (o ocrFunc) ReadImage(ctx context.Context, data []byte, mime string) (string, error) {
	return o.fn(ctx, data, mime)
}

// TranscribeFunc adapts a function to Transcriber.
func TranscribeFunc(name string, fn func(ctx context.Context, data []byte, mime, filename string) (string, error)) Transcriber {
	return transcribeFunc{name, fn}
}

type transcribeFunc struct {
	name string
	fn   func(context.Context, []byte, string, string) (string, error)
}

func (t transcribeFunc) Name() string { return t.name }
func (t transcribeFunc) Transcribe(ctx context.Context, data []byte, mime, filename string) (string, error) {
	return t.fn(ctx, data, mime, filename)
}

// NewOpenAITranscriber returns a Transcriber for any OpenAI-compatible
// /audio/transcriptions endpoint: OpenAI, Groq, LocalAI, speaches,
// faster-whisper-server.
func NewOpenAITranscriber(baseURL, apiKey, model string) Transcriber {
	return &media.OpenAITranscriber{BaseURL: baseURL, APIKey: apiKey, Model: model}
}

// NewHTTPOCR returns a TextReader that posts images to an OCR sidecar and
// reads back {"text": ...} or text/plain.
func NewHTTPOCR(url, token string) TextReader { return &media.HTTPOCR{URL: url, Token: token} }
