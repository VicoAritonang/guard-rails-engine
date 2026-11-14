// Package media is the ingest step for everything that is not plain text:
// documents, images, audio and video, whether a user attached them or a tool
// returned them.
//
// The design is one sentence: turn every part into the text a model would
// read from it, hand that text to the guards that already exist, and report
// separately whatever has no textual form. A prompt injection inside a PDF is
// still a prompt injection, so it is caught by the injection guard, with its
// red-team suite and its threshold sweep; what this package adds is the
// extraction (PDF, Office, HTML, SVG, image metadata, OCR, speech-to-text) and
// the threats that only exist in files: macros, active content, hidden text,
// remote templates, decompression bombs, polyglots, content a moderation model
// judges unsafe as an image.
//
// Extraction is deterministic and local wherever a library makes that
// possible. OCR, transcription and image moderation need a model, and are
// pluggable backends (an OpenAI-compatible endpoint, a self-hosted sidecar, or
// nothing at all). When no backend can read a part, the part is not silently
// passed: it gets a media.unscannable or media.partial_coverage finding, and
// the policy decides whether unread content may travel.
//
// See docs/adr/0011-multimodal-ingest.md.
package media

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// GuardName is the guard that reports ingest findings on the inbound stage,
// and GuardResultName the one that reports them on the tool-result stage.
const (
	GuardName       = config.GuardMedia
	GuardResultName = config.GuardMediaResult
)

// TextReader reads the text in an image (OCR).
type TextReader interface {
	Name() string
	ReadImage(ctx context.Context, data []byte, mime string) (string, error)
}

// Transcriber turns speech in an audio or video file into text.
type Transcriber interface {
	Name() string
	Transcribe(ctx context.Context, data []byte, mime, filename string) (string, error)
}

// ImageVerdict is one image classifier's opinion.
type ImageVerdict struct {
	Unsafe    bool
	Score     float64
	Category  string
	Rationale string
	Model     string
}

// ImageClassifier judges an image's content directly (not its text): Llama
// Guard 4 and OpenAI omni-moderation both take an image as input.
type ImageClassifier interface {
	Name() string
	ClassifyImage(ctx context.Context, data []byte, mime string) (ImageVerdict, error)
}

// Backends are the model-backed readers. Every field is optional.
type Backends struct {
	OCR         TextReader
	Transcriber Transcriber
	ImageSafety []ImageClassifier
	// HTTPClient fetches remote parts when fetch_remote is on. Nil builds a
	// client that refuses private, loopback and link-local addresses.
	HTTPClient *http.Client
}

// Options are the limits and forwarding rules, read from the media guard's
// policy params.
type Options struct {
	MaxParts          int
	MaxPartBytes      int
	MaxTotalBytes     int
	MaxPixels         int64
	MaxChars          int
	MaxAudioSeconds   float64
	MaxArchiveEntries int
	MaxUncompressed   int64
	MaxCompression    float64
	MaxPDFImages      int
	Timeout           time.Duration
	Concurrency       int

	FetchRemote     bool
	FetchAllowHosts []string
	FetchAllowHTTP  bool

	// Forward is native | text. "text" never sends the original bytes
	// upstream, only the extracted text: the strictest posture, and the one
	// that makes a text-only model usable on attachments.
	Forward string
	// BinaryRedaction decides what happens to a part whose extracted text a
	// guard redacted: replace_with_text (send the redacted text instead of
	// the file), block, or keep (send the original anyway; the redaction then
	// only protects logs and classifiers).
	BinaryRedaction string
	// OCRDocuments runs OCR on images embedded in a PDF that has almost no
	// text layer, which is what a scanned document looks like.
	OCRDocuments bool
}

// OptionsFromPolicy reads Options from the media guard config.
func OptionsFromPolicy(g *config.GuardConfig) (Options, error) {
	o := Options{
		MaxParts:          g.Int("max_parts", 16),
		MaxPartBytes:      g.Int("max_part_bytes", 25<<20),
		MaxTotalBytes:     g.Int("max_total_bytes", 64<<20),
		MaxPixels:         int64(g.Int("max_pixels", 50_000_000)),
		MaxChars:          g.Int("max_extract_chars", 200_000),
		MaxAudioSeconds:   g.Float("max_audio_seconds", 1800),
		MaxArchiveEntries: g.Int("max_archive_entries", 5000),
		MaxUncompressed:   int64(g.Int("max_uncompressed_bytes", 200<<20)),
		MaxCompression:    g.Float("max_compression_ratio", 150),
		MaxPDFImages:      g.Int("max_pdf_ocr_images", 8),
		Timeout:           time.Duration(g.Int("extract_timeout_seconds", 60)) * time.Second,
		Concurrency:       g.Int("concurrency", 4),
		FetchRemote:       g.Bool("fetch_remote", false),
		FetchAllowHosts:   g.Strings("fetch_allow_hosts"),
		FetchAllowHTTP:    g.Bool("fetch_allow_http", false),
		Forward:           g.String("forward", "native"),
		BinaryRedaction:   g.String("binary_redaction", "replace_with_text"),
		OCRDocuments:      g.Bool("ocr_scanned_documents", true),
	}
	switch o.Forward {
	case "native", "text":
	default:
		return o, fmt.Errorf("media: forward %q must be native|text", o.Forward)
	}
	switch o.BinaryRedaction {
	case "replace_with_text", "block", "keep":
	default:
		return o, fmt.Errorf("media: binary_redaction %q must be replace_with_text|block|keep", o.BinaryRedaction)
	}
	if o.MaxParts <= 0 || o.MaxPartBytes <= 0 || o.MaxChars <= 0 {
		return o, errors.New("media: max_parts, max_part_bytes and max_extract_chars must be positive")
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 1
	}
	return o, nil
}

// Processor implements core.Ingestor.
type Processor struct {
	opts Options
	b    Backends
}

// New builds a Processor.
func New(opts Options, b Backends) *Processor {
	if b.HTTPClient == nil {
		b.HTTPClient = safeHTTPClient(30 * time.Second)
	}
	return &Processor{opts: opts, b: b}
}

// Capabilities describes what this processor can read, for /v1/media and the
// startup log.
func (p *Processor) Capabilities() map[string]any {
	names := func(cs []ImageClassifier) []string {
		out := make([]string, 0, len(cs))
		for _, c := range cs {
			out = append(out, c.Name())
		}
		return out
	}
	caps := map[string]any{
		"documents":        []string{"pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "html", "svg", "txt", "md", "csv", "json", "xml", "rtf"},
		"images":           []string{"png", "jpeg", "gif", "webp", "bmp", "svg"},
		"audio":            []string{"wav", "mp3", "ogg", "flac", "m4a", "webm"},
		"video":            []string{"mp4", "webm", "mov"},
		"forward":          p.opts.Forward,
		"binary_redaction": p.opts.BinaryRedaction,
		"fetch_remote":     p.opts.FetchRemote,
		"image_safety":     names(p.b.ImageSafety),
	}
	if p.b.OCR != nil {
		caps["ocr"] = p.b.OCR.Name()
	} else {
		caps["ocr"] = "none: image pixels are not read"
	}
	if p.b.Transcriber != nil {
		caps["transcribe"] = p.b.Transcriber.Name()
	} else {
		caps["transcribe"] = "none: audio and video are not read"
	}
	return caps
}

// Prepare extracts every unprocessed part in the transaction.
func (p *Processor) Prepare(ctx context.Context, tx *core.Transaction) error {
	refs := tx.Parts()
	if len(refs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()

	var (
		wg    sync.WaitGroup
		sem   = make(chan struct{}, p.opts.Concurrency)
		total int
		count int
	)
	for _, ref := range refs {
		if ref.Part.Extraction != nil {
			continue // already processed by an earlier stage or call
		}
		count++
		total += len(ref.Part.Data)
		if count > p.opts.MaxParts {
			ext := &core.Extraction{Coverage: core.CoverageNone}
			ext.Findings = append(ext.Findings, finding(ref, "too_many_parts", "media.size_limit", core.SeverityHigh,
				fmt.Sprintf("request carries more than %d attachments; %s was not inspected", p.opts.MaxParts, ref.Part.Label())))
			ref.Part.Extraction = ext
			continue
		}
		if p.opts.MaxTotalBytes > 0 && total > p.opts.MaxTotalBytes {
			ext := &core.Extraction{Coverage: core.CoverageNone, Bytes: len(ref.Part.Data)}
			ext.Findings = append(ext.Findings, finding(ref, "total_bytes", "media.size_limit", core.SeverityHigh,
				fmt.Sprintf("attachments exceed %d bytes in total; %s was not inspected", p.opts.MaxTotalBytes, ref.Part.Label())))
			ref.Part.Extraction = ext
			continue
		}
		wg.Add(1)
		go func(ref core.PartRef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p.process(ctx, ref)
		}(ref)
	}
	wg.Wait()
	return nil
}

// process handles one part and never panics: file parsers meet hostile input
// by definition, and one malformed PDF must not take down the gateway.
func (p *Processor) process(ctx context.Context, ref core.PartRef) {
	start := time.Now()
	part := ref.Part
	ext := &core.Extraction{Coverage: core.CoverageNone}
	defer func() {
		if r := recover(); r != nil {
			ext.Coverage = core.CoverageNone
			ext.Findings = append(ext.Findings, finding(ref, "parser_panic", "media.unscannable", core.SeverityMedium,
				fmt.Sprintf("%s could not be parsed (malformed input): %v", part.Label(), r)))
		}
		p.finish(ref, ext, start)
	}()

	if part.Type == core.ModalityText || (part.Type == "" && len(part.Data) == 0 && part.URL == "" && part.Text != "") {
		part.Type = core.ModalityText
		ext.Coverage = core.CoverageFull
		ext.AddMethod("text")
		return
	}

	if err := p.load(ctx, ref, ext); err != nil {
		ext.Findings = append(ext.Findings, finding(ref, "unavailable", "media.unscannable", core.SeverityMedium,
			fmt.Sprintf("%s was not inspected: %v", part.Label(), err)))
		return
	}
	ext.Bytes = len(part.Data)
	if len(part.Data) > p.opts.MaxPartBytes {
		ext.Findings = append(ext.Findings, finding(ref, "part_bytes", "media.size_limit", core.SeverityHigh,
			fmt.Sprintf("%s is %d bytes, limit is %d", part.Label(), len(part.Data), p.opts.MaxPartBytes)))
		return
	}

	kind := sniff(part.Data, part.MIME, part.Name)
	if mismatch(part.MIME, part.Name, kind) {
		f := finding(ref, "mime_mismatch", "media.mime_mismatch", core.SeverityMedium,
			fmt.Sprintf("%s is declared as %q but its bytes are %s", part.Label(), declared(part), kind.mime))
		ext.Findings = append(ext.Findings, f)
	}
	if part.MIME == "" || mismatchFamily(part.MIME, kind) {
		part.MIME = kind.mime
	}
	if part.Type == "" || !part.Type.Valid() {
		part.Type = kind.modality
	}

	r := &reader{p: p, ref: ref, ext: ext}
	switch kind.modality {
	case core.ModalityDocument:
		r.document(ctx, kind)
	case core.ModalityImage:
		r.image(ctx, kind)
	case core.ModalityAudio:
		r.audio(ctx, kind)
	case core.ModalityVideo:
		r.video(ctx, kind)
	default:
		ext.Findings = append(ext.Findings, finding(ref, "unknown_format", "media.unscannable", core.SeverityMedium,
			fmt.Sprintf("%s has a format the gateway cannot read (%s)", part.Label(), kind.mime)))
	}
	part.Text = r.text()
}

// finish truncates, fingerprints and attaches the extraction report.
func (p *Processor) finish(ref core.PartRef, ext *core.Extraction, start time.Time) {
	part := ref.Part
	if !utf8.ValidString(part.Text) {
		part.Text = strings.ToValidUTF8(part.Text, "�")
	}
	if len(part.Text) > p.opts.MaxChars {
		cut := p.opts.MaxChars
		for cut > 0 && !utf8.RuneStart(part.Text[cut]) {
			cut--
		}
		part.Text = part.Text[:cut]
		ext.Truncated = true
		ext.Findings = append(ext.Findings, finding(ref, "truncated", "media.truncated", core.SeverityLow,
			fmt.Sprintf("only the first %d characters of %s were inspected", p.opts.MaxChars, part.Label())))
		if ext.Coverage == core.CoverageFull {
			ext.Coverage = core.CoveragePartial
		}
	}
	ext.Chars = len(part.Text)
	ext.TextSHA256 = core.TextDigest(part.Text)
	ext.DurationMS = time.Since(start).Milliseconds()
	part.Extraction = ext
}

// load resolves the part's bytes from a data: URI or, if the policy allows,
// a remote URL. A fetched part is then forwarded inline, never by URL: the
// upstream fetching it a second time would let the server swap the content
// between inspection and use.
func (p *Processor) load(ctx context.Context, ref core.PartRef, ext *core.Extraction) error {
	part := ref.Part
	if len(part.Data) > 0 {
		return nil
	}
	if part.URL == "" {
		if part.Text != "" {
			return nil
		}
		return errors.New("the part has neither data nor a URL")
	}
	if strings.HasPrefix(part.URL, "data:") {
		mime, data, err := DecodeDataURI(part.URL)
		if err != nil {
			return err
		}
		part.Data = data
		if part.MIME == "" {
			part.MIME = mime
		}
		part.URL = ""
		return nil
	}
	if !p.opts.FetchRemote {
		return errors.New("remote URLs are not fetched (media.fetch_remote is off); send the content inline")
	}
	data, mime, err := p.fetch(ctx, part.URL)
	if err != nil {
		return err
	}
	ext.AddMethod("fetch")
	part.Data = data
	if part.MIME == "" {
		part.MIME = mime
	}
	part.URL = ""
	return nil
}

// DecodeDataURI parses data:[<mime>][;base64],<payload>.
func DecodeDataURI(uri string) (string, []byte, error) {
	rest, ok := strings.CutPrefix(uri, "data:")
	if !ok {
		return "", nil, errors.New("not a data: URI")
	}
	meta, payload, ok := strings.Cut(rest, ",")
	if !ok {
		return "", nil, errors.New("malformed data: URI")
	}
	mime := meta
	isB64 := false
	if i := strings.Index(meta, ";"); i >= 0 {
		mime = meta[:i]
		isB64 = strings.Contains(meta[i:], ";base64")
	}
	if !isB64 {
		return mime, []byte(payload), nil
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(payload, "="))
	}
	if err != nil {
		return "", nil, fmt.Errorf("data: URI is not valid base64: %w", err)
	}
	return mime, data, nil
}

// Finalize decides what of each part travels onward.
func (p *Processor) Finalize(tx *core.Transaction, d *core.Decision) {
	for _, ref := range p.scope(tx, d.Stage) {
		part := ref.Part
		ext := part.Extraction
		if ext == nil || part.Type == core.ModalityText {
			continue
		}
		if ext.Forwarded == "dropped" {
			continue
		}
		modified := part.Modified()
		switch {
		case p.opts.Forward == "text":
			*part = part.AsText()
		case modified && p.opts.BinaryRedaction == "replace_with_text":
			*part = part.AsText()
		case modified && p.opts.BinaryRedaction == "block":
			f := finding(ref, "redaction_unenforceable", "media.redaction_unenforceable", core.SeverityHigh,
				fmt.Sprintf("a guard redacted text inside %s, and the original file cannot be redacted in place", part.Label()))
			f.Guard = guardFor(d.Stage)
			d.Findings = append(d.Findings, f)
			d.Action = d.Action.Escalate(core.ActionBlock)
			ext.Forwarded = "dropped"
		default:
			ext.Forwarded = "native"
			if modified {
				ext.Warnings = append(ext.Warnings, "the original bytes were forwarded although the extracted text was redacted (binary_redaction: keep)")
			}
		}
	}
}

// scope returns the parts a stage owns: message parts on inbound, tool
// result parts on the tool-result stage.
func (p *Processor) scope(tx *core.Transaction, stage core.Stage) []core.PartRef {
	var out []core.PartRef
	for _, ref := range tx.Parts() {
		isResult := strings.HasPrefix(ref.Field, "tool_results[")
		if (stage == core.StageToolResult) == isResult {
			out = append(out, ref)
		}
	}
	return out
}

func guardFor(stage core.Stage) string {
	if stage == core.StageToolResult {
		return GuardResultName
	}
	return GuardName
}

// finding builds a media finding anchored on the part's text field.
func finding(ref core.PartRef, rule, category string, sev core.Severity, msg string) core.Finding {
	guard := GuardName
	if strings.HasPrefix(ref.Field, "tool_results[") {
		guard = GuardResultName
	}
	f := core.NewFinding(guard, rule, category, sev, 1.0, msg)
	f.Spans = []core.Span{{Field: ref.Field}}
	f.Meta = map[string]string{"part": ref.Part.Label()}
	if ref.Part.MIME != "" {
		f.Meta["mime"] = ref.Part.MIME
	}
	return f
}
