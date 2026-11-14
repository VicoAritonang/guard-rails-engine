package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Modality names the kind of content a Part carries.
//
// The guards read text. Everything that is not text -- a PDF, a screenshot, a
// voice note -- reaches them as the text the ingest step extracted from it,
// plus whatever the ingest step found that has no textual form at all (a macro,
// a decompression bomb, an image a moderation model judged unsafe). That keeps
// one detector per threat instead of one detector per threat per file format.
type Modality string

const (
	ModalityText     Modality = "text"
	ModalityImage    Modality = "image"
	ModalityAudio    Modality = "audio"
	ModalityVideo    Modality = "video"
	ModalityDocument Modality = "document"
)

// Valid reports whether m is a known modality.
func (m Modality) Valid() bool {
	switch m {
	case ModalityText, ModalityImage, ModalityAudio, ModalityVideo, ModalityDocument:
		return true
	}
	return false
}

// Part is one non-text (or attached-text) item of a message or tool result.
//
// Data travels as base64 in JSON, which is what encoding/json does for []byte.
// A Part can instead carry a URL; whether the gateway fetches it is a policy
// decision (media.fetch_remote), because fetching an attacker-chosen URL from
// inside the trust boundary is a server-side request forgery primitive.
type Part struct {
	Type Modality `json:"type"`
	MIME string   `json:"mime,omitempty"`
	Name string   `json:"name,omitempty"`
	Data []byte   `json:"data,omitempty"`
	URL  string   `json:"url,omitempty"`
	// Format is the audio container for providers that need it ("wav", "mp3").
	Format string `json:"format,omitempty"`
	// Detail is the OpenAI image detail hint, forwarded untouched.
	Detail string `json:"detail,omitempty"`

	// Text is what the guards scan: the extracted text of a document, the OCR
	// of an image, the transcript of a recording. For a text part it is the
	// text itself. Redaction rewrites this field, never Data.
	Text string `json:"text,omitempty"`

	// Extraction reports how Text was obtained and what the ingest step found.
	// It is nil until the part has been processed, which is how a part that
	// went through two stages is extracted only once.
	Extraction *Extraction `json:"extraction,omitempty"`
}

// Coverage says how much of a part the guards actually saw.
type Coverage string

const (
	// CoverageFull: every byte that can carry meaning was turned into text.
	CoverageFull Coverage = "full"
	// CoveragePartial: some of it was (e.g. image metadata but no OCR, a video's
	// audio track but not its frames).
	CoveragePartial Coverage = "partial"
	// CoverageNone: nothing in the part was inspected.
	CoverageNone Coverage = "none"
)

// Extraction is the ingest step's report on one part.
type Extraction struct {
	Methods    []string  `json:"methods,omitempty"` // "pdf", "docx", "ocr:vision", "transcribe", "metadata", ...
	Coverage   Coverage  `json:"coverage"`
	Bytes      int       `json:"bytes,omitempty"`
	Chars      int       `json:"chars,omitempty"`
	Pages      int       `json:"pages,omitempty"`
	Width      int       `json:"width,omitempty"`
	Height     int       `json:"height,omitempty"`
	Seconds    float64   `json:"seconds,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	Findings   []Finding `json:"findings,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`

	// TextSHA256 fingerprints Text as extracted. When the pipeline later
	// rewrites Text (a redaction), the fingerprint no longer matches and the
	// finalize step knows the original bytes now contain something the policy
	// removed from the text view -- and must not be forwarded as they are.
	TextSHA256 string `json:"text_sha256,omitempty"`

	// Forwarded records what went upstream: native | text | dropped.
	Forwarded string `json:"forwarded,omitempty"`
}

// AddMethod records an extraction method once.
func (e *Extraction) AddMethod(m string) {
	for _, x := range e.Methods {
		if x == m {
			return
		}
	}
	e.Methods = append(e.Methods, m)
}

// TextDigest returns the SHA-256 of s, hex encoded.
func TextDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Modified reports whether the part's text no longer matches what was
// extracted, i.e. a guard redacted it.
func (p *Part) Modified() bool {
	return p.Extraction != nil && p.Extraction.TextSHA256 != "" && TextDigest(p.Text) != p.Extraction.TextSHA256
}

// DataURI renders the part's bytes as a data: URI, the form every
// OpenAI-compatible API accepts for inline images and files.
func (p *Part) DataURI() string {
	mime := p.MIME
	if mime == "" {
		mime = "application/octet-stream"
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(p.Data)
}

// Label is a short human description: "invoice.pdf (document)".
func (p *Part) Label() string {
	name := p.Name
	if name == "" {
		name = "attachment"
	}
	return fmt.Sprintf("%s (%s)", name, p.Type)
}

// AsText converts the part into a text part carrying its extracted text, the
// form used when the upstream cannot take the original modality or when the
// policy forbids forwarding the original bytes.
func (p Part) AsText() Part {
	body := p.Text
	if strings.TrimSpace(body) == "" {
		body = "[no text could be extracted]"
	}
	out := Part{Type: ModalityText, Name: p.Name, Text: "[" + p.Label() + "]\n" + body, Extraction: p.Extraction}
	if out.Extraction != nil {
		out.Extraction.Forwarded = "text"
	}
	return out
}

// RestrictParts returns a copy of msgs in which every part whose modality is
// not in allowed is replaced by its extracted text. The router applies it per
// route, so a text-only fallback model still gets a usable request instead of
// a 400, and the caller's slice is never modified.
func RestrictParts(msgs []Message, allowed []string) []Message {
	if len(allowed) == 0 {
		return msgs
	}
	ok := map[Modality]bool{ModalityText: true}
	for _, a := range allowed {
		ok[Modality(strings.ToLower(strings.TrimSpace(a)))] = true
	}
	out := make([]Message, len(msgs))
	for i, m := range msgs {
		out[i] = m
		if len(m.Parts) == 0 {
			continue
		}
		parts := make([]Part, len(m.Parts))
		for j, p := range m.Parts {
			if ok[p.Type] {
				parts[j] = p
				continue
			}
			parts[j] = p.AsText()
		}
		out[i].Parts = parts
	}
	return out
}

// HasParts reports whether any message or tool result carries parts.
func (t *Transaction) HasParts() bool {
	for _, m := range t.Messages {
		if len(m.Parts) > 0 {
			return true
		}
	}
	for _, r := range t.ToolResults {
		if len(r.Parts) > 0 {
			return true
		}
	}
	return false
}

// PartRef addresses one part in a transaction.
type PartRef struct {
	Field string // the scan-field reference of the part's text
	Part  *Part
	Role  Role
	// Origin is set for tool-result parts.
	Origin Origin
}

// Parts lists every part in the transaction with its field reference. The
// pointers alias the transaction, so writes through them are visible to the
// pipeline.
func (t *Transaction) Parts() []PartRef {
	var out []PartRef
	for i := range t.Messages {
		for j := range t.Messages[i].Parts {
			out = append(out, PartRef{Field: msgPartField(i, j), Part: &t.Messages[i].Parts[j], Role: t.Messages[i].Role})
		}
	}
	for i := range t.ToolResults {
		for j := range t.ToolResults[i].Parts {
			out = append(out, PartRef{Field: resultPartField(i, j), Part: &t.ToolResults[i].Parts[j],
				Role: RoleTool, Origin: t.ToolResults[i].Origin})
		}
	}
	return out
}

func msgPartField(i, j int) string    { return fmt.Sprintf("messages[%d].parts[%d].text", i, j) }
func resultPartField(i, j int) string { return fmt.Sprintf("tool_results[%d].parts[%d].text", i, j) }

// parsePartRef decodes "messages[i].parts[j].text" or the tool_results form.
func parsePartRef(ref string) (kind string, i, j int, ok bool) {
	for _, k := range []string{"messages", "tool_results"} {
		prefix := k + "["
		if !strings.HasPrefix(ref, prefix) || !strings.HasSuffix(ref, "].text") {
			continue
		}
		body := strings.TrimSuffix(strings.TrimPrefix(ref, prefix), "].text")
		a, b, found := strings.Cut(body, "].parts[")
		if !found {
			return "", 0, 0, false
		}
		ia, okA := atoi(a)
		ib, okB := atoi(b)
		if !okA || !okB {
			return "", 0, 0, false
		}
		return k, ia, ib, true
	}
	return "", 0, 0, false
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func (t *Transaction) partAt(ref string) (*Part, bool) {
	kind, i, j, ok := parsePartRef(ref)
	if !ok {
		return nil, false
	}
	switch kind {
	case "messages":
		if i < len(t.Messages) && j < len(t.Messages[i].Parts) {
			return &t.Messages[i].Parts[j], true
		}
	case "tool_results":
		if i < len(t.ToolResults) && j < len(t.ToolResults[i].Parts) {
			return &t.ToolResults[i].Parts[j], true
		}
	}
	return nil, false
}

// Ingestor turns non-text parts into scannable text before a stage runs, and
// decides after the stage what of each part may travel onward.
//
// It lives behind an interface so core stays free of file-format parsers and
// network clients; internal/media implements it.
type Ingestor interface {
	// Prepare extracts every unprocessed part. It must be idempotent: a part
	// whose Extraction is already set is left alone.
	Prepare(ctx context.Context, tx *Transaction) error
	// Finalize applies the forwarding policy to each part once the stage has
	// decided, possibly escalating the decision.
	Finalize(tx *Transaction, d *Decision)
}

// WithIngestor makes the pipeline run an ingest step before its guards.
func WithIngestor(in Ingestor) PipelineOption {
	return func(p *Pipeline) {
		if in != nil {
			p.ingestor = in
		}
	}
}
