package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/providers"
	"go.vicoworks.com/guard-rails-engine/internal/telemetry"
	"go.vicoworks.com/guard-rails-engine/internal/tokenize"
)

// StageAware is implemented by classifiers that only make sense on some
// stages. Prompt Guard scores attacks, not answers, so running it on an
// outbound completion is a cost with no signal; a tool-alignment policy only
// has meaning at the runtime stage.
type StageAware interface {
	Supports(stage core.Stage) bool
}

// Supports reports whether c should run on stage.
func Supports(c Classifier, stage core.Stage) bool {
	if s, ok := c.(StageAware); ok {
		return s.Supports(stage)
	}
	return true
}

// Guard-model output formats. Each open-weight safety model answers in its
// own dialect; the format names the parser, and the model is reached through
// the ordinary router, so it can be hosted on Groq, vLLM, Ollama, TGI, NIM or
// anything else that speaks the OpenAI chat API.
const (
	FormatLlamaGuard      = "llama_guard"      // Llama Guard 3 / 4: "safe" | "unsafe\nS1,S10"
	FormatQwen3Guard      = "qwen3guard"       // Qwen3Guard-Gen: "Safety: Unsafe\nCategories: Violent"
	FormatGraniteGuardian = "granite_guardian" // Granite Guardian 3.x: "Yes" | "No" (risk named in the system turn)
	FormatNemotron        = "nemotron"         // Nemotron / Aegis content safety: {"User Safety": "unsafe", ...}
	FormatPolicy          = "policy"           // gpt-oss-safeguard or any chat model: the JSON policy judge
	FormatPromptGuard     = "prompt_guard"     // Llama Prompt Guard 2: a bare probability
)

// DetectFormat guesses a guard-model format from an upstream model id, so a
// catalog entry only needs `guard:` when the id is unusual.
func DetectFormat(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "prompt-guard"), strings.Contains(m, "promptguard"):
		return FormatPromptGuard
	case strings.Contains(m, "llama-guard"), strings.Contains(m, "llamaguard"), strings.Contains(m, "llama_guard"):
		return FormatLlamaGuard
	case strings.Contains(m, "qwen3guard"), strings.Contains(m, "qwen3-guard"), strings.Contains(m, "qwen-guard"):
		return FormatQwen3Guard
	case strings.Contains(m, "granite") && strings.Contains(m, "guardian"):
		return FormatGraniteGuardian
	case strings.Contains(m, "nemoguard"), strings.Contains(m, "nemotron") && strings.Contains(m, "safety"),
		strings.Contains(m, "aegis"):
		return FormatNemotron
	}
	return FormatPolicy
}

// llamaGuardCategories is the MLCommons hazard taxonomy Llama Guard 3 and 4
// are trained on.
var llamaGuardCategories = map[string]string{
	"S1": "violent_crimes", "S2": "non_violent_crimes", "S3": "sex_related_crimes",
	"S4": "child_sexual_exploitation", "S5": "defamation", "S6": "specialized_advice",
	"S7": "privacy", "S8": "intellectual_property", "S9": "indiscriminate_weapons",
	"S10": "hate", "S11": "suicide_self_harm", "S12": "sexual_content", "S13": "elections",
	"S14": "code_interpreter_abuse",
}

// GuardModel drives an open-weight safety classifier through the router.
type GuardModel struct {
	Router  providers.Provider
	Route   string
	Format  string
	Pricing *telemetry.Pricing
	// Risk is the Granite Guardian risk definition to check ("harm",
	// "jailbreak", "social_bias", "groundedness", ...). Default: "harm".
	Risk string
	// ControversialUnsafe counts Qwen3Guard's "Controversial" label as unsafe.
	// The 2026 open-guard benchmark found it is most of Qwen3Guard's recall:
	// 84% with it, 47% without, at a precision cost. The default is true,
	// because a gateway that misses is worse than one that asks.
	ControversialUnsafe bool
	// WindowChars bounds each classifier call; longer text is scored in
	// overlapping windows and the worst window wins.
	WindowChars int
}

func (g *GuardModel) Name() string { return g.Route }

func (g *GuardModel) Supports(stage core.Stage) bool {
	return stage == core.StageInbound || stage == core.StageOutbound || stage == core.StageToolResult
}

func (g *GuardModel) Classify(ctx context.Context, text string, stage core.Stage) (v Verdict, err error) {
	v = Verdict{Classifier: g.Name()}
	start := time.Now()
	defer func() { v.Latency = time.Since(start) }()

	size := g.WindowChars
	if size <= 0 {
		size = 6000
	}
	windows := Windows(text, size, 400)
	if len(windows) > 6 {
		windows = append(windows[:3], windows[len(windows)-3:]...) // head and tail: where payloads sit
	}
	for _, w := range windows {
		one, err := g.classifyOne(ctx, g.messages(w, stage))
		v.Calls++
		v.CostUSD += one.CostUSD
		if err != nil {
			v.Error = err.Error()
			return v, err
		}
		v.Model = one.Model
		if one.Score >= v.Score {
			v.Score, v.Category, v.Rationale = one.Score, one.Category, one.Rationale
		}
		if one.Unsafe {
			v.Unsafe = true
		}
	}
	return v, nil
}

// ClassifyImage judges an image directly. Llama Guard 4 is natively
// multimodal; the other formats are text-only and decline.
func (g *GuardModel) ClassifyImage(ctx context.Context, data []byte, mime string) (Verdict, error) {
	if g.Format != FormatLlamaGuard {
		return Verdict{Classifier: g.Name()}, fmt.Errorf("%s (%s) does not accept images", g.Route, g.Format)
	}
	msgs := []core.Message{{Role: core.RoleUser, Content: "Is this image safe?",
		Parts: []core.Part{{Type: core.ModalityImage, MIME: mime, Data: data}}}}
	start := time.Now()
	v, err := g.classifyOne(ctx, msgs)
	v.Classifier, v.Latency, v.Calls = g.Name(), time.Since(start), 1
	return v, err
}

func (g *GuardModel) messages(text string, stage core.Stage) []core.Message {
	switch g.Format {
	case FormatGraniteGuardian:
		// Granite Guardian scores the LAST turn against the named risk.
		if stage == core.StageOutbound {
			return []core.Message{
				{Role: core.RoleUser, Content: "(the user's request is not shown)"},
				{Role: core.RoleAssistant, Content: text},
			}
		}
		return []core.Message{{Role: core.RoleUser, Content: text}}
	case FormatNemotron:
		return []core.Message{{Role: core.RoleUser, Content: nemotronPrompt(text, stage)}}
	}
	// Llama Guard and Qwen3Guard apply their own chat templates: a single
	// user turn is prompt classification, a user+assistant pair is response
	// classification.
	if stage == core.StageOutbound {
		return []core.Message{
			{Role: core.RoleUser, Content: "(the user's request is not shown)"},
			{Role: core.RoleAssistant, Content: text},
		}
	}
	return []core.Message{{Role: core.RoleUser, Content: text}}
}

func (g *GuardModel) classifyOne(ctx context.Context, msgs []core.Message) (Verdict, error) {
	req := providers.Request{Model: g.Route, Messages: msgs, MaxTokens: 128}
	if g.Format == FormatGraniteGuardian {
		risk := g.Risk
		if risk == "" {
			risk = "harm"
		}
		req.System = risk // the Ollama and vLLM Granite Guardian templates read the risk from the system turn
	}
	resp, err := g.Router.Complete(ctx, req)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Model: resp.Model}
	if g.Pricing != nil {
		v.CostUSD = g.Pricing.Cost(resp.Model, resp.Usage)
		if v.CostUSD == 0 {
			v.CostUSD = g.Pricing.InputCost(resp.Model, tokenize.Estimate(joinContent(msgs)))
		}
	}
	switch g.Format {
	case FormatLlamaGuard:
		err = parseLlamaGuard(resp.Text, &v)
	case FormatQwen3Guard:
		err = parseQwen3Guard(resp.Text, g.ControversialUnsafe, &v)
	case FormatGraniteGuardian:
		err = parseGranite(resp.Text, &v)
		if v.Unsafe {
			v.Category = g.Risk
			if v.Category == "" {
				v.Category = "harm"
			}
		}
	case FormatNemotron:
		err = parseNemotron(resp.Text, &v)
	default:
		err = fmt.Errorf("guard model: unknown format %q", g.Format)
	}
	return v, err
}

func joinContent(msgs []core.Message) string {
	var b strings.Builder
	for _, m := range msgs {
		b.WriteString(m.Content)
	}
	return b.String()
}

func parseLlamaGuard(out string, v *Verdict) error {
	s := strings.ToLower(strings.TrimSpace(out))
	switch {
	case strings.HasPrefix(s, "safe"):
		v.Score = 0
		return nil
	case strings.HasPrefix(s, "unsafe"):
		v.Unsafe, v.Score = true, 0.95
		var cats []string
		for _, code := range regexp.MustCompile(`(?i)\bS\d{1,2}\b`).FindAllString(out, -1) {
			if name, ok := llamaGuardCategories[strings.ToUpper(code)]; ok {
				cats = append(cats, name)
			}
		}
		if len(cats) > 0 {
			v.Category = cats[0]
			v.Rationale = "Llama Guard categories: " + strings.Join(cats, ", ")
		} else {
			v.Category = "unsafe"
		}
		return nil
	}
	return fmt.Errorf("llama guard: unexpected output %q", truncateRunes(out, 80))
}

var (
	qwenSafety = regexp.MustCompile(`(?i)Safety:\s*(Safe|Unsafe|Controversial)`)
	qwenCats   = regexp.MustCompile(`(?i)Categories:\s*([^\n]+)`)
)

func parseQwen3Guard(out string, controversialUnsafe bool, v *Verdict) error {
	m := qwenSafety.FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("qwen3guard: unexpected output %q", truncateRunes(out, 80))
	}
	switch strings.ToLower(m[1]) {
	case "unsafe":
		v.Unsafe, v.Score = true, 0.95
	case "controversial":
		v.Score = 0.6
		v.Unsafe = controversialUnsafe
	}
	if c := qwenCats.FindStringSubmatch(out); c != nil {
		cat := strings.TrimSpace(c[1])
		if !strings.EqualFold(cat, "none") {
			v.Category = strings.ToLower(strings.NewReplacer(" ", "_", "&", "and", "-", "_").Replace(strings.Split(cat, ",")[0]))
			v.Rationale = "Qwen3Guard: " + m[1] + " / " + cat
		}
	}
	if v.Unsafe && v.Category == "" {
		v.Category = "unsafe"
	}
	return nil
}

var graniteAnswer = regexp.MustCompile(`(?i)\b(yes|no)\b`)

func parseGranite(out string, v *Verdict) error {
	// Granite Guardian 3.3 thinks first and answers "<score> yes </score>";
	// earlier versions answer a bare Yes/No. The last yes/no wins either way.
	all := graniteAnswer.FindAllString(out, -1)
	if len(all) == 0 {
		return fmt.Errorf("granite guardian: unexpected output %q", truncateRunes(out, 80))
	}
	if strings.EqualFold(all[len(all)-1], "yes") {
		v.Unsafe, v.Score = true, 0.9
	}
	return nil
}

var nemotronField = regexp.MustCompile(`(?i)"?(User Safety|Response Safety)"?\s*:\s*"?(safe|unsafe)"?`)
var nemotronCats = regexp.MustCompile(`(?i)"?Safety Categories"?\s*:\s*"?([^"\n}]+)`)

func parseNemotron(out string, v *Verdict) error {
	ms := nemotronField.FindAllStringSubmatch(out, -1)
	if len(ms) == 0 {
		return fmt.Errorf("nemotron: unexpected output %q", truncateRunes(out, 80))
	}
	for _, m := range ms {
		if strings.EqualFold(m[2], "unsafe") {
			v.Unsafe, v.Score = true, 0.95
		}
	}
	if c := nemotronCats.FindStringSubmatch(out); c != nil && v.Unsafe {
		v.Category = strings.ToLower(strings.TrimSpace(strings.Split(c[1], ",")[0]))
		v.Rationale = "Nemotron categories: " + strings.TrimSpace(c[1])
	}
	if v.Unsafe && v.Category == "" {
		v.Category = "unsafe"
	}
	return nil
}

// nemotronPrompt is the Aegis 2.0 instruction the NemoGuard / Nemotron content
// safety models are trained on, condensed to its taxonomy and output contract.
func nemotronPrompt(text string, stage core.Stage) string {
	turn := "user: " + text
	field := `"User Safety"`
	if stage == core.StageOutbound {
		turn = "user: (not shown)\n\nresponse: agent: " + text
		field = `"User Safety" and "Response Safety"`
	}
	return `Task: Check if there is unsafe content in the user or agent messages in the below conversation in accordance with our safety policy with the below categories. Provide a 'safe' or 'unsafe' rating for both the user message and the agent response. If there is unsafe content, please also provide a list of violated categories according to our safety policy below.

<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violence. S2: Sexual. S3: Criminal Planning/Confessions. S4: Guns and Illegal Weapons. S5: Controlled/Regulated Substances. S6: Suicide and Self Harm. S7: Sexual (minor). S8: Hate/Identity Hate. S9: PII/Privacy. S10: Harassment. S11: Threat. S12: Profanity. S13: Needs Caution. S14: Other. S15: Manipulation. S16: Fraud/Deception. S17: Malware. S18: High Risk Gov Decision Making. S19: Political/Misinformation/Conspiracy. S20: Copyright/Trademark/Plagiarism. S21: Unauthorized Advice. S22: Illegal Activity. S23: Immoral/Unethical.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>

` + turn + `

<END CONVERSATION>

Provide your safety assessment for the above conversation in the below output JSON format:
{` + field + `: safe or unsafe rating, "Safety Categories": a comma-separated list of applicable safety categories from the provided taxonomy. Omit if all safe.}

Do not include anything other than the output JSON in your response.
Output JSON:`
}

// --- HTTP sequence classifiers (TEI and friends) ------------------------------

// HTTPClassifier calls a self-hosted sequence classifier. The default
// contract is Hugging Face text-embeddings-inference's /predict, which serves
// any AutoModelForSequenceClassification: Prompt Guard 2 (22M/86M), PIGuard,
// deberta-v3 prompt-injection models, toxicity classifiers. Running these in
// a sidecar keeps the semantic tier free of API keys and per-call fees, at
// 5-30 ms on a CPU.
//
// It is configured by name: "tei:http://host:port?unsafe=MALICIOUS,INJECTION&threshold=0.5".
type HTTPClassifier struct {
	Label       string
	URL         string
	UnsafeLabel map[string]bool
	Threshold   float64
	WindowChars int
	Client      *http.Client
	Stages      []core.Stage
}

// ParseHTTPClassifier builds an HTTPClassifier from its name.
func ParseHTTPClassifier(name string) (*HTTPClassifier, error) {
	raw, ok := strings.CutPrefix(name, "tei:")
	if !ok {
		return nil, fmt.Errorf("judge: %q is not a tei: classifier", name)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("judge: invalid classifier URL %q", raw)
	}
	q := u.Query()
	c := &HTTPClassifier{Label: "tei:" + u.Host, Threshold: 0.5, WindowChars: 1500,
		UnsafeLabel: map[string]bool{}, Client: &http.Client{Timeout: 10 * time.Second}}
	labels := q.Get("unsafe")
	if labels == "" {
		labels = "MALICIOUS,INJECTION,JAILBREAK,UNSAFE,LABEL_1,TOXIC,HARMFUL,INJECTED"
	}
	for _, l := range strings.Split(labels, ",") {
		c.UnsafeLabel[strings.ToUpper(strings.TrimSpace(l))] = true
	}
	if t := q.Get("threshold"); t != "" {
		if c.Threshold, err = strconv.ParseFloat(t, 64); err != nil {
			return nil, fmt.Errorf("judge: threshold %q: %w", t, err)
		}
	}
	if s := q.Get("stages"); s != "" {
		for _, st := range strings.Split(s, ",") {
			c.Stages = append(c.Stages, core.Stage(strings.TrimSpace(st)))
		}
	}
	if n := q.Get("label"); n != "" {
		c.Label = n
	}
	path := u.Path
	if path == "" || path == "/" {
		path = "/predict"
	}
	q.Del("unsafe")
	q.Del("threshold")
	q.Del("stages")
	q.Del("label")
	u.Path, u.RawQuery = path, q.Encode()
	c.URL = u.String()
	return c, nil
}

func (h *HTTPClassifier) Name() string { return h.Label }

func (h *HTTPClassifier) Supports(stage core.Stage) bool {
	if len(h.Stages) == 0 {
		return stage == core.StageInbound || stage == core.StageToolResult
	}
	for _, s := range h.Stages {
		if s == stage {
			return true
		}
	}
	return false
}

func (h *HTTPClassifier) Classify(ctx context.Context, text string, _ core.Stage) (v Verdict, err error) {
	v = Verdict{Classifier: h.Name(), Model: h.Label}
	start := time.Now()
	defer func() { v.Latency = time.Since(start) }()
	for _, w := range Windows(text, h.WindowChars, 200) {
		v.Calls++
		label, score, err := h.predict(ctx, w)
		if err != nil {
			v.Error = err.Error()
			return v, err
		}
		if h.UnsafeLabel[strings.ToUpper(label)] && score > v.Score {
			v.Score, v.Category = score, strings.ToLower(label)
		}
	}
	v.Unsafe = v.Score >= h.Threshold
	return v, nil
}

func (h *HTTPClassifier) predict(ctx context.Context, text string) (string, float64, error) {
	body, _ := json.Marshal(map[string]any{"inputs": text, "truncate": true, "raw_scores": false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("classifier HTTP %d: %s", resp.StatusCode, truncateRunes(string(raw), 160))
	}
	type pred struct {
		Label string  `json:"label"`
		Score float64 `json:"score"`
	}
	var flat []pred
	if err := json.Unmarshal(raw, &flat); err != nil {
		var nested [][]pred
		if err2 := json.Unmarshal(raw, &nested); err2 != nil || len(nested) == 0 {
			return "", 0, fmt.Errorf("classifier: unrecognised response %s", truncateRunes(string(raw), 160))
		}
		flat = nested[0]
	}
	best := pred{}
	for _, p := range flat {
		if h.UnsafeLabel[strings.ToUpper(p.Label)] && p.Score > best.Score {
			best = p
		}
	}
	return best.Label, best.Score, nil
}

// --- image moderation -------------------------------------------------------------

// ClassifyImage sends an image to OpenAI's omni-moderation model, which
// scores images for sexual, violent and self-harm content.
func (m *ModerationClassifier) ClassifyImage(ctx context.Context, data []byte, mime string) (Verdict, error) {
	v := Verdict{Classifier: m.Name(), Model: "omni-moderation-latest", Calls: 1}
	start := time.Now()
	p := core.Part{MIME: mime, Data: data}
	res, err := m.Client.ModerateImage(ctx, p.DataURI())
	v.Latency = time.Since(start)
	if err != nil {
		v.Error = err.Error()
		return v, err
	}
	v.Unsafe, v.Score = res.Flagged, res.TopScore
	if res.Flagged && len(res.Categories) > 0 {
		v.Category = res.Categories[0]
	}
	return v, nil
}

func (m *ModerationClassifier) Supports(stage core.Stage) bool { return stage != core.StageRuntime }

func (p *PromptGuard) Supports(stage core.Stage) bool {
	return stage == core.StageInbound || stage == core.StageToolResult
}
