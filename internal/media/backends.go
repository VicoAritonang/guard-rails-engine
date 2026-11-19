package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// --- OCR through an HTTP sidecar ---------------------------------------------------

// HTTPOCR posts the raw image to a sidecar and reads back text. The contract
// is deliberately trivial so any OCR engine can sit behind it (Tesseract,
// PaddleOCR, docTR, a cloud API): POST the bytes with their Content-Type, get
// back either {"text": "..."} or text/plain.
type HTTPOCR struct {
	URL    string
	Token  string
	Client *http.Client
}

func (h *HTTPOCR) Name() string { return "http" }

func (h *HTTPOCR) ReadImage(ctx context.Context, data []byte, mime string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if mime == "" {
		mime = "application/octet-stream"
	}
	req.Header.Set("Content-Type", mime)
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	body, err := doHTTP(h.client(), req, 4<<20)
	if err != nil {
		return "", fmt.Errorf("ocr sidecar: %w", err)
	}
	return textOrJSON(body, "text"), nil
}

func (h *HTTPOCR) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// --- Speech to text --------------------------------------------------------------

// OpenAITranscriber speaks the OpenAI /audio/transcriptions API, which is also
// what Groq (whisper-large-v3-turbo), LocalAI, speaches and
// faster-whisper-server implement. One client covers the hosted and the
// self-hosted case.
type OpenAITranscriber struct {
	BaseURL string // e.g. https://api.openai.com/v1
	APIKey  string
	Model   string // gpt-4o-mini-transcribe, whisper-1, whisper-large-v3-turbo, ...
	Label   string
	Client  *http.Client
}

func (t *OpenAITranscriber) Name() string {
	if t.Label != "" {
		return t.Label
	}
	return t.Model
}

func (t *OpenAITranscriber) Transcribe(ctx context.Context, data []byte, mime, filename string) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(data); err != nil {
		return "", err
	}
	_ = mw.WriteField("model", t.Model)
	_ = mw.WriteField("response_format", "json")
	if err := mw.Close(); err != nil {
		return "", err
	}
	url := strings.TrimRight(t.BaseURL, "/") + "/audio/transcriptions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if t.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.APIKey)
	}
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	out, err := doHTTP(client, req, 8<<20)
	if err != nil {
		return "", fmt.Errorf("transcribe: %w", err)
	}
	return textOrJSON(out, "text"), nil
}

func doHTTP(c *http.Client, req *http.Request, limit int64) ([]byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(body)), 200))
	}
	return body, nil
}

func textOrJSON(body []byte, field string) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var m map[string]any
		if json.Unmarshal(trimmed, &m) == nil {
			if s, ok := m[field].(string); ok {
				return s
			}
		}
	}
	return string(trimmed)
}

// ErrNoBackend is returned by backend constructors when nothing is configured.
var ErrNoBackend = errors.New("media: backend not configured")
