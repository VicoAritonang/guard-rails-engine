# Documents, images, audio and video

Attachments go through the same guards as text. The gateway extracts the text
a model would read from each file, the existing guards scan that text, and a
separate pair of guards (`media`, `media_result`) reports threats that only
exist in files. Design rationale: [ADR 0011](adr/0011-multimodal-ingest.md).

## Sending attachments

**OpenAI-compatible proxy.** Standard content parts work as they are:

```python
client.chat.completions.create(model="gpt-5-mini", messages=[{"role": "user", "content": [
    {"type": "text", "text": "Summarise this contract"},
    {"type": "file", "file": {"filename": "contract.pdf", "file_data": "data:application/pdf;base64,..."}},
    {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}},
    {"type": "input_audio", "input_audio": {"data": "<base64 wav>", "format": "wav"}},
]}])
```

`file_id` references are refused: the gateway never saw those bytes.

**Upload endpoint**, for upload forms and RAG ingestion:

```bash
curl -F file=@contract.pdf http://localhost:8080/v1/guard/media
curl -F file=@page.html -F stage=tool_result -F origin=web http://localhost:8080/v1/guard/media
```

**Validate mode / SDKs.** Put parts on a message or a tool result:

```python
from guard_rails_engine import Client, attachment
gr = Client("http://localhost:8080")
gr.inbound(messages=[{"role": "user", "content": "What does this say?", "parts": [attachment("scan.jpg")]}])
gr.scan_file("upload.docx")
```

```go
g, _ := guardrails.New(guardrails.Options{
    Media: guardrails.MediaBackends{
        OCR:         guardrails.NewHTTPOCR("http://ocr:8000/ocr", ""),
        Transcriber: guardrails.NewOpenAITranscriber("https://api.groq.com/openai/v1", key, "whisper-large-v3-turbo"),
    },
})
res, err := g.ScanFile(ctx, "invoice.pdf", data)
```

**MCP.** Image, audio and embedded-resource blocks in tool results are scanned
by the tool-result rails and reach the agent as their (redacted) text.

## What is read, and with what

| Format | Read locally | Needs a backend |
|---|---|---|
| PDF | text layer, tiny-font text, JavaScript/Launch/EmbeddedFile/XFA names, encryption | OCR for scanned pages |
| DOCX, XLSX, PPTX, ODT/ODS/ODP | body, headers, footers, comments, notes, hidden runs/slides/sheets, macros, embedded objects, remote templates, dangerous formulas | — |
| HTML, SVG, RTF, TXT, MD, CSV, JSON, XML | visible and hidden text, comments, scripts, event handlers, OLE objects | — |
| ZIP | member names, executables, bomb limits (contents are not unpacked) | — |
| PNG, JPEG, GIF, WebP, BMP | dimensions, EXIF/XMP/PNG text/comments, appended data | OCR, image safety |
| WAV, MP3, OGG, FLAC, M4A | duration (WAV), ID3 tags | speech-to-text |
| MP4, WebM, MOV | — | speech-to-text (audio track only) |

`GET /v1/media` reports what a running gateway can read.

## Backends

| Variable | Values |
|---|---|
| `GUARDRAILS_MEDIA_OCR` | a catalog route of a vision model (`vision-ocr`, `local:qwen2.5vl:7b`) or an OCR sidecar URL answering `{"text": ...}` |
| `GUARDRAILS_MEDIA_TRANSCRIBE` | `openai`, `groq`, `local`, or the base URL of an OpenAI-compatible speech server (speaches, faster-whisper-server, LocalAI) |
| `GUARDRAILS_MEDIA_TRANSCRIBE_MODEL` | e.g. `gpt-4o-mini-transcribe`, `whisper-large-v3-turbo` |
| `GUARDRAILS_MEDIA_IMAGE_CLASSIFIERS` | `moderation` (OpenAI omni-moderation) and/or a Llama Guard 4 route (`llama-guard-4`) |
| `GUARDRAILS_MEDIA_UPLOAD_BYTES` | multipart upload limit; raise `GUARDRAILS_MAX_BODY_BYTES` too for base64 JSON parts |

Everything can run self-hosted: `deploy/compose/docker-compose.local-models.yml`.

## Findings

| Category | Default severity | Meaning |
|---|---|---|
| `media.unscannable` | medium | the part could not be read at all |
| `media.partial_coverage` | low | part of it was read (no OCR, video frames, archive contents) |
| `media.size_limit` | high | too many parts, too many bytes, too long |
| `media.decompression_bomb` | critical | pixel bomb, ZIP ratio/size/entry bomb |
| `media.mime_mismatch` | medium | the bytes contradict the declared type |
| `media.polyglot` | medium | data appended after an image's end marker |
| `media.encrypted` | medium | encrypted PDF or archive entries |
| `media.unsafe_image` | high | an image classifier judged the picture unsafe |
| `media.metadata_text` | info | an image carries long metadata text (scanned anyway) |
| `media.truncated` | low | extracted text exceeded `max_extract_chars` |
| `media.redaction_unenforceable` | high | `binary_redaction: block` and a guard redacted text inside a file |
| `document.macro` | high | VBA or ODF macros |
| `document.active_content` | high/medium | PDF JavaScript/Launch, SVG/HTML script, DDE/WEBSERVICE formulas |
| `document.external_reference` | high/low | remote templates, OLE links, external SVG resources |
| `document.embedded_file` | medium/high | OLE/ActiveX objects, PDF attachments, executables in archives |
| `document.hidden_text` | medium | text hidden from a human and read by a model |

Retune any of them in the policy, as with any guard:

```yaml
guards:
  media:
    categories:
      media.unscannable: { action: block }     # refuse what nobody read
      document.hidden_text: { severity: high } # block hidden text outright
```

## Forwarding

| Param | Values | Effect |
|---|---|---|
| `forward` | `native` (default), `text` | `text` never sends original bytes upstream, only extracted text |
| `binary_redaction` | `replace_with_text` (default), `block`, `keep` | what happens when a guard redacted text inside a file |
| `fetch_remote` | `false` (default) | fetch `https://` image URLs (public addresses only) and forward them inline |

Model catalog routes can declare `inputs: [text, image, document]`; on a route
that cannot take a modality, that attachment is sent as its extracted text, so
a text-only fallback model still answers.

## Limits worth knowing

- OCR and speech-to-text are models reading attacker content. Their output is
  scanned, but an empty transcription is not proof of a clean file.
- Video frames are not inspected.
- PDF action names inside compressed object streams are not visible to the
  byte scan (a warning is attached).
- Archives are listed, not unpacked.
