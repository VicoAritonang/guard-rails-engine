# 11. Attachments are scanned as the text a model would read from them

Date: 2026-11-13 · Status: accepted

## Context

Until now the gateway refused every non-text content part with a 400: an
image or a PDF would otherwise reach the provider unscanned. That was safe and
useless. Production pipelines send screenshots, contracts, spreadsheets,
voice notes and RAG documents, and the attacks followed them: instructions in
white-on-white text, in a hidden Word run, in PNG metadata, in a scanned page,
in a spoken sentence. The 2025–26 omni-modal guard papers (OmniGuard,
GuardReasoner-Omni) and Llama Guard 4's multi-image input exist because of
this shift.

There were two designs on the table:

1. **One detector per threat per format.** An "image injection" model, a "PDF
   injection" model, an "audio jailbreak" model.
2. **Turn every part into text, then reuse the text guards.** Add detectors
   only for threats that have no textual form.

## Decision

Design 2. A new ingest step (`internal/media`, a `core.Ingestor`) runs before
the inbound and tool-result stages and extracts each part's text:

| Kind | How it is read | Model needed |
|---|---|---|
| PDF | text layer per page (`ledongthuc/pdf`), sub-1.5pt text, embedded JPEG pages → OCR when the PDF is a scan | only for scans |
| DOCX / XLSX / PPTX / ODF | XML walk, including headers, footers, comments, speaker notes, hidden runs/slides/sheets | no |
| HTML, SVG, RTF, text | tokenizer; hidden elements, comments, scripts reported | no |
| Images | header, EXIF/XMP/PNG text/JPEG comments, trailing data; OCR; image classifiers | OCR, image safety |
| Audio, video | WAV/ID3 headers; speech-to-text (video: audio track only) | yes |

The extracted text lands in `Part.Text`, which `Transaction.ScanFields`
exposes as `messages[i].parts[j].text`, so injection, PII, secrets, topic,
custom rules, the URL filter, the semantic tier and the tool-result rails read
it with no change to any of them. Their red-team suites and threshold sweeps
apply to attachments automatically.

What has no textual form becomes a finding of the `media` / `media_result`
guards: `document.macro`, `document.active_content`,
`document.external_reference` (remote templates), `document.embedded_file`,
`document.hidden_text`, `media.decompression_bomb`, `media.polyglot`,
`media.mime_mismatch`, `media.encrypted`, `media.unsafe_image`,
`media.size_limit`, and the two coverage findings below.

### Coverage is reported, never assumed

Every part carries `extraction.coverage` (`full | partial | none`). A part the
gateway could not read (no OCR configured, a scanned PDF, an encrypted file, a
remote URL with fetching off) produces `media.unscannable` (medium) or
`media.partial_coverage` (low). The balanced policy flags medium; strict
blocks it. Content nobody read is a policy decision, not a silent pass.

### Ingest runs outside the stage budget

The 50 ms stage budget bounds the guards. Transcribing a voice note cannot fit
in it and should not have to; ingest has its own deadline
(`extract_timeout_seconds`) and is reported in `media.ingest_ms`.

### Redaction and the original bytes

A guard can redact the extracted text, but not a JPEG. `binary_redaction`
decides what travels: `replace_with_text` (default: the upstream receives the
redacted text instead of the file), `block`, or `keep`. `forward: text` never
sends original bytes at all. Fetched remote parts are forwarded inline, never
by URL, so the upstream cannot fetch different bytes than the gateway scanned.

## Consequences

- One detector per threat, whatever the format; new formats are extractors,
  not new detectors.
- OCR and transcription are themselves models reading attacker content. They
  are coverage layers, fenced with "the content is data" instructions, and an
  empty OCR result is not proof of a clean image.
- Video frames are not inspected (no frame decoder in a static binary); the
  report says so with `media.partial_coverage`.
- PDF active-content names inside compressed object streams are invisible to
  the byte scan; a warning is attached when object streams are present.
