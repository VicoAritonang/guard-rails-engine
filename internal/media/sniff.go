package media

import (
	"bytes"
	"net/http"
	"path"
	"strings"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// kind is what the bytes actually are, which can differ from what the caller
// declared. Every decision downstream keys on kind, never on the declaration:
// a polyglot that claims to be a PNG and parses as a ZIP is the attack.
type kind struct {
	mime     string
	modality core.Modality
	format   string // pdf, docx, png, wav, ...
	strong   bool   // identified by magic bytes rather than by name
}

var extKinds = map[string]kind{
	".pdf":   {"application/pdf", core.ModalityDocument, "pdf", false},
	".docx":  {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", core.ModalityDocument, "docx", false},
	".docm":  {"application/vnd.ms-word.document.macroEnabled.12", core.ModalityDocument, "docx", false},
	".xlsx":  {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", core.ModalityDocument, "xlsx", false},
	".xlsm":  {"application/vnd.ms-excel.sheet.macroEnabled.12", core.ModalityDocument, "xlsx", false},
	".pptx":  {"application/vnd.openxmlformats-officedocument.presentationml.presentation", core.ModalityDocument, "pptx", false},
	".pptm":  {"application/vnd.ms-powerpoint.presentation.macroEnabled.12", core.ModalityDocument, "pptx", false},
	".odt":   {"application/vnd.oasis.opendocument.text", core.ModalityDocument, "odf", false},
	".ods":   {"application/vnd.oasis.opendocument.spreadsheet", core.ModalityDocument, "odf", false},
	".odp":   {"application/vnd.oasis.opendocument.presentation", core.ModalityDocument, "odf", false},
	".html":  {"text/html", core.ModalityDocument, "html", false},
	".htm":   {"text/html", core.ModalityDocument, "html", false},
	".xhtml": {"application/xhtml+xml", core.ModalityDocument, "html", false},
	".md":    {"text/markdown", core.ModalityDocument, "text", false},
	".txt":   {"text/plain", core.ModalityDocument, "text", false},
	".csv":   {"text/csv", core.ModalityDocument, "text", false},
	".tsv":   {"text/tab-separated-values", core.ModalityDocument, "text", false},
	".json":  {"application/json", core.ModalityDocument, "text", false},
	".jsonl": {"application/jsonl", core.ModalityDocument, "text", false},
	".xml":   {"application/xml", core.ModalityDocument, "text", false},
	".yaml":  {"application/yaml", core.ModalityDocument, "text", false},
	".yml":   {"application/yaml", core.ModalityDocument, "text", false},
	".rtf":   {"application/rtf", core.ModalityDocument, "rtf", false},
	".eml":   {"message/rfc822", core.ModalityDocument, "text", false},
	".svg":   {"image/svg+xml", core.ModalityImage, "svg", false},
	".png":   {"image/png", core.ModalityImage, "png", false},
	".jpg":   {"image/jpeg", core.ModalityImage, "jpeg", false},
	".jpeg":  {"image/jpeg", core.ModalityImage, "jpeg", false},
	".gif":   {"image/gif", core.ModalityImage, "gif", false},
	".webp":  {"image/webp", core.ModalityImage, "webp", false},
	".bmp":   {"image/bmp", core.ModalityImage, "bmp", false},
	".tif":   {"image/tiff", core.ModalityImage, "tiff", false},
	".tiff":  {"image/tiff", core.ModalityImage, "tiff", false},
	".heic":  {"image/heic", core.ModalityImage, "heic", false},
	".avif":  {"image/avif", core.ModalityImage, "avif", false},
	".wav":   {"audio/wav", core.ModalityAudio, "wav", false},
	".mp3":   {"audio/mpeg", core.ModalityAudio, "mp3", false},
	".ogg":   {"audio/ogg", core.ModalityAudio, "ogg", false},
	".oga":   {"audio/ogg", core.ModalityAudio, "ogg", false},
	".opus":  {"audio/ogg", core.ModalityAudio, "ogg", false},
	".flac":  {"audio/flac", core.ModalityAudio, "flac", false},
	".m4a":   {"audio/mp4", core.ModalityAudio, "m4a", false},
	".aac":   {"audio/aac", core.ModalityAudio, "aac", false},
	".mp4":   {"video/mp4", core.ModalityVideo, "mp4", false},
	".m4v":   {"video/mp4", core.ModalityVideo, "mp4", false},
	".mov":   {"video/quicktime", core.ModalityVideo, "mov", false},
	".webm":  {"video/webm", core.ModalityVideo, "webm", false},
	".mkv":   {"video/x-matroska", core.ModalityVideo, "mkv", false},
}

// sniff identifies the bytes, preferring magic numbers over names.
func sniff(data []byte, declaredMIME, name string) kind {
	byName, hasName := extKinds[strings.ToLower(path.Ext(name))]
	byMIME := kindForMIME(declaredMIME)
	hint := byName
	if !hasName {
		hint = byMIME
	}

	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	switch {
	case bytes.HasPrefix(head, []byte("%PDF-")) || bytes.Contains(head[:min(len(head), 1024)], []byte("%PDF-")):
		return kind{"application/pdf", core.ModalityDocument, "pdf", true}
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return kind{"image/png", core.ModalityImage, "png", true}
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		return kind{"image/jpeg", core.ModalityImage, "jpeg", true}
	case bytes.HasPrefix(head, []byte("GIF87a")) || bytes.HasPrefix(head, []byte("GIF89a")):
		return kind{"image/gif", core.ModalityImage, "gif", true}
	case len(head) >= 12 && bytes.HasPrefix(head, []byte("RIFF")) && string(head[8:12]) == "WEBP":
		return kind{"image/webp", core.ModalityImage, "webp", true}
	case len(head) >= 12 && bytes.HasPrefix(head, []byte("RIFF")) && string(head[8:12]) == "WAVE":
		return kind{"audio/wav", core.ModalityAudio, "wav", true}
	case bytes.HasPrefix(head, []byte("BM")) && len(head) > 26 && hint.format == "bmp":
		return kind{"image/bmp", core.ModalityImage, "bmp", true}
	case bytes.HasPrefix(head, []byte("II*\x00")) || bytes.HasPrefix(head, []byte("MM\x00*")):
		return kind{"image/tiff", core.ModalityImage, "tiff", true}
	case bytes.HasPrefix(head, []byte("ID3")) || (len(head) > 2 && head[0] == 0xFF && head[1]&0xE0 == 0xE0 && hint.modality != core.ModalityImage):
		return kind{"audio/mpeg", core.ModalityAudio, "mp3", true}
	case bytes.HasPrefix(head, []byte("OggS")):
		return kind{"audio/ogg", core.ModalityAudio, "ogg", true}
	case bytes.HasPrefix(head, []byte("fLaC")):
		return kind{"audio/flac", core.ModalityAudio, "flac", true}
	case len(head) >= 12 && string(head[4:8]) == "ftyp":
		brand := string(head[8:12])
		switch {
		case strings.HasPrefix(brand, "M4A"), strings.HasPrefix(brand, "M4B"):
			return kind{"audio/mp4", core.ModalityAudio, "m4a", true}
		case brand == "heic" || brand == "heix" || brand == "mif1":
			return kind{"image/heic", core.ModalityImage, "heic", true}
		case brand == "avif":
			return kind{"image/avif", core.ModalityImage, "avif", true}
		case strings.HasPrefix(brand, "qt"):
			return kind{"video/quicktime", core.ModalityVideo, "mov", true}
		}
		if hint.modality == core.ModalityAudio {
			return kind{"audio/mp4", core.ModalityAudio, "m4a", true}
		}
		return kind{"video/mp4", core.ModalityVideo, "mp4", true}
	case bytes.HasPrefix(head, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		if hint.modality == core.ModalityAudio {
			return kind{"audio/webm", core.ModalityAudio, "webm", true}
		}
		return kind{"video/webm", core.ModalityVideo, "webm", true}
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		return sniffZip(data, hint)
	case bytes.HasPrefix(head, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		// OLE compound file: legacy .doc/.xls/.ppt, or an encrypted OOXML.
		return kind{"application/x-ole-storage", core.ModalityDocument, "ole", true}
	case bytes.HasPrefix(head, []byte(`{\rtf`)):
		return kind{"application/rtf", core.ModalityDocument, "rtf", true}
	}

	trimmed := bytes.TrimLeft(head, " \t\r\n\xef\xbb\xbf")
	lower := bytes.ToLower(trimmed[:min(len(trimmed), 512)])
	if bytes.Contains(lower, []byte("<svg")) {
		return kind{"image/svg+xml", core.ModalityImage, "svg", true}
	}
	if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) ||
		(hint.format == "html" && bytes.HasPrefix(lower, []byte("<"))) {
		return kind{"text/html", core.ModalityDocument, "html", true}
	}
	if hint.mime != "" && (hint.format != "text" || looksText(data)) {
		return hint
	}
	ct := http.DetectContentType(data)
	if strings.HasPrefix(ct, "text/") || looksText(data) {
		mime := strings.Split(ct, ";")[0]
		if hint.format == "text" {
			mime = hint.mime
		}
		return kind{mime, core.ModalityDocument, "text", false}
	}
	return kind{strings.Split(ct, ";")[0], "", "unknown", false}
}

func sniffZip(data []byte, hint kind) kind {
	switch {
	case bytes.Contains(data, []byte("word/document.xml")):
		return kind{extKinds[".docx"].mime, core.ModalityDocument, "docx", true}
	case bytes.Contains(data, []byte("xl/workbook.xml")):
		return kind{extKinds[".xlsx"].mime, core.ModalityDocument, "xlsx", true}
	case bytes.Contains(data, []byte("ppt/presentation.xml")):
		return kind{extKinds[".pptx"].mime, core.ModalityDocument, "pptx", true}
	case bytes.Contains(data[:min(len(data), 200)], []byte("application/vnd.oasis.opendocument")):
		return kind{extKinds[".odt"].mime, core.ModalityDocument, "odf", true}
	}
	if hint.format == "docx" || hint.format == "xlsx" || hint.format == "pptx" || hint.format == "odf" {
		return hint
	}
	return kind{"application/zip", core.ModalityDocument, "zip", true}
}

func kindForMIME(mime string) kind {
	mime = strings.ToLower(strings.TrimSpace(strings.Split(mime, ";")[0]))
	if mime == "" {
		return kind{}
	}
	for _, k := range extKinds {
		if k.mime == mime {
			return k
		}
	}
	switch {
	case mime == "image/jpg":
		return extKinds[".jpg"]
	case mime == "audio/x-wav" || mime == "audio/wave":
		return extKinds[".wav"]
	case mime == "audio/mp3":
		return extKinds[".mp3"]
	case strings.HasPrefix(mime, "text/"):
		return kind{mime, core.ModalityDocument, "text", false}
	case strings.HasPrefix(mime, "image/"):
		return kind{mime, core.ModalityImage, "unknown", false}
	case strings.HasPrefix(mime, "audio/"):
		return kind{mime, core.ModalityAudio, "unknown", false}
	case strings.HasPrefix(mime, "video/"):
		return kind{mime, core.ModalityVideo, "unknown", false}
	}
	return kind{mime: mime}
}

// mismatch reports a strong identification that contradicts the declared
// type's family: an "image/png" whose bytes are a PDF, a ".jpg" that is a ZIP.
func mismatch(declaredMIME, name string, k kind) bool {
	if !k.strong {
		return false
	}
	for _, d := range []kind{kindForMIME(declaredMIME), extKinds[strings.ToLower(path.Ext(name))]} {
		if d.mime == "" || d.modality == "" {
			continue
		}
		if d.modality != k.modality {
			return true
		}
		// Within documents, a PDF declared as DOCX is still a mismatch.
		if d.format != "" && d.format != "unknown" && d.format != "text" && k.format != d.format &&
			!(d.format == "html" && k.format == "text") {
			return true
		}
	}
	return false
}

func mismatchFamily(declaredMIME string, k kind) bool {
	d := kindForMIME(declaredMIME)
	return k.strong && d.modality != "" && d.modality != k.modality
}

func declared(p *core.Part) string {
	if p.MIME != "" {
		return p.MIME
	}
	return path.Ext(p.Name)
}

// looksText reports whether data is plausibly UTF-8 text: no NUL bytes in the
// first 8 KB and mostly printable.
func looksText(data []byte) bool {
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	if len(head) == 0 {
		return false
	}
	ctrl := 0
	for _, b := range head {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			ctrl++
		}
	}
	return ctrl*20 < len(head)
}
