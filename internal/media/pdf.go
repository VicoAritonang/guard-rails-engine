package media

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ledongthuc/pdf"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// PDF names an attacker can use to make a document do something when opened.
// Matching happens after #xx name escapes are decoded, because /J#61vaScript
// is /JavaScript to every reader.
var pdfActive = []struct {
	name, rule, category string
	sev                  core.Severity
	what                 string
}{
	{"/JavaScript", "pdf_javascript", "document.active_content", core.SeverityHigh, "embedded JavaScript"},
	{"/JS", "pdf_javascript", "document.active_content", core.SeverityHigh, "embedded JavaScript"},
	{"/Launch", "pdf_launch", "document.active_content", core.SeverityHigh, "a Launch action (runs a program)"},
	{"/SubmitForm", "pdf_submit", "document.active_content", core.SeverityMedium, "a form that submits data to a URL"},
	{"/ImportData", "pdf_import", "document.active_content", core.SeverityMedium, "an ImportData action"},
	{"/RichMedia", "pdf_richmedia", "document.active_content", core.SeverityMedium, "embedded rich media (Flash/3D)"},
	{"/XFA", "pdf_xfa", "document.active_content", core.SeverityMedium, "an XFA form (scriptable)"},
	{"/EmbeddedFile", "pdf_embedded_file", "document.embedded_file", core.SeverityMedium, "an embedded file"},
	{"/OpenAction", "pdf_open_action", "document.active_content", core.SeverityLow, "an action that runs on open"},
	{"/AA", "pdf_additional_actions", "document.active_content", core.SeverityLow, "additional (event-triggered) actions"},
}

var (
	pdfNameEscape = regexp.MustCompile(`#([0-9A-Fa-f]{2})`)
	pdfNameEnd    = regexp.MustCompile(`^[\s/<>\[\]()%{}]`)
)

func (r *reader) pdf(ctx context.Context, data []byte) {
	r.ext.AddMethod("pdf")
	label := r.ref.Part.Label()

	decoded := pdfNameEscape.ReplaceAllFunc(data, func(m []byte) []byte {
		n, _ := strconv.ParseUint(string(m[1:]), 16, 8)
		return []byte{byte(n)}
	})
	seen := map[string]bool{}
	for _, a := range pdfActive {
		if seen[a.rule] {
			continue
		}
		if pdfHasName(decoded, a.name) {
			seen[a.rule] = true
			r.add(a.rule, a.category, a.sev, "%s contains %s (%s)", label, a.what, a.name)
		}
	}
	if pdfHasName(decoded, "/Encrypt") {
		r.add("pdf_encrypted", "media.encrypted", core.SeverityMedium, "%s is encrypted; its text may be unreadable to the gateway", label)
	}
	if bytes.Contains(decoded, []byte("/ObjStm")) {
		r.warn("the PDF uses compressed object streams; active-content names inside them are not visible to the byte scan")
	}

	text, pages, small, err := pdfText(data)
	r.ext.Pages = pages
	if err != nil {
		r.add("pdf_unreadable", "media.unscannable", core.SeverityMedium, "%s: the text layer could not be read: %v", label, err)
	}
	r.section("", text)
	if small.chars > 0 {
		r.hidden.WriteString(small.sample.String())
		r.hiddenFinding("text set below 1.5pt", small.chars, small.sample.String())
	}

	// A PDF with pages and almost no text is a scan. Its words are pixels,
	// and the only way to read them is OCR on the page images.
	scanned := pages > 0 && len(strings.TrimSpace(text)) < 40*pages
	switch {
	case err == nil && !scanned:
		r.ext.Coverage = core.CoverageFull
	case scanned && r.p.b.OCR != nil && r.p.opts.OCRDocuments:
		imgs := pdfJPEGs(data, r.p.opts.MaxPDFImages)
		read := 0
		for i, img := range imgs {
			if ctx.Err() != nil {
				break
			}
			t, oerr := r.p.b.OCR.ReadImage(ctx, img, "image/jpeg")
			if oerr != nil {
				r.warn("OCR of page image %d failed: %v", i+1, oerr)
				continue
			}
			read++
			r.section(fmt.Sprintf("page image %d (OCR)", i+1), t)
		}
		if read > 0 {
			r.ext.AddMethod("ocr:" + r.p.b.OCR.Name())
			r.ext.Coverage = core.CoveragePartial
			if read == len(imgs) && len(imgs) >= pages {
				r.ext.Coverage = core.CoverageFull
			}
		}
		if r.ext.Coverage != core.CoverageFull {
			r.add("pdf_scanned", "media.partial_coverage", core.SeverityLow,
				"%s looks scanned (%d pages, little text); %d page image(s) were read by OCR", label, pages, read)
		}
	case scanned:
		r.ext.Coverage = core.CoveragePartial
		if strings.TrimSpace(text) == "" {
			r.ext.Coverage = core.CoverageNone
		}
		r.add("pdf_scanned", "media.unscannable", core.SeverityMedium,
			"%s looks scanned (%d pages, little or no text layer) and no OCR backend is configured", label, pages)
	}
}

func pdfHasName(data []byte, name string) bool {
	for i := 0; ; {
		j := bytes.Index(data[i:], []byte(name))
		if j < 0 {
			return false
		}
		end := i + j + len(name)
		if end >= len(data) || pdfNameEnd.Match(data[end:end+1]) {
			return true
		}
		i = end
	}
}

type smallText struct {
	chars  int
	sample strings.Builder
}

// pdfText extracts the text layer page by page. The library panics on some
// malformed files; the panic is contained here so a hostile PDF costs its
// text, not the request.
func pdfText(data []byte) (text string, pages int, small *smallText, err error) {
	small = &smallText{}
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("malformed PDF: %v", rec)
		}
	}()
	rd, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", 0, small, err
	}
	pages = rd.NumPage()
	var b strings.Builder
	for i := 1; i <= pages; i++ {
		p := rd.Page(i)
		if p.V.IsNull() {
			continue
		}
		t, perr := pageText(p, small)
		if perr != nil {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, "[page %d]\n", i)
		b.WriteString(t)
	}
	return b.String(), pages, small, nil
}

func pageText(p pdf.Page, small *smallText) (out string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("page: %v", rec)
		}
	}()
	out, err = p.GetPlainText(nil)
	// Text drawn below 1.5pt is invisible on screen and in print, and fully
	// legible to a model. Content() is costlier, so it only runs on pages
	// that have text at all.
	if err == nil && strings.TrimSpace(out) != "" {
		for _, t := range p.Content().Text {
			if t.FontSize > 0 && t.FontSize < 1.5 && strings.TrimSpace(t.S) != "" {
				small.chars += len(t.S)
				if small.sample.Len() < 200 {
					small.sample.WriteString(t.S)
				}
			}
		}
	}
	return out, err
}

// pdfJPEGs pulls DCT-encoded image streams out of a PDF. Scanners write each
// page as one JPEG, so this recovers the page images without a PDF renderer.
func pdfJPEGs(data []byte, max int) [][]byte {
	var out [][]byte
	for i := 0; len(out) < max; {
		j := bytes.Index(data[i:], []byte("/DCTDecode"))
		if j < 0 {
			break
		}
		at := i + j
		s := bytes.Index(data[at:], []byte("stream"))
		if s < 0 {
			break
		}
		start := at + s + len("stream")
		for start < len(data) && (data[start] == '\r' || data[start] == '\n') {
			start++
		}
		e := bytes.Index(data[start:], []byte("endstream"))
		if e < 0 {
			break
		}
		img := bytes.TrimRight(data[start:start+e], "\r\n")
		if bytes.HasPrefix(img, []byte{0xFF, 0xD8}) && len(img) > 2048 {
			out = append(out, img)
		}
		i = start + e
	}
	return out
}
