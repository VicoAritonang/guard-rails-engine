package media

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

func (r *reader) document(ctx context.Context, k kind) {
	data := r.ref.Part.Data
	switch k.format {
	case "pdf":
		r.pdf(ctx, data)
	case "docx", "xlsx", "pptx", "odf":
		r.office(k, data)
	case "zip":
		r.archive(data)
	case "ole":
		r.add("legacy_office", "media.unscannable", core.SeverityMedium,
			"%s is a legacy or password-protected Office file (OLE compound document), which the gateway cannot read; convert it to OOXML or PDF", r.ref.Part.Label())
		if bytes.Contains(data, []byte("V\x00B\x00A")) || bytes.Contains(data, []byte("_VBA_PROJECT")) {
			r.add("macro", "document.macro", core.SeverityHigh, "%s contains a VBA macro project", r.ref.Part.Label())
		}
	case "html":
		r.html(data)
		r.ext.AddMethod("html")
		r.ext.Coverage = core.CoverageFull
	case "rtf":
		r.rtf(data)
	default:
		r.section("", string(data))
		r.ext.AddMethod("text")
		r.ext.Coverage = core.CoverageFull
	}
}

// --- OOXML and OpenDocument ------------------------------------------------------

// office reads the ZIP-based formats. They are archives of XML, so the text
// is a walk over the right parts; the risks are the parts that are not text:
// macros, embedded objects, and relationships that point outside the file
// (a remote template is how a .docx runs code without containing any).
func (r *reader) office(k kind, data []byte) {
	zr, ok := r.openZip(data)
	if !ok {
		return
	}
	r.ext.AddMethod(k.format)
	files := map[string]*zip.File{}
	var names []string
	for _, f := range zr.File {
		files[f.Name] = f
		names = append(names, f.Name)
	}
	sort.Slice(names, func(i, j int) bool { return naturalLess(names[i], names[j]) })

	r.officeRisks(names, files)

	var budget = r.p.opts.MaxUncompressed
	read := func(name string) []byte {
		f, ok := files[name]
		if !ok {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		defer rc.Close()
		b, _ := io.ReadAll(io.LimitReader(rc, budget))
		budget -= int64(len(b))
		return b
	}

	switch k.format {
	case "docx":
		for _, n := range names {
			if !strings.HasPrefix(n, "word/") || !strings.HasSuffix(n, ".xml") || strings.Contains(n, "/_rels/") {
				continue
			}
			base := path.Base(n)
			switch {
			case base == "document.xml":
				r.section("", r.wordText(read(n), "body"))
			case strings.HasPrefix(base, "header"), strings.HasPrefix(base, "footer"):
				r.section(strings.TrimSuffix(base, ".xml"), r.wordText(read(n), base))
			case base == "footnotes.xml", base == "endnotes.xml":
				r.section(strings.TrimSuffix(base, ".xml"), r.wordText(read(n), base))
			case base == "comments.xml":
				r.section("comments", r.wordText(read(n), "comments"))
			}
		}
	case "pptx":
		for _, n := range names {
			switch {
			case strings.HasPrefix(n, "ppt/slides/slide") && strings.HasSuffix(n, ".xml"):
				raw := read(n)
				if bytes.Contains(raw[:min(len(raw), 600)], []byte(`show="0"`)) {
					txt := xmlText(raw, nil)
					r.hidden.WriteString(txt + "\n")
					r.hiddenFinding("hidden slide "+path.Base(n), len(txt), txt)
					continue
				}
				r.section(strings.TrimSuffix(path.Base(n), ".xml"), xmlText(raw, nil))
			case strings.HasPrefix(n, "ppt/notesSlides/") && strings.HasSuffix(n, ".xml"):
				r.section("speaker notes "+strings.TrimSuffix(path.Base(n), ".xml"), xmlText(read(n), nil))
			case strings.HasPrefix(n, "ppt/comments/") && strings.HasSuffix(n, ".xml"):
				r.section("comments", xmlText(read(n), nil))
			}
		}
	case "xlsx":
		r.section("", xmlText(read("xl/sharedStrings.xml"), nil))
		wb := read("xl/workbook.xml")
		for _, m := range hiddenSheetRe.FindAllSubmatch(wb, -1) {
			r.hiddenFinding("hidden worksheet "+string(m[1]), 1, "worksheet "+string(m[1]))
		}
		for _, n := range names {
			if !strings.HasPrefix(n, "xl/worksheets/sheet") || !strings.HasSuffix(n, ".xml") {
				continue
			}
			raw := read(n)
			r.section("", inlineStrings(raw))
			r.formulaRisks(n, raw)
		}
		for _, n := range names {
			if strings.HasPrefix(n, "xl/comments") && strings.HasSuffix(n, ".xml") {
				r.section("comments", xmlText(read(n), nil))
			}
		}
	case "odf":
		r.section("", xmlText(read("content.xml"), map[string]bool{"p": true, "h": true}))
		r.section("styles", xmlText(read("styles.xml"), map[string]bool{"p": true, "h": true}))
	}
	r.ext.Coverage = core.CoverageFull
	if r.hasImages(names) {
		r.ext.Coverage = core.CoveragePartial
		r.warn("embedded images were not read")
	}
}

var hiddenSheetRe = regexp.MustCompile(`<sheet\b[^>]*\bname="([^"]*)"[^>]*\bstate="(?:hidden|veryHidden)"`)

func (r *reader) hasImages(names []string) bool {
	for _, n := range names {
		if strings.Contains(n, "/media/") || strings.HasPrefix(n, "Pictures/") {
			return true
		}
	}
	return false
}

// openZip opens an archive after checking the limits a bomb would violate.
// The declared sizes in a ZIP directory are attacker-controlled, so every
// later read is also bounded by a LimitReader.
func (r *reader) openZip(data []byte) (*zip.Reader, bool) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		r.add("bad_archive", "media.unscannable", core.SeverityMedium, "%s is not a readable archive: %v", r.ref.Part.Label(), err)
		return nil, false
	}
	o := r.p.opts
	if o.MaxArchiveEntries > 0 && len(zr.File) > o.MaxArchiveEntries {
		r.add("archive_entries", "media.decompression_bomb", core.SeverityCritical,
			"%s has %d archive entries, limit is %d", r.ref.Part.Label(), len(zr.File), o.MaxArchiveEntries)
		return nil, false
	}
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
		if f.Flags&0x1 != 0 {
			r.add("encrypted_archive", "media.encrypted", core.SeverityMedium, "%s contains encrypted entries (%s) that cannot be inspected", r.ref.Part.Label(), f.Name)
		}
		if f.CompressedSize64 > 0 && o.MaxCompression > 0 &&
			float64(f.UncompressedSize64)/float64(f.CompressedSize64) > o.MaxCompression && f.UncompressedSize64 > 1<<20 {
			r.add("compression_ratio", "media.decompression_bomb", core.SeverityCritical,
				"%s: entry %s expands %.0fx (limit %.0fx)", r.ref.Part.Label(), f.Name,
				float64(f.UncompressedSize64)/float64(f.CompressedSize64), o.MaxCompression)
			return nil, false
		}
	}
	if o.MaxUncompressed > 0 && total > uint64(o.MaxUncompressed) {
		r.add("uncompressed_size", "media.decompression_bomb", core.SeverityCritical,
			"%s expands to %d bytes, limit is %d", r.ref.Part.Label(), total, o.MaxUncompressed)
		return nil, false
	}
	return zr, true
}

// officeRisks flags what a document can do rather than say.
func (r *reader) officeRisks(names []string, files map[string]*zip.File) {
	label := r.ref.Part.Label()
	var embedded []string
	for _, n := range names {
		lower := strings.ToLower(n)
		switch {
		case strings.HasSuffix(lower, "vbaproject.bin"), strings.HasSuffix(lower, "vbadata.xml"),
			strings.HasPrefix(lower, "basic/"), strings.HasPrefix(lower, "scripts/"):
			r.add("macro", "document.macro", core.SeverityHigh, "%s contains a macro project (%s)", label, n)
		case strings.Contains(lower, "/embeddings/"), strings.Contains(lower, "/activex/"), strings.HasPrefix(lower, "object "):
			embedded = append(embedded, n)
		}
	}
	if len(embedded) > 0 {
		f := r.add("embedded_object", "document.embedded_file", core.SeverityMedium,
			"%s embeds %d object(s) or ActiveX controls", label, len(embedded))
		f.Meta["objects"] = strings.Join(embedded[:min(len(embedded), 5)], ",")
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".rels") {
			continue
		}
		rc, err := files[n].Open()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		for _, m := range externalRelRe.FindAllSubmatch(raw, -1) {
			relType, target := string(m[1]), string(m[2])
			t := path.Base(relType)
			switch t {
			case "hyperlink":
				continue // an ordinary link; the URL guards judge it in the text
			case "attachedTemplate", "oleObject", "frame", "subDocument", "externalLinkPath":
				f := r.add("remote_reference", "document.external_reference", core.SeverityHigh,
					"%s loads a %s from outside the file (%s), the remote-template technique", label, t, truncate(target, 80))
				f.Meta["target"] = truncate(target, 200)
			default:
				f := r.add("external_reference", "document.external_reference", core.SeverityLow,
					"%s references external content (%s: %s)", label, t, truncate(target, 80))
				f.Meta["target"] = truncate(target, 200)
			}
		}
	}
}

var externalRelRe = regexp.MustCompile(`<Relationship\b[^>]*?\bType="([^"]+)"[^>]*?\bTarget="([^"]+)"[^>]*?\bTargetMode="External"`)

var dangerousFormula = regexp.MustCompile(`(?i)(?:\bcmd\s*\||\bmsexcel\s*\||\bDDE(?:AUTO)?\b|\bWEBSERVICE\s*\(|\bFILTERXML\s*\(|\bIMPORTXML\s*\(|\bIMPORTDATA\s*\(|\bCALL\s*\(|\bREGISTER\s*\(|\bEXEC\s*\()`)

func (r *reader) formulaRisks(sheet string, raw []byte) {
	for _, m := range formulaRe.FindAllSubmatch(raw, 2000) {
		if len(m[1]) <= 4000 && dangerousFormula.Match(m[1]) {
			f := r.add("dangerous_formula", "document.active_content", core.SeverityHigh,
				"%s: %s has a formula that executes commands or calls the network", r.ref.Part.Label(), path.Base(sheet))
			f.Spans[0].Excerpt = truncate(xmlUnescape(string(m[1])), 120)
			return
		}
	}
}

// RE2 caps repeat counts at 1000; formula length is bounded by the 4000-byte
// check in formulaRisks instead.
var formulaRe = regexp.MustCompile(`<f\b[^>]*>([^<]+)</f>`)

var xmlEntities = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&", "&quot;", `"`, "&apos;", "'")

func xmlUnescape(s string) string { return xmlEntities.Replace(s) }

// wordText walks WordprocessingML, keeping paragraph structure and noticing
// runs a human reader would not see: <w:vanish/>, white text, sub-2pt type.
func (r *reader) wordText(raw []byte, where string) string {
	if len(raw) == 0 {
		return ""
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	var (
		b                    strings.Builder
		inRun, inRPr, inText bool
		vanish, white, tiny  bool
		hiddenChars          int
		sample               strings.Builder
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "r":
				inRun, vanish, white, tiny = true, false, false, false
			case "rPr":
				inRPr = inRun
			case "vanish", "specVanish", "webHidden":
				if inRPr && attrOr(t, "val", "true") != "false" && attrOr(t, "val", "1") != "0" {
					vanish = true
				}
			case "color":
				if inRPr {
					v := strings.ToUpper(attrOr(t, "val", ""))
					white = v == "FFFFFF" || v == "FEFEFE"
				}
			case "sz":
				if inRPr {
					if n, err := strconv.Atoi(attrOr(t, "val", "")); err == nil && n > 0 && n < 4 {
						tiny = true // half-points: under 2pt
					}
				}
			case "t", "delText", "instrText":
				inText = true
			case "tab":
				b.WriteByte('\t')
			case "br", "cr":
				b.WriteByte('\n')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "r":
				inRun = false
			case "rPr":
				inRPr = false
			case "t", "delText", "instrText":
				inText = false
			case "p":
				b.WriteByte('\n')
			}
		case xml.CharData:
			if !inText {
				continue
			}
			s := string(t)
			if vanish || white || tiny {
				hiddenChars += len(s)
				if sample.Len() < 200 {
					sample.WriteString(s)
				}
				r.hidden.WriteString(s)
				continue
			}
			b.WriteString(s)
		}
	}
	if hiddenChars > 0 {
		r.hiddenFinding(where+" (hidden, white or sub-2pt runs)", hiddenChars, sample.String())
	}
	return b.String()
}

func attrOr(t xml.StartElement, local, def string) string {
	for _, a := range t.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return def
}

// xmlText returns every character run in an XML document, with a newline at
// the end of each paragraph-like element.
func xmlText(raw []byte, paragraphs map[string]bool) string {
	if len(raw) == 0 {
		return ""
	}
	if paragraphs == nil {
		paragraphs = map[string]bool{"p": true, "si": true, "br": true, "comment": true}
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if paragraphs[t.Name.Local] {
				b.WriteByte('\n')
			}
		case xml.StartElement:
			if t.Name.Local == "tab" {
				b.WriteByte('\t')
			}
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				b.WriteString(string(t))
			}
		}
	}
	return b.String()
}

var inlineStrRe = regexp.MustCompile(`(?s)<is>(.*?)</is>`)

func inlineStrings(raw []byte) string {
	var b strings.Builder
	for _, m := range inlineStrRe.FindAllSubmatch(raw, -1) {
		b.WriteString(xmlText(m[1], nil))
		b.WriteByte('\n')
	}
	return b.String()
}

// archive lists a plain ZIP. Its members are not recursively extracted: a
// gateway that unpacks nested archives is a decompression service for
// whoever sends it one. The names are scanned, and the archive is reported
// as partially covered.
func (r *reader) archive(data []byte) {
	zr, ok := r.openZip(data)
	if !ok {
		return
	}
	r.ext.AddMethod("zip-listing")
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		lower := strings.ToLower(f.Name)
		for _, ext := range []string{".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".lnk", ".hta", ".msi", ".iso"} {
			if strings.HasSuffix(lower, ext) {
				r.add("executable_in_archive", "document.embedded_file", core.SeverityHigh,
					"%s contains an executable or script (%s)", r.ref.Part.Label(), f.Name)
				break
			}
		}
	}
	r.section("archive listing", strings.Join(names, "\n"))
	r.ext.Coverage = core.CoveragePartial
	r.add("archive_not_extracted", "media.partial_coverage", core.SeverityLow,
		"%s is an archive; its member names were inspected but its contents were not", r.ref.Part.Label())
}

// --- RTF -------------------------------------------------------------------------

var (
	rtfControl = regexp.MustCompile(`\\[a-zA-Z]+-?\d* ?|\\'[0-9a-fA-F]{2}|\\[^a-zA-Z]`)
	rtfObject  = regexp.MustCompile(`\\(?:object|objdata|objupdate|objemb|objlink|objautlink)\b`)
)

func (r *reader) rtf(data []byte) {
	r.ext.AddMethod("rtf")
	if rtfObject.Match(data) {
		r.add("rtf_object", "document.embedded_file", core.SeverityHigh,
			"%s embeds an OLE object (\\object/\\objdata), the vehicle of most RTF exploits", r.ref.Part.Label())
	}
	s := string(data)
	// Drop the font, colour and stylesheet tables, which are pure noise.
	for _, grp := range []string{`{\fonttbl`, `{\colortbl`, `{\stylesheet`, `{\*\`} {
		for {
			i := strings.Index(s, grp)
			if i < 0 {
				break
			}
			j := matchBrace(s, i)
			if j <= i {
				break
			}
			s = s[:i] + s[j+1:]
		}
	}
	s = rtfControl.ReplaceAllString(s, "")
	s = strings.NewReplacer("{", "", "}", "").Replace(s)
	r.section("", s)
	r.ext.Coverage = core.CoverageFull
}

func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// naturalLess orders "slide2.xml" before "slide10.xml".
func naturalLess(a, b string) bool {
	na, pa := trailingNumber(a)
	nb, pb := trailingNumber(b)
	if pa == pb && na >= 0 && nb >= 0 {
		return na < nb
	}
	return a < b
}

func trailingNumber(s string) (int, string) {
	base := strings.TrimSuffix(s, path.Ext(s))
	i := len(base)
	for i > 0 && base[i-1] >= '0' && base[i-1] <= '9' {
		i--
	}
	if i == len(base) {
		return -1, s
	}
	n, err := strconv.Atoi(base[i:])
	if err != nil {
		return -1, s
	}
	return n, base[:i] + path.Ext(s)
}

// fmtBytes is a compact size for messages.
func fmtBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
