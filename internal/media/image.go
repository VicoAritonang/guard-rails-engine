package media

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	_ "image/gif"  // register decoder for DecodeConfig
	_ "image/jpeg" // register decoder for DecodeConfig
	_ "image/png"  // register decoder for DecodeConfig
	"io"
	"strings"
	"sync"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// image handles a picture in four passes, cheapest first: dimensions (a
// pixel bomb is refused before anything decodes it), metadata (EXIF, XMP,
// PNG text chunks, JPEG comments -- a favourite hiding place for injected
// instructions, because no human ever looks there), trailing data (a ZIP or
// PDF glued after the image end marker), then the model-backed passes: OCR
// for the text in the pixels and image-safety classifiers for the picture
// itself.
func (r *reader) image(ctx context.Context, k kind) {
	data := r.ref.Part.Data
	label := r.ref.Part.Label()
	if k.format == "svg" {
		r.svg(data)
		return
	}

	w, h := imageSize(data, k.format)
	r.ext.Width, r.ext.Height = w, h
	if w > 0 && h > 0 {
		r.ext.AddMethod("header")
		if r.p.opts.MaxPixels > 0 && int64(w)*int64(h) > r.p.opts.MaxPixels {
			r.add("pixel_bomb", "media.decompression_bomb", core.SeverityCritical,
				"%s declares %dx%d pixels (%.0f MP), limit is %.0f MP", label, w, h,
				float64(w)*float64(h)/1e6, float64(r.p.opts.MaxPixels)/1e6)
			return
		}
	}

	if meta := imageMetadata(data, k.format); strings.TrimSpace(meta) != "" {
		r.ext.AddMethod("metadata")
		r.section("image metadata", meta)
		if len(meta) > 200 {
			f := r.add("metadata_text", "media.metadata_text", core.SeverityInfo,
				"%s carries %d characters of text in its metadata", label, len(meta))
			f.Spans[0].Excerpt = truncate(meta, 120)
		}
	}
	if tail := trailingBytes(data, k.format); tail > 1024 {
		rest := data[len(data)-tail:]
		what := "data"
		switch {
		case bytes.Contains(rest, []byte("PK\x03\x04")):
			what = "a ZIP archive"
		case bytes.Contains(rest, []byte("%PDF")):
			what = "a PDF"
		case bytes.Contains(rest, []byte("<script")), bytes.Contains(rest, []byte("<html")):
			what = "HTML or script"
		}
		r.add("trailing_data", "media.polyglot", core.SeverityMedium,
			"%s has %s of %s appended after the image end marker", label, fmtBytes(tail), what)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	if ocr := r.p.b.OCR; ocr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			text, err := ocr.ReadImage(ctx, data, r.ref.Part.MIME)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				r.warn("OCR failed: %v", err)
				return
			}
			r.ext.AddMethod("ocr:" + ocr.Name())
			if t := strings.TrimSpace(text); t != "" && !strings.EqualFold(t, "NONE") {
				r.section("text in image (OCR)", t)
			}
			r.ext.Coverage = core.CoverageFull
		}()
	}
	for _, c := range r.p.b.ImageSafety {
		wg.Add(1)
		go func(c ImageClassifier) {
			defer wg.Done()
			v, err := c.ClassifyImage(ctx, data, r.ref.Part.MIME)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				r.warn("image classifier %s failed: %v", c.Name(), err)
				return
			}
			r.ext.AddMethod("classify:" + c.Name())
			if !v.Unsafe {
				return
			}
			cat := v.Category
			if cat == "" {
				cat = "unsafe"
			}
			f := r.add("unsafe_image", "media.unsafe_image", core.SeverityHigh,
				"image classifier %s judged %s unsafe (%s)", c.Name(), label, cat)
			f.Score = v.Score
			f.Meta["classifier"] = c.Name()
			f.Meta["image_category"] = cat
			if v.Rationale != "" {
				f.Meta["rationale"] = truncate(v.Rationale, 200)
			}
		}(c)
	}
	wg.Wait()

	if r.p.b.OCR == nil {
		r.ext.Coverage = core.CoveragePartial
		r.add("pixels_not_read", "media.partial_coverage", core.SeverityLow,
			"text inside the pixels of %s was not read: no OCR backend is configured (GUARDRAILS_MEDIA_OCR)", label)
	} else if r.ext.Coverage != core.CoverageFull {
		r.ext.Coverage = core.CoveragePartial
		r.add("ocr_failed", "media.partial_coverage", core.SeverityMedium, "OCR of %s failed; the text in its pixels was not read", label)
	}
}

// imageSize reads dimensions from the header without decoding pixels.
func imageSize(data []byte, format string) (int, int) {
	switch format {
	case "png", "jpeg", "gif":
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err == nil {
			return cfg.Width, cfg.Height
		}
	case "webp":
		return webpSize(data)
	case "bmp":
		if len(data) >= 26 {
			w := int(int32(binary.LittleEndian.Uint32(data[18:22])))
			h := int(int32(binary.LittleEndian.Uint32(data[22:26])))
			if h < 0 {
				h = -h
			}
			return w, h
		}
	}
	return 0, 0
}

func webpSize(d []byte) (int, int) {
	if len(d) < 30 {
		return 0, 0
	}
	switch string(d[12:16]) {
	case "VP8X":
		w := 1 + int(d[24]) | int(d[25])<<8 | int(d[26])<<16
		h := 1 + int(d[27]) | int(d[28])<<8 | int(d[29])<<16
		return w, h
	case "VP8L":
		b := d[21:25]
		w := 1 + int(b[0]) | (int(b[1])&0x3F)<<8
		h := 1 + (int(b[1])>>6 | int(b[2])<<2 | (int(b[3])&0x0F)<<10)
		return w, h
	case "VP8 ":
		w := int(binary.LittleEndian.Uint16(d[26:28]) & 0x3FFF)
		h := 0
		if len(d) >= 30 {
			h = int(binary.LittleEndian.Uint16(d[28:30]) & 0x3FFF)
		}
		return w, h
	}
	return 0, 0
}

// imageMetadata collects every human-readable string an image carries
// outside its pixels.
func imageMetadata(data []byte, format string) string {
	var b strings.Builder
	add := func(label, s string) {
		s = strings.TrimSpace(strings.Map(func(r rune) rune {
			if r == 0 {
				return ' '
			}
			return r
		}, s))
		if s == "" || b.Len() > 16<<10 {
			return
		}
		if label != "" {
			b.WriteString(label + ": ")
		}
		b.WriteString(s + "\n")
	}
	switch format {
	case "png":
		pngChunks(data, add)
	case "jpeg":
		jpegSegments(data, add)
	case "gif":
		gifComments(data, add)
	case "webp":
		riffChunks(data[min(len(data), 12):], add)
	}
	return b.String()
}

func pngChunks(d []byte, add func(string, string)) {
	i := 8
	for i+12 <= len(d) {
		n := int(binary.BigEndian.Uint32(d[i : i+4]))
		typ := string(d[i+4 : i+8])
		if n < 0 || i+12+n > len(d) {
			return
		}
		body := d[i+8 : i+8+n]
		switch typ {
		case "tEXt":
			k, v, _ := bytes.Cut(body, []byte{0})
			add(string(k), string(v))
		case "zTXt":
			k, rest, _ := bytes.Cut(body, []byte{0})
			if len(rest) > 1 {
				add(string(k), inflate(rest[1:]))
			}
		case "iTXt":
			// keyword \0 compression-flag compression-method lang \0 translated \0 text
			k, rest, _ := bytes.Cut(body, []byte{0})
			if len(rest) < 2 {
				break
			}
			compressed := rest[0] == 1
			rest = rest[2:]
			_, rest, _ = bytes.Cut(rest, []byte{0})
			_, text, _ := bytes.Cut(rest, []byte{0})
			if compressed {
				add(string(k), inflate(text))
			} else {
				add(string(k), string(text))
			}
		case "eXIf":
			add("exif", printableRuns(body, 6))
		case "IEND":
			return
		}
		i += 12 + n
	}
}

func jpegSegments(d []byte, add func(string, string)) {
	i := 2
	for i+4 <= len(d) {
		if d[i] != 0xFF {
			return
		}
		marker := d[i+1]
		if marker == 0xD9 || marker == 0xDA { // EOI or start of scan: metadata is over
			return
		}
		if marker >= 0xD0 && marker <= 0xD7 || marker == 0x01 {
			i += 2
			continue
		}
		n := int(binary.BigEndian.Uint16(d[i+2 : i+4]))
		if n < 2 || i+2+n > len(d) {
			return
		}
		body := d[i+4 : i+2+n]
		switch {
		case marker == 0xFE:
			add("comment", string(body))
		case marker == 0xE1 && bytes.HasPrefix(body, []byte("Exif\x00\x00")):
			add("exif", printableRuns(body[6:], 6))
		case marker == 0xE1 && bytes.HasPrefix(body, []byte("http://ns.adobe.com/xap/1.0/\x00")):
			add("xmp", xmlText(body[29:], map[string]bool{"li": true, "Description": true}))
		case marker == 0xED: // Photoshop IPTC
			add("iptc", printableRuns(body, 6))
		}
		i += 2 + n
	}
}

func gifComments(d []byte, add func(string, string)) {
	for i := 0; i+2 < len(d); i++ {
		if d[i] != 0x21 || d[i+1] != 0xFE {
			continue
		}
		var b strings.Builder
		j := i + 2
		for j < len(d) {
			n := int(d[j])
			if n == 0 || j+1+n > len(d) {
				break
			}
			b.Write(d[j+1 : j+1+n])
			j += 1 + n
		}
		add("comment", b.String())
		i = j
	}
}

func riffChunks(d []byte, add func(string, string)) {
	for i := 0; i+8 <= len(d); {
		id := string(d[i : i+4])
		n := int(binary.LittleEndian.Uint32(d[i+4 : i+8]))
		if n < 0 || i+8+n > len(d) {
			return
		}
		body := d[i+8 : i+8+n]
		switch id {
		case "EXIF":
			add("exif", printableRuns(body, 6))
		case "XMP ":
			add("xmp", xmlText(body, map[string]bool{"li": true, "Description": true}))
		}
		i += 8 + n + n%2
	}
}

// trailingBytes counts bytes after the format's end marker.
func trailingBytes(d []byte, format string) int {
	switch format {
	case "png":
		if i := bytes.LastIndex(d, []byte("IEND")); i >= 0 && i+8 <= len(d) {
			return len(d) - (i + 8)
		}
	case "jpeg":
		if i := bytes.LastIndex(d, []byte{0xFF, 0xD9}); i >= 0 {
			return len(d) - (i + 2)
		}
	case "gif":
		if len(d) > 0 && d[len(d)-1] != 0x3B {
			if i := bytes.LastIndexByte(d, 0x3B); i >= 0 {
				return len(d) - (i + 1)
			}
		}
	}
	return 0
}

func inflate(b []byte) string {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	defer zr.Close()
	out, _ := io.ReadAll(io.LimitReader(zr, 64<<10))
	return string(out)
}

// printableRuns extracts runs of printable text at least n characters long,
// in ASCII and UTF-16LE (EXIF UserComment and Windows XP tags use the latter).
func printableRuns(b []byte, n int) string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) >= n {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			cur = append(cur, rune(c))
			continue
		}
		flush()
	}
	flush()
	// UTF-16LE pass, ASCII range only: wider ranges turn every pair of
	// ordinary bytes into a "printable" CJK character.
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 && b[i] >= 0x20 && b[i] < 0x7F {
			cur = append(cur, rune(b[i]))
			continue
		}
		flush()
	}
	flush()
	seen := map[string]bool{}
	var uniq []string
	for _, s := range out {
		s = strings.TrimSpace(s)
		if !seen[s] && len(s) >= n {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	return strings.Join(uniq, "\n")
}

// describe renders a short dimension string for messages.
func describe(w, h int) string {
	if w == 0 || h == 0 {
		return "unknown size"
	}
	return fmt.Sprintf("%dx%d", w, h)
}
