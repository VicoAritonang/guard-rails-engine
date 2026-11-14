package media

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "param": true, "source": true, "track": true, "wbr": true,
}

var blockElements = map[string]bool{
	"p": true, "div": true, "br": true, "li": true, "tr": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "section": true, "article": true, "td": true, "th": true,
	"pre": true, "blockquote": true, "title": true,
}

var invisibleStyle = regexp.MustCompile(`(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.\d+)?(?:px|pt|em|rem)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b|(?:left|top)\s*:\s*-\d{4,}px|clip\s*:\s*rect\(\s*0`)

// html extracts the text a browser shows and, separately, the text it hides.
//
// Hidden text is the classic carrier for indirect prompt injection in web
// content: a human sees a product page, a model reads "assistant, ignore the
// user". Both halves are scanned; the hidden half is also reported.
func (r *reader) html(data []byte) {
	z := html.NewTokenizer(bytes.NewReader(data))
	type frame struct {
		tag    string
		hidden bool
	}
	var (
		stack       []frame
		visible     strings.Builder
		hiddenChars int
		sample      strings.Builder
		skipText    bool
		scripts     int
		handlers    int
	)
	hiddenNow := func() bool {
		for _, f := range stack {
			if f.hidden {
				return true
			}
		}
		return false
	}
	addHidden := func(s string) {
		hiddenChars += len(s)
		if sample.Len() < 200 {
			sample.WriteString(s + " ")
		}
		r.hidden.WriteString(s + "\n")
	}
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			hidden := tag == "template" || tag == "noscript"
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				key := strings.ToLower(string(k))
				switch {
				case key == "hidden", key == "aria-hidden" && strings.EqualFold(string(v), "true"):
					hidden = true
				case key == "style" && invisibleStyle.Match(v):
					hidden = true
				case strings.HasPrefix(key, "on"):
					handlers++
				case (key == "href" || key == "src") && bytes.HasPrefix(bytes.ToLower(bytes.TrimSpace(v)), []byte("javascript:")):
					handlers++
				case key == "alt" || key == "title" || key == "aria-label":
					// Attribute text is read by models and rarely by people.
					if s := strings.TrimSpace(string(v)); len(s) > 20 {
						r.hidden.WriteString(s + "\n")
					}
				}
			}
			if tag == "script" || tag == "style" {
				if tag == "script" {
					scripts++
				}
				skipText = true
			}
			if tt == html.StartTagToken && !voidElements[tag] {
				stack = append(stack, frame{tag: tag, hidden: hidden})
			}
			if blockElements[tag] {
				visible.WriteByte('\n')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" {
				skipText = false
			}
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tag == tag {
					stack = stack[:i]
					break
				}
			}
			if blockElements[tag] {
				visible.WriteByte('\n')
			}
		case html.TextToken:
			if skipText {
				continue
			}
			s := strings.TrimSpace(html.UnescapeString(string(z.Text())))
			if s == "" {
				continue
			}
			if hiddenNow() {
				addHidden(s)
				continue
			}
			visible.WriteString(s + " ")
		case html.CommentToken:
			if s := strings.TrimSpace(string(z.Text())); len(s) > 3 {
				addHidden(s)
			}
		}
	}
	r.section("", collapseBlankLines(visible.String()))
	if hiddenChars > 0 {
		r.hiddenFinding("hidden elements, invisible styles or HTML comments", hiddenChars, sample.String())
	}
	if scripts > 0 || handlers > 0 {
		r.add("html_script", "document.active_content", core.SeverityMedium,
			"%s contains %d script block(s) and %d event handler(s) or javascript: link(s)", r.ref.Part.Label(), scripts, handlers)
	}
}

// svg reads an SVG image's text and flags what makes it more than a picture.
// An SVG is an XML document a browser will execute, which is why it is
// handled here rather than as pixels.
func (r *reader) svg(data []byte) {
	r.ext.AddMethod("svg")
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	var (
		b                          strings.Builder
		scripts, handlers, foreign int
		external                   []string
		depthScript                int
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch strings.ToLower(t.Name.Local) {
			case "script":
				scripts++
				depthScript++
			case "foreignobject":
				foreign++
			}
			for _, a := range t.Attr {
				k := strings.ToLower(a.Name.Local)
				v := strings.TrimSpace(a.Value)
				switch {
				case strings.HasPrefix(k, "on"):
					handlers++
				case k == "href" && strings.HasPrefix(strings.ToLower(v), "javascript:"):
					handlers++
				case k == "href" && (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "//")):
					external = append(external, v)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "script") && depthScript > 0 {
				depthScript--
			}
		case xml.CharData:
			if depthScript > 0 {
				continue
			}
			if s := strings.TrimSpace(string(t)); s != "" {
				b.WriteString(s + "\n")
			}
		case xml.Comment:
			if s := strings.TrimSpace(string(t)); len(s) > 3 {
				r.hidden.WriteString(s + "\n")
			}
		}
	}
	r.section("svg text", b.String())
	label := r.ref.Part.Label()
	if scripts > 0 || handlers > 0 {
		r.add("svg_script", "document.active_content", core.SeverityHigh,
			"%s is an SVG with %d script element(s) and %d event handler(s)", label, scripts, handlers)
	}
	if foreign > 0 {
		r.add("svg_foreign_object", "document.active_content", core.SeverityMedium,
			"%s embeds HTML through <foreignObject>", label)
	}
	if len(external) > 0 {
		f := r.add("svg_external", "document.external_reference", core.SeverityLow,
			"%s loads %d external resource(s)", label, len(external))
		f.Meta["target"] = truncate(external[0], 200)
	}
	r.ext.Coverage = core.CoverageFull
}

var blankLines = regexp.MustCompile(`\n[ \t]*\n(?:[ \t]*\n)+`)

func collapseBlankLines(s string) string {
	return blankLines.ReplaceAllString(s, "\n\n")
}
