package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// audio transcribes speech so the text guards can read it. A spoken
// jailbreak is a jailbreak; the voice channel is not a side door.
func (r *reader) audio(ctx context.Context, k kind) {
	data := r.ref.Part.Data
	label := r.ref.Part.Label()
	if r.ref.Part.Format == "" {
		r.ref.Part.Format = k.format
	}

	if k.format == "wav" {
		if secs, ok := wavSeconds(data); ok {
			r.ext.Seconds = secs
			r.ext.AddMethod("header")
		}
	}
	if r.p.opts.MaxAudioSeconds > 0 && r.ext.Seconds > r.p.opts.MaxAudioSeconds {
		r.add("audio_length", "media.size_limit", core.SeverityHigh,
			"%s is %.0f s long, limit is %.0f s", label, r.ext.Seconds, r.p.opts.MaxAudioSeconds)
		return
	}
	if k.format == "mp3" {
		if tags := id3Text(data); tags != "" {
			r.ext.AddMethod("id3")
			r.section("audio tags", tags)
		}
	}
	r.transcribe(ctx, label, core.CoverageFull)
}

// video reads what can be read without a frame decoder: the audio track.
// The frames themselves are not inspected, and the report says so.
func (r *reader) video(ctx context.Context, _ kind) {
	label := r.ref.Part.Label()
	r.transcribe(ctx, label, core.CoveragePartial)
	if r.ext.Coverage != core.CoverageNone {
		r.add("frames_not_read", "media.partial_coverage", core.SeverityLow,
			"the audio track of %s was transcribed; its frames were not inspected", label)
	}
}

func (r *reader) transcribe(ctx context.Context, label string, onSuccess core.Coverage) {
	t := r.p.b.Transcriber
	if t == nil {
		r.add("no_transcriber", "media.unscannable", core.SeverityMedium,
			"%s was not transcribed: no speech-to-text backend is configured (GUARDRAILS_MEDIA_TRANSCRIBE)", label)
		return
	}
	text, err := t.Transcribe(ctx, r.ref.Part.Data, r.ref.Part.MIME, filenameFor(r.ref.Part))
	if err != nil {
		r.add("transcription_failed", "media.unscannable", core.SeverityMedium, "%s could not be transcribed: %v", label, err)
		return
	}
	r.ext.AddMethod("transcribe:" + t.Name())
	r.section("transcript", text)
	r.ext.Coverage = onSuccess
}

func filenameFor(p *core.Part) string {
	if p.Name != "" {
		return p.Name
	}
	ext := p.Format
	if ext == "" {
		for e, k := range extKinds {
			if k.mime == p.MIME {
				ext = strings.TrimPrefix(e, ".")
				break
			}
		}
	}
	if ext == "" {
		ext = "bin"
	}
	return "upload." + ext
}

// wavSeconds reads the duration from the fmt and data chunks.
func wavSeconds(d []byte) (float64, bool) {
	if len(d) < 12 {
		return 0, false
	}
	var byteRate uint32
	for i := 12; i+8 <= len(d); {
		id := string(d[i : i+4])
		n := binary.LittleEndian.Uint32(d[i+4 : i+8])
		switch id {
		case "fmt ":
			if i+8+12 <= len(d) {
				byteRate = binary.LittleEndian.Uint32(d[i+16 : i+20])
			}
		case "data":
			if byteRate == 0 {
				return 0, false
			}
			size := n
			if int(n) > len(d)-(i+8) || n == 0xFFFFFFFF {
				size = uint32(len(d) - (i + 8))
			}
			return float64(size) / float64(byteRate), true
		}
		i += 8 + int(n) + int(n%2)
		if n > uint32(len(d)) {
			break
		}
	}
	return 0, false
}

// id3Text reads the text frames of an ID3v2 tag (title, comment, lyrics).
func id3Text(d []byte) string {
	if len(d) < 10 || !bytes.HasPrefix(d, []byte("ID3")) {
		return ""
	}
	size := int(d[6]&0x7F)<<21 | int(d[7]&0x7F)<<14 | int(d[8]&0x7F)<<7 | int(d[9]&0x7F)
	end := min(10+size, len(d))
	var b strings.Builder
	for i := 10; i+10 <= end; {
		id := string(d[i : i+4])
		n := int(binary.BigEndian.Uint32(d[i+4 : i+8]))
		if d[3] == 4 { // v2.4 uses synchsafe frame sizes
			n = int(d[i+4]&0x7F)<<21 | int(d[i+5]&0x7F)<<14 | int(d[i+6]&0x7F)<<7 | int(d[i+7]&0x7F)
		}
		if n <= 0 || i+10+n > end || id[0] == 0 {
			break
		}
		if id[0] == 'T' || id == "COMM" || id == "USLT" {
			if s := printableRuns(d[i+10:i+10+n], 3); s != "" {
				b.WriteString(id + ": " + strings.ReplaceAll(s, "\n", " ") + "\n")
			}
		}
		i += 10 + n
	}
	return b.String()
}
