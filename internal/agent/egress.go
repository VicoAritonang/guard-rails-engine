package agent

import (
	"net"
	"net/url"
	"strings"
)

// HostScope classifies a hostname by where it lives.
//
// It is shared by the tool broker and by the runtime tool-policy guard, which
// are two independent layers that both need the same answer. Two copies of this
// logic would drift, and the direction they drift in is always the same one:
// the copy nobody is looking at gets a new cloud provider's metadata address
// six months later than the other.
func HostScope(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return "unknown"
	}
	for _, m := range MetadataHosts {
		if h == m {
			return "metadata"
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "private"
		}
		return "public"
	}
	switch {
	case h == "localhost",
		strings.HasSuffix(h, ".local"),
		strings.HasSuffix(h, ".internal"),
		strings.HasSuffix(h, ".localhost"),
		!strings.Contains(h, "."):
		return "private"
	}
	return "public"
}

// MetadataHosts are the cloud instance-metadata endpoints. A tool call that
// reaches one of these is either SSRF or an agent that has been talked into
// stealing its own host's credentials.
var MetadataHosts = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.goog",
	"100.100.100.200",
	"fd00:ec2::254",
}

// Destination is a parsed egress target: a URL, an email address, or an opaque
// identifier such as a chat channel.
type Destination struct {
	Raw   string
	Kind  string // "url" | "email" | "opaque"
	Host  string // hostname for a URL, domain for an email
	Scope string // public | private | metadata | unknown
}

// ParseDestination interprets a destination argument.
func ParseDestination(raw string) Destination {
	v := strings.TrimSpace(raw)
	d := Destination{Raw: v, Kind: "opaque", Scope: "unknown"}
	if v == "" {
		return d
	}
	low := strings.ToLower(v)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			d.Kind, d.Host = "url", strings.ToLower(u.Hostname())
			d.Scope = HostScope(d.Host)
			return d
		}
	}
	// An address may arrive as "Name <user@example.com>".
	if i := strings.LastIndex(v, "<"); i >= 0 && strings.HasSuffix(v, ">") {
		v = strings.TrimSuffix(v[i+1:], ">")
		low = strings.ToLower(v)
	}
	if at := strings.LastIndex(low, "@"); at > 0 && at < len(low)-1 && strings.Contains(low[at:], ".") {
		d.Kind, d.Host = "email", low[at+1:]
		d.Scope = "public"
		return d
	}
	return d
}

// AllowedBy reports whether the destination matches an allowlist entry.
//
// Matching is suffix-based on domain labels, never plain string suffix. The
// difference matters: a plain suffix match on "example.com" also accepts
// "notexample.com", and registering that domain is a fifteen-dollar bypass of
// the entire egress control.
func (d Destination) AllowedBy(allowlist []string) bool {
	if len(allowlist) == 0 {
		return false
	}
	for _, entry := range allowlist {
		e := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(entry, "*.")))
		if e == "" {
			continue
		}
		if e == "*" {
			return true
		}
		switch d.Kind {
		case "url", "email":
			if d.Host == e || strings.HasSuffix(d.Host, "."+e) {
				return true
			}
		default:
			if strings.EqualFold(d.Raw, entry) {
				return true
			}
		}
	}
	return false
}
