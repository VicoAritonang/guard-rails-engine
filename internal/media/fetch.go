package media

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// safeHTTPClient refuses to connect to any address that is not public
// unicast. The check runs at dial time, on the resolved IP, so it also covers
// redirects and DNS names that resolve to 169.254.169.254: checking the URL
// string would miss both.
func safeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !publicIP(ip) {
				return fmt.Errorf("refusing to fetch from non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			Proxy:                 nil,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConns:          8,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() ||
		// 100.64.0.0/10 carrier-grade NAT and the IPv4-mapped forms of the above.
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xC0 == 64))
}

// fetch downloads a remote part within the size limit.
func (p *Processor) fetch(ctx context.Context, raw string) ([]byte, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.opts.FetchAllowHTTP {
			return nil, "", errors.New("plain http URLs are not fetched (media.fetch_allow_http)")
		}
	default:
		return nil, "", fmt.Errorf("URL scheme %q is not fetched", u.Scheme)
	}
	if u.User != nil {
		return nil, "", errors.New("URLs with credentials are not fetched")
	}
	if len(p.opts.FetchAllowHosts) > 0 && !hostAllowed(u.Hostname(), p.opts.FetchAllowHosts) {
		return nil, "", fmt.Errorf("host %s is not in media.fetch_allow_hosts", u.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "guard-rails-engine/media-fetch")
	resp, err := p.b.HTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, "", fmt.Errorf("fetch returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(p.opts.MaxPartBytes)+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > p.opts.MaxPartBytes {
		return nil, "", fmt.Errorf("remote content exceeds %d bytes", p.opts.MaxPartBytes)
	}
	return data, strings.Split(resp.Header.Get("Content-Type"), ";")[0], nil
}

// hostAllowed matches exact hosts and "*.example.com" suffix patterns.
func hostAllowed(host string, allow []string) bool {
	host = strings.ToLower(host)
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(a, "*."); ok && strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
