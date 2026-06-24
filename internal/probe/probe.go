package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
)

var (
	reTitle = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	client  = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
)

// Probe checks HTTP/HTTPS on a subdomain and returns info about the service.
func Probe(subdomain string) *resolver.HTTPInfo {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)
		info := doRequest(url)
		if info != nil {
			return info
		}
	}
	return nil
}

func doRequest(url string) *resolver.HTTPInfo {
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // max 1MB

	info := &resolver.HTTPInfo{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
	}

	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		if m := reTitle.FindSubmatch(body); m != nil {
			info.Title = strings.TrimSpace(string(m[1]))
		}
	}

	return info
}
