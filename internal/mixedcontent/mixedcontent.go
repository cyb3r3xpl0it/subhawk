package mixedcontent

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	// Match src="http://..." href="http://..." url(http://...)
	reSrc = regexp.MustCompile(`(?i)(?:src|href|action|data-src)\s*=\s*["']?(http://[^"'\s>]+)`)
	reURL = regexp.MustCompile(`(?i)url\s*\(\s*["']?(http://[^"'\s)]+)`)
)

// Check fetches the HTTPS page and looks for HTTP resource references (mixed content).
func Check(subdomain string, timeout time.Duration) []string {
	resp, err := httpClient.Get("https://" + subdomain)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	page := string(body)

	seen := map[string]bool{}
	var results []string
	for _, m := range append(reSrc.FindAllStringSubmatch(page, -1), reURL.FindAllStringSubmatch(page, -1)...) {
		if len(m) < 2 {
			continue
		}
		u := strings.TrimSpace(m[1])
		// Skip localhost and 127.0.0.1
		if strings.Contains(u, "localhost") || strings.Contains(u, "127.0.0.1") {
			continue
		}
		if !seen[u] {
			seen[u] = true
			results = append(results, u)
		}
	}
	return results
}
