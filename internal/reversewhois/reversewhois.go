package reversewhois

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	reDomain = regexp.MustCompile(`(?i)([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})`)
)

// LookupByEmail finds other domains registered with the same email via viewdns.info.
func LookupByEmail(email string) []string {
	url := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", email)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return parseViewDNS(string(body))
}

// LookupByDomain finds WHOIS email for the domain, then runs reverse lookup.
func LookupByDomain(domain string, timeout time.Duration) ([]string, string) {
	// Extract email from WHOIS using hackertarget's WHOIS API (free)
	url := fmt.Sprintf("https://api.hackertarget.com/whois/?q=%s", domain)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	// Find email in WHOIS output
	reEmail := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	emails := reEmail.FindAllString(string(body), -1)
	if len(emails) == 0 {
		return nil, ""
	}
	// Use first non-example email
	email := ""
	for _, e := range emails {
		if !strings.Contains(e, "example") && !strings.Contains(e, "dnsstuff") {
			email = strings.ToLower(e)
			break
		}
	}
	if email == "" {
		return nil, ""
	}
	return LookupByEmail(email), email
}

func parseViewDNS(body string) []string {
	// viewdns returns an HTML table with domain results
	seen := map[string]bool{}
	var results []string

	// Look for table rows containing domain entries
	// The results are in a table: <td>domain.com</td>
	reRow := regexp.MustCompile(`(?i)<td>([^<]{3,})</td>`)
	for _, m := range reRow.FindAllStringSubmatch(body, -1) {
		cell := strings.TrimSpace(m[1])
		if reDomain.MatchString(cell) && strings.Contains(cell, ".") &&
			!strings.Contains(cell, " ") && !seen[cell] {
			seen[cell] = true
			results = append(results, strings.ToLower(cell))
		}
	}
	return results
}
