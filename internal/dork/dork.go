package dork

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func get(u string) string {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body)
}

func extractSubs(body, domain string) []string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllString(body, -1)
	seen := map[string]bool{}
	var result []string
	for _, m := range matches {
		m = strings.ToLower(strings.TrimSpace(m))
		if !seen[m] && m != domain {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}

// Bing scrapes Bing search results for subdomains using site: dork.
func Bing(domain string, maxPages int) []string {
	if maxPages <= 0 {
		maxPages = 5
	}
	seen := map[string]bool{}
	var all []string

	for page := 1; page <= maxPages; page++ {
		first := (page-1)*10 + 1
		q := url.QueryEscape(fmt.Sprintf("site:%s", domain))
		u := fmt.Sprintf("https://www.bing.com/search?q=%s&first=%d", q, first)
		body := get(u)
		if body == "" {
			break
		}
		added := 0
		for _, s := range extractSubs(body, domain) {
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
				added++
			}
		}
		if added == 0 {
			break
		}
	}
	return all
}

// Google scrapes Google search results for subdomains.
func Google(domain string, maxPages int) []string {
	if maxPages <= 0 {
		maxPages = 5
	}
	seen := map[string]bool{}
	var all []string

	for page := 0; page < maxPages; page++ {
		start := page * 10
		q := url.QueryEscape(fmt.Sprintf("site:%s -www", domain))
		u := fmt.Sprintf("https://www.google.com/search?q=%s&start=%d&num=100", q, start)
		body := get(u)
		if body == "" {
			break
		}
		added := 0
		for _, s := range extractSubs(body, domain) {
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
				added++
			}
		}
		if added == 0 {
			break
		}
	}
	return all
}

// Dork runs both Google and Bing dorking and returns unique subdomains.
func Dork(domain string) []string {
	seen := map[string]bool{}
	var all []string
	for _, s := range append(Bing(domain, 5), Google(domain, 5)...) {
		if !seen[s] {
			seen[s] = true
			all = append(all, s)
		}
	}
	return all
}
