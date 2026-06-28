package pathdisc

import (
	"bufio"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Paths           []string // paths found (e.g. /admin, /api/v1)
	DisallowedPaths []string // paths disallowed in robots.txt
	SitemapURLs     []string // full URLs from sitemap
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func get(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512*1024))
}

func resolveBase(subdomain string) string {
	for _, scheme := range []string{"https", "http"} {
		resp, err := httpClient.Get(scheme + "://" + subdomain)
		if err == nil {
			resp.Body.Close()
			return scheme + "://" + subdomain
		}
	}
	return ""
}

func parseRobots(body string) (allowed, disallowed []string) {
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") {
			p := strings.TrimSpace(line[9:])
			if p != "" && p != "/" && !seen[p] {
				seen[p] = true
				disallowed = append(disallowed, p)
			}
		} else if strings.HasPrefix(lower, "allow:") {
			p := strings.TrimSpace(line[6:])
			if p != "" && !seen[p] {
				seen[p] = true
				allowed = append(allowed, p)
			}
		}
	}
	return
}

type sitemapURL struct {
	Loc string `xml:"loc"`
}
type sitemap struct {
	URLs []sitemapURL `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func parseSitemap(body []byte, base string) (paths, sitemapURLs []string) {
	var sm sitemap
	xml.Unmarshal(body, &sm)
	seen := map[string]bool{}
	for _, u := range sm.URLs {
		if u.Loc != "" {
			sitemapURLs = append(sitemapURLs, u.Loc)
			// Extract path
			path := u.Loc
			if idx := strings.Index(path, "://"); idx >= 0 {
				rest := path[idx+3:]
				if slash := strings.Index(rest, "/"); slash >= 0 {
					path = rest[slash:]
				} else {
					path = "/"
				}
			}
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}
	// Return nested sitemap locs for further fetching
	for _, s := range sm.Sitemaps {
		if s.Loc != "" {
			sitemapURLs = append(sitemapURLs, s.Loc)
		}
	}
	return
}

// Discover fetches robots.txt and sitemap.xml for the given subdomain.
func Discover(subdomain string, timeout time.Duration) *Result {
	base := resolveBase(subdomain)
	if base == "" {
		return nil
	}

	result := &Result{}
	seen := map[string]bool{}

	// robots.txt
	if body, err := get(base + "/robots.txt"); err == nil {
		allowed, disallowed := parseRobots(string(body))
		result.DisallowedPaths = disallowed
		for _, p := range append(allowed, disallowed...) {
			if !seen[p] {
				seen[p] = true
				result.Paths = append(result.Paths, p)
			}
		}
	}

	// sitemap.xml (and sitemap_index.xml)
	for _, sitemapPath := range []string{"/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"} {
		body, err := get(base + sitemapPath)
		if err != nil {
			continue
		}
		paths, urls := parseSitemap(body, base)
		result.SitemapURLs = append(result.SitemapURLs, urls...)
		for _, p := range paths {
			if !seen[p] {
				seen[p] = true
				result.Paths = append(result.Paths, p)
			}
		}
	}

	return result
}
