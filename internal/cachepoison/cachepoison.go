package cachepoison

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Finding struct {
	URL         string
	Technique   string // "x-forwarded-host", "x-host", "x-forwarded-server", "x-original-url", "x-rewrite-url"
	Reflected   bool   // injected value appeared in body/location
	CacheHeader string // value of X-Cache or Age header (proves caching)
	Evidence    string // snippet of where it was reflected
}

type Result struct {
	Subdomain string
	Findings  []Finding
	Cached    bool // any cache headers observed
}

var httpClient = &http.Client{
	Timeout: 12 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Check probes the subdomain for cache poisoning vulnerabilities.
func Check(subdomain string, timeout time.Duration) *Result {
	var baseURL string
	for _, scheme := range []string{"https", "http"} {
		resp, err := httpClient.Get(scheme + "://" + subdomain + "/")
		if err == nil {
			resp.Body.Close()
			baseURL = scheme + "://" + subdomain
			break
		}
	}
	if baseURL == "" {
		return nil
	}

	result := &Result{Subdomain: subdomain}
	poison := "cache-probe.evil.com"

	// Injection headers to test
	techniques := []struct {
		header string
		name   string
	}{
		{"X-Forwarded-Host", "x-forwarded-host"},
		{"X-Host", "x-host"},
		{"X-Forwarded-Server", "x-forwarded-server"},
		{"X-Original-URL", "x-original-url"},
		{"X-Rewrite-URL", "x-rewrite-url"},
		{"X-Forwarded-For", "x-forwarded-for"},
	}

	// Baseline request (no injection)
	baseResp, err := httpClient.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 64*1024))
	baseResp.Body.Close()
	baseBodyStr := string(baseBody)

	// Check if already cached
	if age := baseResp.Header.Get("Age"); age != "" && age != "0" {
		result.Cached = true
	}
	if xc := baseResp.Header.Get("X-Cache"); strings.Contains(strings.ToLower(xc), "hit") {
		result.Cached = true
	}

	for _, tech := range techniques {
		req, err := http.NewRequest("GET", baseURL+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "subhawk/1.7")
		req.Header.Set(tech.header, poison)

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		bodyStr := string(body)

		finding := Finding{
			URL:       baseURL + "/",
			Technique: tech.name,
		}

		// Check if injected value reflected in body
		if strings.Contains(bodyStr, poison) && !strings.Contains(baseBodyStr, poison) {
			finding.Reflected = true
			// Extract snippet around the reflection
			idx := strings.Index(bodyStr, poison)
			start := idx - 40
			if start < 0 {
				start = 0
			}
			end := idx + len(poison) + 40
			if end > len(bodyStr) {
				end = len(bodyStr)
			}
			finding.Evidence = "..." + bodyStr[start:end] + "..."
		}

		// Check if injected value reflected in Location header
		if loc := resp.Header.Get("Location"); strings.Contains(loc, poison) {
			finding.Reflected = true
			finding.Evidence = fmt.Sprintf("Location: %s", loc)
		}

		// Record cache indicators
		if xc := resp.Header.Get("X-Cache"); xc != "" {
			finding.CacheHeader = "X-Cache: " + xc
			result.Cached = true
		}
		if age := resp.Header.Get("Age"); age != "" && age != "0" {
			if finding.CacheHeader != "" {
				finding.CacheHeader += " | "
			}
			finding.CacheHeader += "Age: " + age
			result.Cached = true
		}
		if cf := resp.Header.Get("CF-Cache-Status"); cf != "" {
			if finding.CacheHeader != "" {
				finding.CacheHeader += " | "
			}
			finding.CacheHeader += "CF-Cache-Status: " + cf
		}

		if finding.Reflected {
			result.Findings = append(result.Findings, finding)
		}
	}

	if len(result.Findings) == 0 && !result.Cached {
		return nil
	}
	return result
}
