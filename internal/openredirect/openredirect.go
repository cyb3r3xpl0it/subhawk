package openredirect

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Result holds details about a detected open redirect vulnerability.
type Result struct {
	URL    string // the URL that has the redirect
	Param  string // the vulnerable parameter
	Target string // where it redirected to
}

var testParams = []string{
	"url", "next", "redirect", "redir", "return", "returnUrl", "return_url",
	"goto", "target", "dest", "destination", "link", "out", "view", "to",
	"image_url", "go", "r", "redirect_uri", "redirect_url", "callback",
}

const payload = "https://evil.subhawk.test"

var metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^;]*;\s*url=([^"'>\s]+)`)

func newClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func resolveBase(subdomain string, client *http.Client) string {
	for _, scheme := range []string{"https", "http"} {
		u := fmt.Sprintf("%s://%s", scheme, subdomain)
		resp, err := client.Get(u)
		if err == nil {
			resp.Body.Close()
			return u
		}
	}
	return ""
}

func checkBody(body string) string {
	matches := metaRefreshRe.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// Check tests a subdomain for open redirects by injecting the payload into common parameters.
func Check(subdomain string, timeout time.Duration) []Result {
	client := newClient(timeout)
	baseURL := resolveBase(subdomain, client)
	if baseURL == "" {
		return nil
	}

	type work struct {
		param string
	}

	jobs := make(chan work, len(testParams))
	for _, p := range testParams {
		jobs <- work{param: p}
	}
	close(jobs)

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
	)

	concurrency := 5
	if len(testParams) < concurrency {
		concurrency = len(testParams)
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				testURL := fmt.Sprintf("%s?%s=%s", baseURL, j.param, payload)
				resp, err := client.Get(testURL)
				if err != nil {
					continue
				}

				target := ""

				// Check Location header
				loc := resp.Header.Get("Location")
				if strings.Contains(loc, "evil.subhawk.test") {
					target = loc
				}

				// Check meta-refresh in body if not already found
				if target == "" {
					bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					resp.Body.Close()
					if err == nil {
						if t := checkBody(string(bodyBytes)); strings.Contains(t, "evil.subhawk.test") {
							target = t
						}
					}
				} else {
					resp.Body.Close()
				}

				if target != "" {
					mu.Lock()
					results = append(results, Result{
						URL:    testURL,
						Param:  j.param,
						Target: target,
					})
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return results
}
