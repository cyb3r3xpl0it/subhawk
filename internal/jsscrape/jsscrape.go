package jsscrape

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

var (
	reSrc      = regexp.MustCompile(`(?i)src=["']([^"']+\.js[^"']*)["']`)
	reURL      = regexp.MustCompile(`(?i)["']((?:https?:)?//[^"'<>\s]+)["']`)
	reEndpoint = regexp.MustCompile(`["'](/(?:api|v\d|graphql|rest|gql|auth|oauth|internal)[^"'<>\s]*)["']`)
	reSecret   = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["']([^"']{8,})["']`)

	commonJSPaths = []string{
		"/app.js", "/main.js", "/bundle.js", "/index.js",
		"/static/js/main.js", "/assets/js/app.js",
		"/js/app.js", "/js/main.js",
	}
)

type Result struct {
	JSFiles   []string
	Endpoints []string
	URLs      []string
	Secrets   []string
}

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func Scrape(subdomain string) *Result {
	baseURL := ""
	for _, scheme := range []string{"https", "http"} {
		u := fmt.Sprintf("%s://%s", scheme, subdomain)
		if body := fetch(u); body != "" {
			baseURL = u
			jsFiles := extractJSFiles(body, u)
			res := &Result{JSFiles: jsFiles}
			for _, jsURL := range append(jsFiles, commonJSURLs(u)...) {
				parseJS(jsURL, res)
			}
			dedupe(res)
			return res
		}
	}
	_ = baseURL
	return nil
}

func commonJSURLs(base string) []string {
	var out []string
	for _, p := range commonJSPaths {
		out = append(out, base+p)
	}
	return out
}

func fetch(u string) string {
	resp, err := client.Get(u)
	if err != nil || resp.StatusCode >= 400 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return string(body)
}

func extractJSFiles(html, base string) []string {
	seen := map[string]bool{}
	var files []string
	for _, m := range reSrc.FindAllStringSubmatch(html, -1) {
		jsURL := resolveURL(m[1], base)
		if jsURL != "" && !seen[jsURL] {
			seen[jsURL] = true
			files = append(files, jsURL)
		}
	}
	return files
}

func parseJS(jsURL string, res *Result) {
	body := fetch(jsURL)
	if body == "" {
		return
	}

	for _, m := range reEndpoint.FindAllStringSubmatch(body, -1) {
		res.Endpoints = append(res.Endpoints, m[1])
	}
	for _, m := range reURL.FindAllStringSubmatch(body, -1) {
		res.URLs = append(res.URLs, m[1])
	}
	for _, m := range reSecret.FindAllStringSubmatch(body, -1) {
		res.Secrets = append(res.Secrets, fmt.Sprintf("%s (in %s)", m[1], jsURL))
	}
}

func resolveURL(src, base string) string {
	if strings.HasPrefix(src, "//") {
		return "https:" + src
	}
	if strings.HasPrefix(src, "http") {
		return src
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(src)
	if err != nil {
		return ""
	}
	return u.ResolveReference(ref).String()
}

func dedupe(res *Result) {
	res.Endpoints = unique(res.Endpoints)
	res.URLs = unique(res.URLs)
	res.Secrets = unique(res.Secrets)
}

func unique(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
