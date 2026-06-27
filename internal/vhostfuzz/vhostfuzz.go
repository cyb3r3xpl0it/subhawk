package vhostfuzz

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

// Result holds the findings for a discovered virtual host.
type Result struct {
	VHost      string
	StatusCode int
	Title      string
	Length     int
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

func newClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

func probe(client *http.Client, ip, host string) (statusCode int, length int, title string, err error) {
	url := fmt.Sprintf("http://%s/", ip)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, "", err
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, 0, "", err
	}

	bodyStr := string(body)
	length = len(body)
	statusCode = resp.StatusCode

	if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		title = strings.TrimSpace(m[1])
	}

	return statusCode, length, title, nil
}

// Fuzz sends Host: {word}.{domain} to the target IP and returns vhosts that
// respond differently from the baseline. words is a slice of subdomain words
// to try. concurrency is max parallel requests.
func Fuzz(ip, domain string, words []string, timeout time.Duration, concurrency int) []Result {
	if concurrency <= 0 {
		concurrency = 20
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := newClient(timeout)

	baseStatus, baseLength, _, err := probe(client, ip, domain)
	if err != nil {
		baseStatus = 0
		baseLength = 0
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var results []Result
	var wg sync.WaitGroup

	for _, word := range words {
		word := word
		if word == "" {
			continue
		}
		vhost := fmt.Sprintf("%s.%s", word, domain)

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			status, length, title, err := probe(client, ip, vhost)
			if err != nil {
				return
			}

			diff := length - baseLength
			if diff < 0 {
				diff = -diff
			}

			if status != baseStatus || diff > 50 {
				mu.Lock()
				results = append(results, Result{
					VHost:      vhost,
					StatusCode: status,
					Title:      title,
					Length:     length,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results
}
