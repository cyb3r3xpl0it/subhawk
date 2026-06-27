package buckets

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Bucket struct {
	URL      string
	Provider string
	Name     string
	Public   bool
	Writable bool
}

func generateNames(domain string) []string {
	// Strip TLD
	parts := strings.Split(domain, ".")
	base := parts[0]
	if len(parts) > 2 {
		base = strings.Join(parts[:len(parts)-1], "-")
	}

	suffixes := []string{
		"",
		"-dev",
		"-staging",
		"-backup",
		"-assets",
		"-static",
		"-media",
		"-uploads",
		"-data",
		"-logs",
		"-cdn",
		"-files",
	}

	names := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		names = append(names, base+s)
	}
	return names
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func checkS3(client *http.Client, name string) *Bucket {
	url := fmt.Sprintf("https://%s.s3.amazonaws.com", name)
	resp, err := client.Head(url)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil
	case http.StatusOK:
		b := &Bucket{
			URL:      url,
			Provider: "s3",
			Name:     name,
			Public:   true,
		}
		// Check writability
		putURL := fmt.Sprintf("%s/write-test", url)
		req, err := http.NewRequest(http.MethodPut, putURL, bytes.NewBufferString("test"))
		if err == nil {
			putResp, err := client.Do(req)
			if err == nil {
				putResp.Body.Close()
				if putResp.StatusCode == http.StatusOK || putResp.StatusCode == http.StatusNoContent {
					b.Writable = true
				}
			}
		}
		return b
	case http.StatusForbidden:
		return &Bucket{
			URL:      url,
			Provider: "s3",
			Name:     name,
			Public:   false,
		}
	default:
		return nil
	}
}

func checkGCS(client *http.Client, name string) *Bucket {
	url := fmt.Sprintf("https://storage.googleapis.com/%s", name)
	resp, err := client.Head(url)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil
	case http.StatusOK:
		return &Bucket{
			URL:      url,
			Provider: "gcs",
			Name:     name,
			Public:   true,
		}
	case http.StatusForbidden:
		return &Bucket{
			URL:      url,
			Provider: "gcs",
			Name:     name,
			Public:   false,
		}
	default:
		return nil
	}
}

func checkAzure(client *http.Client, name string) *Bucket {
	url := fmt.Sprintf("https://%s.blob.core.windows.net", name)
	resp, err := client.Head(url)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil
	case http.StatusOK, http.StatusBadRequest:
		return &Bucket{
			URL:      url,
			Provider: "azure",
			Name:     name,
			Public:   true,
		}
	default:
		return nil
	}
}

func Check(domain string, timeout time.Duration) []Bucket {
	names := generateNames(domain)
	client := newClient(timeout)

	type job struct {
		name     string
		provider string
	}

	jobs := make(chan job, len(names)*3)
	results := make(chan *Bucket, len(names)*3)

	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup

	for _, name := range names {
		for _, provider := range []string{"s3", "gcs", "azure"} {
			jobs <- job{name: name, provider: provider}
		}
	}
	close(jobs)

	for j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var b *Bucket
			switch j.provider {
			case "s3":
				b = checkS3(client, j.name)
			case "gcs":
				b = checkGCS(client, j.name)
			case "azure":
				b = checkAzure(client, j.name)
			}
			results <- b
		}(j)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var buckets []Bucket
	for b := range results {
		if b != nil {
			buckets = append(buckets, *b)
		}
	}

	return buckets
}
