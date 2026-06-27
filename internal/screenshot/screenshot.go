package screenshot

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Result holds the outcome of a screenshot attempt.
type Result struct {
	Subdomain string
	URL       string
	Path      string // path to saved PNG file
	Error     string
}

// sanitize replaces dots and slashes with underscores for use as a filename.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

// Take captures a screenshot of the given subdomain and saves it to outputDir.
// It tries https:// first, then http://.
func Take(subdomain string, outputDir string, timeout time.Duration) Result {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return Result{
			Subdomain: subdomain,
			Error:     fmt.Sprintf("failed to create output directory: %v", err),
		}
	}

	urls := []string{
		"https://" + subdomain,
		"http://" + subdomain,
	}

	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("ignore-certificate-errors", true),
	}

	for _, u := range urls {
		path, err := captureScreenshot(u, subdomain, outputDir, timeout, allocOpts)
		if err == nil {
			return Result{
				Subdomain: subdomain,
				URL:       u,
				Path:      path,
			}
		}
	}

	return Result{
		Subdomain: subdomain,
		Error:     fmt.Sprintf("failed to capture screenshot for %s (tried https and http)", subdomain),
	}
}

// captureScreenshot performs the actual chromedp screenshot capture.
func captureScreenshot(url, subdomain, outputDir string, timeout time.Duration, allocOpts []chromedp.ExecAllocatorOption) (string, error) {
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	defer cancel()

	ctx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.FullScreenshot(&buf, 90),
	)
	if err != nil {
		return "", fmt.Errorf("chromedp run failed for %s: %w", url, err)
	}

	filename := sanitize(subdomain) + ".png"
	path := outputDir + "/" + filename

	if err := os.WriteFile(path, buf, 0644); err != nil {
		return "", fmt.Errorf("failed to write screenshot to %s: %w", path, err)
	}

	return path, nil
}

// TakeBulk takes screenshots of multiple subdomains concurrently.
// concurrency limits parallel Chrome instances (default 3 if <= 0).
func TakeBulk(subdomains []string, outputDir string, timeout time.Duration, concurrency int) []Result {
	if concurrency <= 0 {
		concurrency = 3
	}

	results := make([]Result, len(subdomains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, subdomain := range subdomains {
		wg.Add(1)
		go func(idx int, sd string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = Take(sd, outputDir, timeout)
		}(i, subdomain)
	}

	wg.Wait()
	return results
}
