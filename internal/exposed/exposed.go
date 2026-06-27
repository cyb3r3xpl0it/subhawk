package exposed

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type File struct {
	Path       string
	StatusCode int
	Size       int64
	URL        string
}

var SensitivePaths = []string{
	"/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.backup",
	"/.DS_Store", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
	"/.htpasswd", "/.htaccess", "/web.config", "/config.php", "/config.bak",
	"/wp-config.php", "/wp-config.php.bak", "/database.yml", "/secrets.yml",
	"/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa", "/server-status", "/phpinfo.php",
	"/info.php", "/test.php", "/debug.php", "/readme.txt", "/CHANGELOG.md",
	"/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
	"/robots.txt", "/.well-known/security.txt", "/crossdomain.xml",
	"/clientaccesspolicy.xml", "/sitemap.xml", "/.npmrc", "/.dockerignore",
	"/Dockerfile", "/docker-compose.yml",
}

func isIncluded(code int) bool {
	switch code {
	case 200, 206, 301, 302, 401, 403:
		return true
	}
	return false
}

func resolveBase(subdomain string, timeout time.Duration) string {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		base := fmt.Sprintf("%s://%s", scheme, subdomain)
		resp, err := client.Get(base)
		if err == nil {
			resp.Body.Close()
			return base
		}
	}
	return ""
}

func Scan(subdomain string, timeout time.Duration) []File {
	base := resolveBase(subdomain, timeout)
	if base == "" {
		return nil
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, 20)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []File

	for _, path := range SensitivePaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := base + p
			resp, err := client.Get(url)
			if err != nil {
				return
			}
			resp.Body.Close()

			if !isIncluded(resp.StatusCode) {
				return
			}

			size := resp.ContentLength
			if size < 0 {
				size = 0
			}

			mu.Lock()
			results = append(results, File{
				Path:       p,
				StatusCode: resp.StatusCode,
				Size:       size,
				URL:        url,
			})
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	return results
}
