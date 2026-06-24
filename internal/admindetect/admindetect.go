package admindetect

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var adminPaths = []string{
	"/admin", "/admin/", "/admin/login", "/admin/dashboard",
	"/administrator", "/administrator/index.php",
	"/wp-admin", "/wp-admin/", "/wp-login.php",
	"/login", "/signin", "/sign-in", "/auth", "/auth/login",
	"/panel", "/cpanel", "/control", "/control-panel",
	"/dashboard", "/dashboard/login",
	"/manage", "/management", "/manager",
	"/portal", "/portal/login",
	"/secure", "/secure/login",
	"/user/login", "/users/login", "/account/login",
	"/phpmyadmin", "/pma",
	"/jenkins", "/gitlab", "/grafana",
	"/console", "/web-console",
	"/api/admin", "/api/v1/admin",
}

var reTitle = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

type Panel struct {
	URL        string
	StatusCode int
	Title      string
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func Detect(subdomain string) []Panel {
	scheme := "https"
	if _, err := client.Get("https://" + subdomain); err != nil {
		scheme = "http"
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		panels  []Panel
		sem     = make(chan struct{}, 20)
	)

	for _, path := range adminPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf("%s://%s%s", scheme, subdomain, p)
			resp, err := client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Only interested in 200, 401, 403 — not 404/500
			if resp.StatusCode == 404 || resp.StatusCode >= 500 {
				return
			}

			title := ""
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			if m := reTitle.FindSubmatch(buf[:n]); m != nil {
				title = strings.TrimSpace(string(m[1]))
			}

			mu.Lock()
			panels = append(panels, Panel{
				URL:        url,
				StatusCode: resp.StatusCode,
				Title:      title,
			})
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	return panels
}
