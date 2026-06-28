package webfuzz

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Hit struct {
	URL        string
	StatusCode int
	BodySize   int
	Title      string
	Redirect   string
}

type Result struct {
	BaseURL string
	Hits    []Hit
}

var defaultWordlist = []string{
	"admin", "api", "login", "logout", "dashboard", "config", "backup",
	"upload", "uploads", "files", "static", "assets", "images", "img",
	"js", "css", "fonts", "media", "docs", "documentation", "swagger",
	"graphql", "graphiql", "api-docs", "api/v1", "api/v2", "v1", "v2",
	"auth", "oauth", "sso", "register", "signup", "forgot-password",
	"reset-password", "profile", "account", "settings", "users", "user",
	"panel", "cpanel", "wp-admin", "wp-login.php", "administrator",
	"phpmyadmin", "adminer", "database", "db", "mysql", "phpinfo.php",
	"info.php", "test.php", "debug", "health", "status", "ping", "metrics",
	"actuator", "actuator/health", "actuator/env", "actuator/beans",
	"actuator/mappings", "console", "shell", "cmd", "exec",
	".env", ".git", ".git/HEAD", ".htaccess", ".htpasswd",
	"robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
	"server-status", "server-info", "nginx_status",
	"old", "bak", "backup.zip", "backup.tar.gz", "backup.sql",
	"dump.sql", "db.sql", "database.sql", "site.zip",
	"error", "errors", "log", "logs", "access.log", "error.log",
	"web.config", "app.config", "application.properties", "application.yml",
	"config.php", "config.json", "config.xml", "config.yaml",
	"credentials", "credential", "password", "passwords", "secret", "secrets",
	"private", "internal", "hidden", "temp", "tmp",
	"cgi-bin", "cgi-bin/test.cgi",
	"wp-content/uploads", "wp-json", "xmlrpc.php",
	"joomla", "drupal", "magento",
	"checkout", "cart", "payment", "invoice",
	"report", "reports", "export", "import",
	"search", "query", "find",
	"id_rsa", "id_rsa.pub", "authorized_keys",
	"composer.json", "package.json", "yarn.lock", "Gemfile",
	"Dockerfile", "docker-compose.yml", ".dockerignore",
	"Makefile", "README.md", "CHANGELOG.md", "LICENSE",
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // capture redirect without following
	},
}

// Fuzz performs directory/file fuzzing against the given subdomain.
// wordlistReader may be nil to use the built-in default wordlist.
// extensions: extra file extensions to try (e.g. []string{".php",".bak"})
// filterStatus: if non-empty, only return hits with these status codes.
// threads: concurrency level (default 20).
func Fuzz(subdomain string, wordlistReader io.Reader, extensions []string, filterStatus []int, threads int, timeout time.Duration) *Result {
	if threads <= 0 {
		threads = 20
	}

	// Build base URL
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

	// Build word list
	words := loadWords(wordlistReader)

	// Expand with extensions
	var entries []string
	for _, w := range words {
		entries = append(entries, w)
		for _, ext := range extensions {
			if !strings.Contains(w, ".") {
				entries = append(entries, w+ext)
			}
		}
	}

	statusFilter := map[int]bool{}
	for _, code := range filterStatus {
		statusFilter[code] = true
	}

	result := &Result{BaseURL: baseURL}
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, entry := range entries {
		entry := entry
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			target := baseURL + "/" + strings.TrimPrefix(entry, "/")
			hit := probe(target, statusFilter)
			if hit != nil {
				mu.Lock()
				result.Hits = append(result.Hits, *hit)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return result
}

func probe(url string, filterStatus map[int]bool) *Hit {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "subhawk/1.7")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Skip 404 and 400 by default; if filter is set, only include those
	if len(filterStatus) > 0 {
		if !filterStatus[resp.StatusCode] {
			return nil
		}
	} else {
		if resp.StatusCode == 404 || resp.StatusCode == 400 {
			return nil
		}
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(body)

	hit := &Hit{
		URL:        url,
		StatusCode: resp.StatusCode,
		BodySize:   len(body),
	}

	// Extract title
	if idx := strings.Index(strings.ToLower(bodyStr), "<title>"); idx != -1 {
		end := strings.Index(strings.ToLower(bodyStr[idx:]), "</title>")
		if end != -1 {
			hit.Title = strings.TrimSpace(bodyStr[idx+7 : idx+end])
			if len(hit.Title) > 80 {
				hit.Title = hit.Title[:80]
			}
		}
	}

	// Capture redirect location
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		hit.Redirect = resp.Header.Get("Location")
	}

	return hit
}

func loadWords(r io.Reader) []string {
	if r == nil {
		return defaultWordlist
	}
	var words []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	if len(words) == 0 {
		return defaultWordlist
	}
	return words
}

// String returns a compact summary for display.
func (r *Result) String() string {
	if r == nil || len(r.Hits) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, h := range r.Hits {
		line := fmt.Sprintf("  [%d] %s (%d bytes)", h.StatusCode, h.URL, h.BodySize)
		if h.Title != "" {
			line += fmt.Sprintf(" [%s]", h.Title)
		}
		if h.Redirect != "" {
			line += fmt.Sprintf(" -> %s", h.Redirect)
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}
