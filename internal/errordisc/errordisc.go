package errordisc

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Finding struct {
	URL         string
	Type        string // "debug-endpoint", "stack-trace", "version-disclosure", "error-page", "config-exposure"
	Description string
	StatusCode  int
	Evidence    string
}

type Result struct {
	Subdomain string
	Findings  []Finding
}

// Debug/admin endpoints to probe
var debugPaths = []struct {
	path string
	desc string
	kind string
}{
	{"/actuator", "Spring Boot Actuator", "debug-endpoint"},
	{"/actuator/health", "Spring Boot health check", "debug-endpoint"},
	{"/actuator/env", "Spring Boot environment (secrets!)", "debug-endpoint"},
	{"/actuator/beans", "Spring Boot beans", "debug-endpoint"},
	{"/actuator/mappings", "Spring Boot URL mappings", "debug-endpoint"},
	{"/actuator/httptrace", "Spring Boot HTTP traces", "debug-endpoint"},
	{"/actuator/dump", "Spring Boot thread dump", "debug-endpoint"},
	{"/_ah/admin", "Google App Engine admin console", "debug-endpoint"},
	{"/_ah/stats", "Google App Engine stats", "debug-endpoint"},
	{"/debug/pprof", "Go pprof debug endpoint", "debug-endpoint"},
	{"/debug/pprof/heap", "Go pprof heap", "debug-endpoint"},
	{"/debug/vars", "Go expvar endpoint", "debug-endpoint"},
	{"/metrics", "Prometheus metrics", "debug-endpoint"},
	{"/metrics/", "Prometheus metrics (trailing slash)", "debug-endpoint"},
	{"/__admin__", "Django admin (guessed path)", "debug-endpoint"},
	{"/__debug__", "Django debug panel", "debug-endpoint"},
	{"/rails/info", "Rails info endpoint", "debug-endpoint"},
	{"/rails/info/properties", "Rails properties", "debug-endpoint"},
	{"/info", "Generic info endpoint", "debug-endpoint"},
	{"/phpinfo.php", "PHP info page", "debug-endpoint"},
	{"/info.php", "PHP info page", "debug-endpoint"},
	{"/test.php", "PHP test page", "debug-endpoint"},
	{"/console", "Web console", "debug-endpoint"},
	{"/jolokia", "Jolokia JMX bridge", "debug-endpoint"},
	{"/jolokia/list", "Jolokia JMX list", "debug-endpoint"},
	{"/swagger-ui.html", "Swagger UI", "debug-endpoint"},
	{"/swagger-ui/", "Swagger UI", "debug-endpoint"},
	{"/api-docs", "API documentation", "debug-endpoint"},
	{"/v2/api-docs", "Swagger v2 API docs", "debug-endpoint"},
	{"/v3/api-docs", "OpenAPI v3 docs", "debug-endpoint"},
	{"/graphiql", "GraphiQL explorer", "debug-endpoint"},
	{"/graphql/playground", "GraphQL Playground", "debug-endpoint"},
	{"/trace", "Trace endpoint", "debug-endpoint"},
	{"/error", "Error page", "error-page"},
	{"/errors", "Errors listing", "error-page"},
	{"/server-status", "Apache server status", "debug-endpoint"},
	{"/server-info", "Apache server info", "debug-endpoint"},
	{"/nginx_status", "nginx status", "debug-endpoint"},
	{"/status", "Status endpoint", "debug-endpoint"},
	{"/_profiler", "Symfony profiler", "debug-endpoint"},
	{"/_profiler/phpinfo", "Symfony phpinfo", "debug-endpoint"},
	{"/telescope", "Laravel Telescope", "debug-endpoint"},
	{"/horizon", "Laravel Horizon", "debug-endpoint"},
	{"/horizon/api/stats", "Laravel Horizon stats", "debug-endpoint"},
}

// Patterns indicating stack traces or version disclosure in response body
var stackTracePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)at\s+\w[\w.$]+\s*\(`),            // Java stack trace
	regexp.MustCompile(`(?i)Traceback \(most recent call`),    // Python traceback
	regexp.MustCompile(`(?i)Exception in thread`),             // Java exception
	regexp.MustCompile(`(?i)Fatal error:.*in\s+/`),            // PHP fatal error
	regexp.MustCompile(`(?i)stack trace:|stacktrace`),         // Generic stack trace
	regexp.MustCompile(`(?i)goroutine \d+ \[running\]`),       // Go panic
	regexp.MustCompile(`(?i)NullPointerException`),            // Java NPE
	regexp.MustCompile(`(?i)RuntimeException|SQLException`),   // Java exceptions
	regexp.MustCompile(`(?i)ActiveRecord::|ActionController:`), // Rails errors
	regexp.MustCompile(`(?i)undefined method .* for nil`),     // Ruby nil error
	regexp.MustCompile(`(?i)NameError|TypeError|ValueError`),  // Python errors
	regexp.MustCompile(`(?i)SyntaxError|ReferenceError`),      // JS errors
	regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`),                 // PDO SQL error
	regexp.MustCompile(`(?i)mysql_num_rows|mysql_connect`),    // Old PHP MySQL
	regexp.MustCompile(`(?i)ORA-\d{5}`),                       // Oracle error
	regexp.MustCompile(`(?i)pg_connect|pg_query|PostgreSQL`),  // PostgreSQL error
}

var versionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Apache[/ ]([\d.]+)`),
	regexp.MustCompile(`(?i)nginx/([\d.]+)`),
	regexp.MustCompile(`(?i)PHP/([\d.]+)`),
	regexp.MustCompile(`(?i)Server: .*/([\d.]+)`),
	regexp.MustCompile(`(?i)X-Powered-By: .*([\d.]+)`),
	regexp.MustCompile(`(?i)Tomcat/([\d.]+)`),
	regexp.MustCompile(`(?i)JBoss.*/([\d.]+)`),
	regexp.MustCompile(`(?i)Spring Framework ([\d.]+)`),
	regexp.MustCompile(`(?i)Django/([\d.]+)`),
	regexp.MustCompile(`(?i)Rails ([\d.]+)`),
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Check probes the subdomain for debug endpoints, stack traces, and version disclosure.
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

	// Check all response headers for version disclosure
	resp, err := httpClient.Get(baseURL + "/")
	if err == nil {
		defer resp.Body.Close()
		for name, vals := range resp.Header {
			val := strings.Join(vals, "; ")
			for _, pat := range versionPatterns {
				if m := pat.FindString(val); m != "" {
					result.Findings = append(result.Findings, Finding{
						URL:         baseURL + "/",
						Type:        "version-disclosure",
						Description: fmt.Sprintf("Version in %s header", name),
						StatusCode:  resp.StatusCode,
						Evidence:    m,
					})
					break
				}
			}
		}
	}

	// Probe debug paths concurrently
	type job struct {
		path string
		desc string
		kind string
	}
	jobs := make(chan job, len(debugPaths))
	results := make(chan Finding, len(debugPaths)*2)

	for i := 0; i < 15; i++ {
		go func() {
			for j := range jobs {
				f := probeDebug(baseURL+j.path, j.desc, j.kind)
				if f != nil {
					results <- *f
				}
			}
		}()
	}

	for _, dp := range debugPaths {
		jobs <- job{dp.path, dp.desc, dp.kind}
	}
	close(jobs)

	// Drain results
	for i := 0; i < len(debugPaths); i++ {
		select {
		case f := <-results:
			result.Findings = append(result.Findings, f)
		case <-time.After(15 * time.Second):
		}
	}

	if len(result.Findings) == 0 {
		return nil
	}
	return result
}

func probeDebug(url, desc, kind string) *Finding {
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

	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 410 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	bodyStr := string(body)

	finding := &Finding{
		URL:         url,
		Type:        kind,
		Description: desc,
		StatusCode:  resp.StatusCode,
	}

	// Look for stack traces in response
	for _, pat := range stackTracePatterns {
		if m := pat.FindString(bodyStr); m != "" {
			finding.Type = "stack-trace"
			finding.Description += " (stack trace detected)"
			finding.Evidence = truncate(m, 120)
			break
		}
	}

	// Look for version disclosure in body
	if finding.Evidence == "" {
		for _, pat := range versionPatterns {
			if m := pat.FindString(bodyStr); m != "" {
				finding.Description += " (version disclosure)"
				finding.Evidence = truncate(m, 80)
				break
			}
		}
	}

	return finding
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
