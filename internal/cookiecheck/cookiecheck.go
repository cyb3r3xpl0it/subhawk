package cookiecheck

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CookieIssue struct {
	Name  string
	Issue string // "missing-httponly", "missing-secure", "missing-samesite", "samesite-none-no-secure"
	Value string // partial cookie value for context
}

type Result struct {
	Issues []CookieIssue
	Total  int
	Secure int // cookies with all flags set correctly
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// Check fetches the root path of subdomain and analyzes Set-Cookie headers.
func Check(subdomain string, timeout time.Duration) *Result {
	var resp *http.Response
	var err error
	for _, scheme := range []string{"https", "http"} {
		resp, err = httpClient.Get(scheme + "://" + subdomain)
		if err == nil {
			break
		}
	}
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return nil
	}

	result := &Result{Total: len(cookies)}
	for _, raw := range cookies {
		parts := strings.Split(raw, ";")
		if len(parts) == 0 {
			continue
		}
		nameVal := strings.SplitN(parts[0], "=", 2)
		name := strings.TrimSpace(nameVal[0])
		lower := strings.ToLower(raw)

		hasHTTPOnly := strings.Contains(lower, "httponly")
		hasSecure := strings.Contains(lower, "secure")
		hasSameSite := strings.Contains(lower, "samesite")
		sameSiteNone := strings.Contains(lower, "samesite=none")

		cookieOK := true
		if !hasHTTPOnly {
			result.Issues = append(result.Issues, CookieIssue{Name: name, Issue: "missing-httponly"})
			cookieOK = false
		}
		if !hasSecure {
			result.Issues = append(result.Issues, CookieIssue{Name: name, Issue: "missing-secure"})
			cookieOK = false
		}
		if !hasSameSite {
			result.Issues = append(result.Issues, CookieIssue{Name: name, Issue: "missing-samesite"})
			cookieOK = false
		}
		if sameSiteNone && !hasSecure {
			result.Issues = append(result.Issues, CookieIssue{Name: name, Issue: "samesite-none-no-secure"})
			cookieOK = false
		}
		if cookieOK {
			result.Secure++
		}
	}
	return result
}
