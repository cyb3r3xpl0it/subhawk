package httpmethods

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	URL              string
	AllowedMethods   []string // from OPTIONS Allow header
	DangerousMethods []string // subset: PUT, DELETE, TRACE, CONNECT, PATCH
	OptionsStatus    int
	Error            string
}

var dangerSet = map[string]bool{
	"PUT":     true,
	"DELETE":  true,
	"TRACE":   true,
	"CONNECT": true,
	"PATCH":   true,
}

var probeOrder = []string{"PUT", "DELETE", "TRACE", "PATCH", "DEBUG"}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Enumerate sends OPTIONS to the subdomain root and extracts allowed methods.
// It also probes dangerous methods individually when OPTIONS is absent/unhelpful.
func Enumerate(subdomain string, timeout time.Duration) *Result {
	var targetURL string
	for _, scheme := range []string{"https", "http"} {
		resp, err := httpClient.Get(scheme + "://" + subdomain + "/")
		if err == nil {
			resp.Body.Close()
			targetURL = scheme + "://" + subdomain + "/"
			break
		}
	}
	if targetURL == "" {
		return nil
	}

	result := &Result{URL: targetURL}

	// Send OPTIONS request
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "subhawk/1.7")

	resp, err := httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.OptionsStatus = resp.StatusCode

	// Parse Allow / Access-Control-Allow-Methods headers
	allowHdr := resp.Header.Get("Allow")
	if allowHdr == "" {
		allowHdr = resp.Header.Get("Access-Control-Allow-Methods")
	}

	if allowHdr != "" {
		for _, m := range strings.Split(allowHdr, ",") {
			method := strings.TrimSpace(strings.ToUpper(m))
			if method != "" {
				result.AllowedMethods = append(result.AllowedMethods, method)
				if dangerSet[method] {
					result.DangerousMethods = append(result.DangerousMethods, method)
				}
			}
		}
	}

	// If OPTIONS gave us nothing or returned 4xx, probe dangerous methods directly
	if len(result.AllowedMethods) == 0 || resp.StatusCode >= 400 {
		for _, method := range probeOrder {
			if alreadyFound(result.AllowedMethods, method) {
				continue
			}
			r, err := http.NewRequest(method, targetURL, nil)
			if err != nil {
				continue
			}
			r.Header.Set("User-Agent", "subhawk/1.7")
			pr, err := httpClient.Do(r)
			if err != nil {
				continue
			}
			pr.Body.Close()
			// If we get anything other than 405/501, the method is likely accepted
			if pr.StatusCode != 405 && pr.StatusCode != 501 && pr.StatusCode != 400 {
				result.AllowedMethods = append(result.AllowedMethods, method)
				if dangerSet[method] {
					result.DangerousMethods = append(result.DangerousMethods, method)
				}
			}
		}
	}

	if len(result.AllowedMethods) == 0 && result.Error == "" {
		return nil
	}
	return result
}

func alreadyFound(methods []string, m string) bool {
	for _, existing := range methods {
		if existing == m {
			return true
		}
	}
	return false
}
