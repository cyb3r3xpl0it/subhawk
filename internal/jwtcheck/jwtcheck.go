package jwtcheck

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type JWTFinding struct {
	Token     string // first 40 chars only
	Algorithm string
	Issues    []string // "alg:none", "weak-alg", "exposed-in-response"
	Claims    map[string]interface{}
}

type Result struct {
	Findings []JWTFinding
}

var (
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*`)
)

func decodeBase64(s string) []byte {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	data, _ := base64.URLEncoding.DecodeString(s)
	if data == nil {
		data, _ = base64.StdEncoding.DecodeString(s)
	}
	return data
}

func analyzeToken(token string) JWTFinding {
	finding := JWTFinding{}
	if len(token) > 40 {
		finding.Token = token[:40] + "..."
	} else {
		finding.Token = token
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return finding
	}

	// Decode header
	headerData := decodeBase64(parts[0])
	var header map[string]interface{}
	if err := json.Unmarshal(headerData, &header); err == nil {
		if alg, ok := header["alg"].(string); ok {
			finding.Algorithm = alg
			alg = strings.ToLower(alg)
			if alg == "none" || alg == "" {
				finding.Issues = append(finding.Issues, "alg:none — signature not verified")
			} else if alg == "hs256" || alg == "hs384" || alg == "hs512" {
				finding.Issues = append(finding.Issues, "HMAC-only — may be vulnerable to secret brute-force")
			}
		}
	}

	// Decode payload
	payloadData := decodeBase64(parts[1])
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadData, &claims); err == nil {
		finding.Claims = claims
		// Check for sensitive claim names
		sensitiveKeys := []string{"password", "secret", "key", "token", "api_key", "admin"}
		for _, k := range sensitiveKeys {
			for claimKey := range claims {
				if strings.Contains(strings.ToLower(claimKey), k) {
					finding.Issues = append(finding.Issues, "sensitive claim: "+claimKey)
				}
			}
		}
	}

	// No signature = potential alg:none
	if parts[2] == "" {
		finding.Issues = append(finding.Issues, "empty signature (alg:none candidate)")
	}

	finding.Issues = append(finding.Issues, "exposed-in-response")
	return finding
}

// Check fetches the subdomain and extracts any JWT tokens from the response body and headers.
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	// Search in body + Authorization header
	searchIn := string(body)
	for _, v := range resp.Header {
		searchIn += " " + strings.Join(v, " ")
	}

	tokens := reJWT.FindAllString(searchIn, -1)
	if len(tokens) == 0 {
		return nil
	}

	result := &Result{}
	seen := map[string]bool{}
	for _, t := range tokens {
		if seen[t] {
			continue
		}
		seen[t] = true
		result.Findings = append(result.Findings, analyzeToken(t))
	}
	return result
}
