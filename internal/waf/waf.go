package waf

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type fingerprint struct {
	name    string
	headers map[string]string
	cookies []string
	body    string
}

var fingerprints = []fingerprint{
	{
		name:    "Cloudflare",
		headers: map[string]string{"Server": "cloudflare", "CF-Ray": ""},
	},
	{
		name:    "AWS WAF",
		headers: map[string]string{"X-Cache": "Error from cloudfront", "x-amzn-RequestId": ""},
	},
	{
		name:    "Akamai",
		headers: map[string]string{"X-Check-Cacheable": "", "Akamai-Cache-Status": ""},
	},
	{
		name:    "Sucuri",
		headers: map[string]string{"X-Sucuri-ID": "", "X-Sucuri-Cache": ""},
	},
	{
		name:    "Imperva / Incapsula",
		headers: map[string]string{"X-Iinfo": ""},
		cookies: []string{"incap_ses", "visid_incap"},
	},
	{
		name:    "F5 BIG-IP ASM",
		cookies: []string{"TS"},
		headers: map[string]string{"X-WA-Info": ""},
	},
	{
		name:    "Barracuda",
		cookies: []string{"barra_counter_session"},
	},
	{
		name:    "Fortinet FortiWeb",
		cookies: []string{"FORTIWAFSID"},
	},
	{
		name:    "Wordfence",
		cookies: []string{"wfvt_"},
	},
	{
		name:    "ModSecurity",
		body:    "Mod_Security",
	},
	{
		name:    "Radware AppWall",
		headers: map[string]string{"X-SL-CompState": ""},
	},
	{
		name:    "Reblaze",
		cookies: []string{"rbzid"},
	},
	{
		name:    "DDoS-Guard",
		headers: map[string]string{"Server": "ddos-guard"},
	},
	{
		name:    "Fastly WAF",
		headers: map[string]string{"Fastly-WAF-Blocked": ""},
	},
}

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Detect returns the WAF name or empty string.
func Detect(subdomain string) string {
	for _, scheme := range []string{"https", "http"} {
		name := probe(fmt.Sprintf("%s://%s", scheme, subdomain))
		if name != "" {
			return name
		}
	}
	return ""
}

func probe(url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()

	bodyStr := strings.ToLower(string(body))

	for _, fp := range fingerprints {
		for hdr, val := range fp.headers {
			hv := strings.ToLower(resp.Header.Get(hdr))
			if hv != "" && (val == "" || strings.Contains(hv, strings.ToLower(val))) {
				return fp.name
			}
		}
		for _, cookie := range fp.cookies {
			for _, c := range resp.Cookies() {
				if strings.HasPrefix(strings.ToLower(c.Name), strings.ToLower(cookie)) {
					return fp.name
				}
			}
		}
		if fp.body != "" && strings.Contains(bodyStr, strings.ToLower(fp.body)) {
			return fp.name
		}
	}
	return ""
}
