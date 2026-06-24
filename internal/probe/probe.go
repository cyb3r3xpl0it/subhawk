package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
)

var (
	reTitle = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	client  = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
)

type techSignature struct {
	name    string
	headers map[string]string // header name → substring
	body    string            // body substring
	cookie  string            // cookie name substring
}

var techSignatures = []techSignature{
	{name: "WordPress", body: "wp-content"},
	{name: "WordPress", body: "wp-includes"},
	{name: "Joomla", body: "joomla"},
	{name: "Drupal", headers: map[string]string{"X-Generator": "Drupal"}},
	{name: "Drupal", body: "drupal.js"},
	{name: "Laravel", cookie: "laravel_session"},
	{name: "Django", cookie: "csrftoken"},
	{name: "Ruby on Rails", headers: map[string]string{"X-Powered-By": "Phusion Passenger"}},
	{name: "PHP", headers: map[string]string{"X-Powered-By": "PHP"}},
	{name: "ASP.NET", headers: map[string]string{"X-Powered-By": "ASP.NET"}},
	{name: "ASP.NET", headers: map[string]string{"X-AspNet-Version": ""}},
	{name: "Cloudflare", headers: map[string]string{"CF-Ray": ""}},
	{name: "AWS CloudFront", headers: map[string]string{"X-Amz-Cf-Id": ""}},
	{name: "Varnish", headers: map[string]string{"X-Varnish": ""}},
	{name: "Nginx", headers: map[string]string{"Server": "nginx"}},
	{name: "Apache", headers: map[string]string{"Server": "Apache"}},
	{name: "IIS", headers: map[string]string{"Server": "Microsoft-IIS"}},
	{name: "Tomcat", headers: map[string]string{"Server": "Apache-Coyote"}},
	{name: "Node.js", headers: map[string]string{"X-Powered-By": "Express"}},
	{name: "Next.js", headers: map[string]string{"X-Powered-By": "Next.js"}},
	{name: "Shopify", body: "cdn.shopify.com"},
	{name: "WordPress.com", body: "wp.com"},
	{name: "Wix", body: "wix.com"},
	{name: "Squarespace", body: "squarespace.com"},
	{name: "HubSpot", headers: map[string]string{"X-HubSpot-Request-Id": ""}},
}

func Probe(subdomain string) *resolver.HTTPInfo {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)
		info := doRequest(url)
		if info != nil {
			return info
		}
	}
	return nil
}

func doRequest(url string) *resolver.HTTPInfo {
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := strings.ToLower(string(body))

	info := &resolver.HTTPInfo{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
	}

	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		if m := reTitle.FindSubmatch(body); m != nil {
			info.Title = strings.TrimSpace(string(m[1]))
		}
	}

	info.Tech = detectTech(resp, bodyStr)
	return info
}

func detectTech(resp *http.Response, body string) []string {
	seen := map[string]bool{}
	var tech []string

	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			tech = append(tech, name)
		}
	}

	for _, sig := range techSignatures {
		for hdr, val := range sig.headers {
			hv := resp.Header.Get(hdr)
			if hv != "" && (val == "" || strings.Contains(strings.ToLower(hv), strings.ToLower(val))) {
				add(sig.name)
			}
		}
		if sig.body != "" && strings.Contains(body, sig.body) {
			add(sig.name)
		}
		if sig.cookie != "" {
			for _, c := range resp.Cookies() {
				if strings.Contains(c.Name, sig.cookie) {
					add(sig.name)
				}
			}
		}
	}
	return tech
}
