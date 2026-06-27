package cdnbypass

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Result holds a discovered real IP and the technique used to find it.
type Result struct {
	IP       string
	Method   string // "spf", "mx", "historical-dns", "subdomain-leak"
	Verified bool   // true if HTTP probe to IP responds for this domain
}

var bypassSubdomains = []string{
	"direct", "mail", "smtp", "ftp", "cpanel", "webmail",
	"vpn", "remote", "origin", "direct-connect", "backend",
	"api", "admin", "portal", "server",
}

// Find attempts to discover the real IP behind a CDN-fronted domain.
func Find(domain string, timeout time.Duration) []Result {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Fetch baseline body length for verification
	baseline := fetchBaseline(httpClient, domain)

	type candidate struct {
		ip     string
		method string
	}

	var mu sync.Mutex
	seen := map[string]bool{}
	var candidates []candidate

	addCandidate := func(ip, method string) {
		ip = strings.TrimSpace(ip)
		if ip == "" || ip == "0.0.0.0" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !seen[ip] {
			seen[ip] = true
			candidates = append(candidates, candidate{ip: ip, method: method})
		}
	}

	var wg sync.WaitGroup

	// Technique 1: SPF record
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, ip := range spfIPs(domain) {
			addCandidate(ip, "spf")
		}
	}()

	// Technique 2: MX record
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, ip := range mxIPs(domain) {
			addCandidate(ip, "mx")
		}
	}()

	// Technique 3: Historical DNS via hackertarget
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, ip := range historicalIPs(httpClient, domain) {
			addCandidate(ip, "historical-dns")
		}
	}()

	// Technique 4: Common subdomains that bypass CDN
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, ip := range subdomainLeakIPs(domain) {
			addCandidate(ip, "subdomain-leak")
		}
	}()

	wg.Wait()

	// Verify candidates concurrently
	results := make([]Result, len(candidates))
	var verifyWg sync.WaitGroup
	for i, c := range candidates {
		verifyWg.Add(1)
		go func(idx int, cand candidate) {
			defer verifyWg.Done()
			results[idx] = Result{
				IP:       cand.ip,
				Method:   cand.method,
				Verified: verifyIP(httpClient, cand.ip, domain, baseline),
			}
		}(i, c)
	}
	verifyWg.Wait()

	return results
}

// spfIPs parses TXT records for the domain and extracts ip4: entries from SPF.
func spfIPs(domain string) []string {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}
	var ips []string
	for _, txt := range txts {
		lower := strings.ToLower(txt)
		if !strings.HasPrefix(lower, "v=spf1") {
			continue
		}
		fields := strings.Fields(txt)
		for _, f := range fields {
			f = strings.ToLower(f)
			if strings.HasPrefix(f, "ip4:") {
				raw := strings.TrimPrefix(f, "ip4:")
				// Strip CIDR notation if present
				if idx := strings.Index(raw, "/"); idx != -1 {
					raw = raw[:idx]
				}
				if net.ParseIP(raw) != nil {
					ips = append(ips, raw)
				}
			}
		}
	}
	return ips
}

// mxIPs resolves MX hosts for the domain to IPs.
func mxIPs(domain string) []string {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return nil
	}
	var ips []string
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if net.ParseIP(addr) != nil {
				ips = append(ips, addr)
			}
		}
	}
	return ips
}

// historicalIPs queries hackertarget.com for historical IP data.
func historicalIPs(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://hackertarget.com/api/hostsearch/?q=%s", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	// hackertarget returns lines like: hostname,ip
	// Also try JSON in case the API changes
	var ips []string
	seen := map[string]bool{}

	text := string(body)
	// Check for error or rate limit responses
	if strings.HasPrefix(strings.TrimSpace(text), "error") ||
		strings.HasPrefix(strings.TrimSpace(text), "API") {
		// Try viewdns as fallback
		return historicalIPsViewDNS(client, domain)
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			ip := strings.TrimSpace(parts[len(parts)-1])
			if net.ParseIP(ip) != nil && !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// historicalIPsViewDNS queries viewdns.info as a fallback for historical IPs.
func historicalIPsViewDNS(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=free&output=json", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}

	var result struct {
		Response struct {
			Records []struct {
				IP string `json:"ip"`
			} `json:"records"`
		} `json:"response"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var ips []string
	for _, rec := range result.Response.Records {
		ip := strings.TrimSpace(rec.IP)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// subdomainLeakIPs resolves common subdomains that often bypass CDN.
func subdomainLeakIPs(domain string) []string {
	seen := map[string]bool{}
	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, prefix := range bypassSubdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			host := sub + "." + domain
			addrs, err := net.LookupHost(host)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, addr := range addrs {
				if net.ParseIP(addr) != nil && !seen[addr] {
					seen[addr] = true
					ips = append(ips, addr)
				}
			}
		}(prefix)
	}
	wg.Wait()
	return ips
}

// fetchBaseline fetches the domain over HTTP/HTTPS and returns body length for comparison.
func fetchBaseline(client *http.Client, domain string) int {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if len(body) > 0 {
			return len(body)
		}
	}
	return 0
}

// verifyIP checks if the IP responds to HTTP requests with Host: domain header
// and compares body length to baseline to determine if it's the real server.
func verifyIP(client *http.Client, ip, domain string, baseline int) bool {
	for _, scheme := range []string{"http", "https"} {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		url := fmt.Sprintf("%s://%s:%s/", scheme, ip, port)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Host = domain
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subhawk)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == 0 {
			continue
		}

		// Consider verified if we get a non-error response
		if resp.StatusCode < 500 {
			// If we have a baseline, check body length similarity (within 20%)
			if baseline > 0 && len(body) > 0 {
				ratio := float64(len(body)) / float64(baseline)
				if ratio >= 0.8 && ratio <= 1.2 {
					return true
				}
				// Even if body differs, a 200 with content is a good sign
				if resp.StatusCode == 200 && len(body) > 512 {
					return true
				}
			} else if resp.StatusCode == 200 {
				return true
			}
		}
	}
	return false
}
