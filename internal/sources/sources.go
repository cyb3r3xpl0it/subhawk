package sources

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Source interface {
	Name() string
	Enumerate(domain string) ([]string, error)
}

var client = &http.Client{Timeout: 20 * time.Second}

func get(u string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SubHawk/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func filterSubs(entries []string, domain string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		e = strings.TrimSpace(strings.TrimPrefix(e, "*."))
		if e != "" && strings.HasSuffix(e, domain) && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

// ---- crt.sh ----

type CRTsh struct{}

func (s *CRTsh) Name() string { return "crt.sh" }

func (s *CRTsh) Enumerate(domain string) ([]string, error) {
	data, err := get(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain), nil)
	if err != nil {
		return nil, err
	}
	var entries []struct{ NameValue string `json:"name_value"` }
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	var all []string
	for _, e := range entries {
		all = append(all, strings.Split(e.NameValue, "\n")...)
	}
	return filterSubs(all, domain), nil
}

// ---- AlienVault OTX ----

type AlienVault struct{}

func (s *AlienVault) Name() string { return "alienvault" }

func (s *AlienVault) Enumerate(domain string) ([]string, error) {
	data, err := get(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		PassiveDNS []struct{ Hostname string `json:"hostname"` } `json:"passive_dns"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	var all []string
	for _, e := range resp.PassiveDNS {
		all = append(all, e.Hostname)
	}
	return filterSubs(all, domain), nil
}

// ---- HackerTarget ----

type HackerTarget struct{}

func (s *HackerTarget) Name() string { return "hackertarget" }

func (s *HackerTarget) Enumerate(domain string) ([]string, error) {
	data, err := get(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain), nil)
	if err != nil {
		return nil, err
	}
	var all []string
	for _, line := range strings.Split(string(data), "\n") {
		if parts := strings.SplitN(line, ",", 2); len(parts) >= 1 {
			all = append(all, parts[0])
		}
	}
	return filterSubs(all, domain), nil
}

// ---- RapidDNS ----

type RapidDNS struct{}

func (s *RapidDNS) Name() string { return "rapiddns" }

func (s *RapidDNS) Enumerate(domain string) ([]string, error) {
	data, err := get(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", domain), nil)
	if err != nil {
		return nil, err
	}
	var all []string
	for _, line := range strings.Split(string(data), "\n") {
		all = append(all, strings.TrimSpace(line))
	}
	return filterSubs(all, domain), nil
}

// ---- URLScan.io ----

type URLScan struct{}

func (s *URLScan) Name() string { return "urlscan" }

func (s *URLScan) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain),
		nil,
	)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Results []struct {
			Page struct{ Domain string `json:"domain"` } `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	var all []string
	for _, r := range resp.Results {
		all = append(all, r.Page.Domain)
	}
	return filterSubs(all, domain), nil
}

// ---- Wayback Machine ----

type Wayback struct{}

func (s *Wayback) Name() string { return "wayback" }

func (s *Wayback) Enumerate(domain string) ([]string, error) {
	u := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=100000",
		domain,
	)
	data, err := get(u, nil)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var results []string
	for _, line := range strings.Split(string(data), "\n") {
		parsed, err := url.Parse(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		h := parsed.Hostname()
		if h != "" && strings.HasSuffix(h, "."+domain) && !seen[h] {
			seen[h] = true
			results = append(results, h)
		}
	}
	return results, nil
}

// ---- ThreatMiner ----

type ThreatMiner struct{}

func (s *ThreatMiner) Name() string { return "threatminer" }

func (s *ThreatMiner) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain),
		nil,
	)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return filterSubs(resp.Results, domain), nil
}

// ---- VirusTotal ----

type VirusTotal struct{ APIKey string }

func (s *VirusTotal) Name() string { return "virustotal" }

func (s *VirusTotal) Enumerate(domain string) ([]string, error) {
	var all []string
	cursor := ""
	for {
		u := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
		if cursor != "" {
			u += "&cursor=" + cursor
		}
		data, err := get(u, map[string]string{"x-apikey": s.APIKey})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Data []struct{ ID string `json:"id"` } `json:"data"`
			Meta struct{ Cursor string `json:"cursor"` } `json:"meta"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, err
		}
		for _, d := range resp.Data {
			all = append(all, d.ID)
		}
		if resp.Meta.Cursor == "" || len(resp.Data) == 0 {
			break
		}
		cursor = resp.Meta.Cursor
	}
	return filterSubs(all, domain), nil
}

// ---- SecurityTrails ----

type SecurityTrails struct{ APIKey string }

func (s *SecurityTrails) Name() string { return "securitytrails" }

func (s *SecurityTrails) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=true", domain),
		map[string]string{"APIKEY": s.APIKey},
	)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	var all []string
	for _, sub := range resp.Subdomains {
		all = append(all, sub+"."+domain)
	}
	return filterSubs(all, domain), nil
}

// ---- Shodan ----

type Shodan struct{ APIKey string }

func (s *Shodan) Name() string { return "shodan" }

func (s *Shodan) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, s.APIKey),
		nil,
	)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	var all []string
	for _, sub := range resp.Subdomains {
		all = append(all, sub+"."+domain)
	}
	return filterSubs(all, domain), nil
}

// ---- Censys ----

type Censys struct {
	APIID     string
	APISecret string
}

func (s *Censys) Name() string { return "censys" }

func (s *Censys) Enumerate(domain string) ([]string, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(s.APIID + ":" + s.APISecret))
	data, err := get(
		fmt.Sprintf("https://search.censys.io/api/v2/certificates/search?q=parsed.names%%3A%s&per_page=100", domain),
		map[string]string{"Authorization": "Basic " + auth},
	)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result struct {
			Hits []struct {
				ParsedNames []string `json:"parsed.names"`
			} `json:"hits"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	var all []string
	for _, hit := range resp.Result.Hits {
		all = append(all, hit.ParsedNames...)
	}
	return filterSubs(all, domain), nil
}

// ---- TLS Certificate Scraper ----

type TLSScrape struct{}

func (s *TLSScrape) Name() string { return "tls" }

func (s *TLSScrape) Enumerate(domain string) ([]string, error) {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", domain+":443", conf,
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var all []string
	for _, cert := range conn.ConnectionState().PeerCertificates {
		for _, san := range cert.DNSNames {
			all = append(all, strings.TrimPrefix(san, "*."))
		}
	}
	return filterSubs(all, domain), nil
}

// ---- Wordlist ----

type Wordlist struct{ Path string }

func (s *Wordlist) Name() string { return "wordlist" }

func (s *Wordlist) Enumerate(domain string) ([]string, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			results = append(results, fmt.Sprintf("%s.%s", word, domain))
		}
	}
	return results, scanner.Err()
}

// ---- Builder ----

type Options struct {
	WordlistPath   string
	VirusTotalKey  string
	SecurityTrailsKey string
	ShodanKey      string
	CensysID       string
	CensysSecret   string
}

func All(opts Options) []Source {
	srcs := []Source{
		&CRTsh{},
		&AlienVault{},
		&HackerTarget{},
		&RapidDNS{},
		&URLScan{},
		&TLSScrape{},
		&Wayback{},
		&ThreatMiner{},
	}
	if opts.WordlistPath != "" {
		srcs = append(srcs, &Wordlist{Path: opts.WordlistPath})
	}
	if opts.VirusTotalKey != "" {
		srcs = append(srcs, &VirusTotal{APIKey: opts.VirusTotalKey})
	}
	if opts.SecurityTrailsKey != "" {
		srcs = append(srcs, &SecurityTrails{APIKey: opts.SecurityTrailsKey})
	}
	if opts.ShodanKey != "" {
		srcs = append(srcs, &Shodan{APIKey: opts.ShodanKey})
	}
	if opts.CensysID != "" && opts.CensysSecret != "" {
		srcs = append(srcs, &Censys{APIID: opts.CensysID, APISecret: opts.CensysSecret})
	}
	return srcs
}
