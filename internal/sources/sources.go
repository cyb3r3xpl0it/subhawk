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
	"regexp"
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

// ---- Chaos (ProjectDiscovery) ----

type Chaos struct{ APIKey string }

func (s *Chaos) Name() string { return "chaos" }

func (s *Chaos) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain),
		map[string]string{"X-API-Key": s.APIKey},
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

// ---- CommonCrawl ----

type CommonCrawl struct{}

func (s *CommonCrawl) Name() string { return "commoncrawl" }

func (s *CommonCrawl) Enumerate(domain string) ([]string, error) {
	// Step 1: get the latest index CDX API endpoint
	indexData, err := get("http://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return nil, err
	}
	var indexes []struct {
		CDXAPI string `json:"cdx-api"`
	}
	if err := json.Unmarshal(indexData, &indexes); err != nil {
		return nil, err
	}
	if len(indexes) == 0 {
		return nil, fmt.Errorf("no CommonCrawl indexes found")
	}
	cdxAPI := indexes[0].CDXAPI

	// Step 2: query the CDX API for subdomains
	u := fmt.Sprintf("%s?url=*.%s&output=json&fl=url&limit=5000", cdxAPI, domain)
	data, err := get(u, nil)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		parsed, err := url.Parse(obj.URL)
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

// ---- FullHunt ----

type FullHunt struct{ APIKey string }

func (s *FullHunt) Name() string { return "fullhunt" }

func (s *FullHunt) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain),
		map[string]string{"X-API-KEY": s.APIKey},
	)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return filterSubs(resp.Hosts, domain), nil
}

// ---- Bevigil ----

type Bevigil struct{ APIKey string }

func (s *Bevigil) Name() string { return "bevigil" }

func (s *Bevigil) Enumerate(domain string) ([]string, error) {
	data, err := get(
		fmt.Sprintf("https://osint.bevigil.com/api/%s/subdomains/", domain),
		map[string]string{"X-Access-Token": s.APIKey},
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
	return filterSubs(resp.Subdomains, domain), nil
}

// ---- LeakIX ----

type LeakIX struct{ APIKey string }

func (s *LeakIX) Name() string { return "leakix" }

func (s *LeakIX) Enumerate(domain string) ([]string, error) {
	headers := map[string]string{}
	if s.APIKey != "" {
		headers["api-key"] = s.APIKey
	}
	data, err := get(
		fmt.Sprintf("https://leakix.net/api/subdomains/%s", domain),
		headers,
	)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	var all []string
	for _, e := range entries {
		all = append(all, e.Subdomain)
	}
	return filterSubs(all, domain), nil
}

// ---- GitHub Code Search ----

type GitHub struct{ Token string }

func (s *GitHub) Name() string { return "github" }

func (s *GitHub) Enumerate(domain string) ([]string, error) {
	headers := map[string]string{
		"Accept": "application/vnd.github.v3.text-match+json",
	}
	if s.Token != "" {
		headers["Authorization"] = "token " + s.Token
	}

	escapedDomain := regexp.QuoteMeta(domain)
	subPattern := regexp.MustCompile(`(?i)([a-zA-Z0-9_\-]+\.` + escapedDomain + `)`)

	data, err := get(
		fmt.Sprintf("https://api.github.com/search/code?q=%%22%s%%22&per_page=100", url.QueryEscape(domain)),
		headers,
	)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Items []struct {
			TextMatches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string
	for _, item := range resp.Items {
		for _, match := range item.TextMatches {
			for _, found := range subPattern.FindAllString(match.Fragment, -1) {
				found = strings.ToLower(found)
				if !seen[found] {
					seen[found] = true
					results = append(results, found)
				}
			}
		}
	}
	return filterSubs(results, domain), nil
}

// ---- Builder ----

type Options struct {
	WordlistPath      string
	VirusTotalKey     string
	SecurityTrailsKey string
	ShodanKey         string
	CensysID          string
	CensysSecret      string
	ChaosKey          string
	FullHuntKey       string
	BevigilKey        string
	LeakIXKey         string
	GitHubToken       string
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
		&CommonCrawl{},
		&LeakIX{APIKey: opts.LeakIXKey},
		&GitHub{Token: opts.GitHubToken},
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
	if opts.ChaosKey != "" {
		srcs = append(srcs, &Chaos{APIKey: opts.ChaosKey})
	}
	if opts.FullHuntKey != "" {
		srcs = append(srcs, &FullHunt{APIKey: opts.FullHuntKey})
	}
	if opts.BevigilKey != "" {
		srcs = append(srcs, &Bevigil{APIKey: opts.BevigilKey})
	}
	return srcs
}
