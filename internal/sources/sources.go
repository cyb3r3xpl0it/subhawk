package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Source interface {
	Name() string
	Enumerate(domain string) ([]string, error)
}

var client = &http.Client{Timeout: 15 * time.Second}

// ---- CRT.sh ----

type CRTsh struct{}

func (s *CRTsh) Name() string { return "crt.sh" }

func (s *CRTsh) Enumerate(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name != "" && strings.HasSuffix(name, domain) && !seen[name] {
				seen[name] = true
				results = append(results, name)
			}
		}
	}
	return results, nil
}

// ---- AlienVault OTX ----

type AlienVault struct{}

func (s *AlienVault) Name() string { return "alienvault" }

func (s *AlienVault) Enumerate(domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string
	for _, entry := range data.PassiveDNS {
		h := strings.TrimSpace(entry.Hostname)
		if h != "" && strings.HasSuffix(h, domain) && !seen[h] {
			seen[h] = true
			results = append(results, h)
		}
	}
	return results, nil
}

// ---- HackerTarget ----

type HackerTarget struct{}

func (s *HackerTarget) Name() string { return "hackertarget" }

func (s *HackerTarget) Enumerate(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			h := strings.TrimSpace(parts[0])
			if h != "" && strings.HasSuffix(h, domain) && !seen[h] {
				seen[h] = true
				results = append(results, h)
			}
		}
	}
	return results, nil
}

// ---- RapidDNS ----

type RapidDNS struct{}

func (s *RapidDNS) Name() string { return "rapiddns" }

func (s *RapidDNS) Enumerate(domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 SubHawk")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "."+domain) && !seen[line] {
			seen[line] = true
			results = append(results, line)
		}
	}
	return results, nil
}

// ---- Wordlist bruteforce ----

type Wordlist struct {
	Path string
}

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

// ---- All active sources ----

func All(wordlistPath string) []Source {
	sources := []Source{
		&CRTsh{},
		&AlienVault{},
		&HackerTarget{},
		&RapidDNS{},
	}
	if wordlistPath != "" {
		sources = append(sources, &Wordlist{Path: wordlistPath})
	}
	return sources
}
