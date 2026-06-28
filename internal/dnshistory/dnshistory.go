package dnshistory

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Record struct {
	IP        string
	FirstSeen string
	LastSeen  string
}

var (
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	reIP = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
)

// Lookup fetches DNS history for a domain via multiple free APIs.
func Lookup(domain string) []Record {
	var records []Record
	seen := map[string]bool{}

	// Try HackerTarget DNS history
	if r := fromHackerTarget(domain); len(r) > 0 {
		for _, rec := range r {
			if !seen[rec.IP] {
				seen[rec.IP] = true
				records = append(records, rec)
			}
		}
	}

	// Try SecurityTrails-compatible endpoint (ViewDNS)
	if r := fromViewDNS(domain); len(r) > 0 {
		for _, rec := range r {
			if !seen[rec.IP] {
				seen[rec.IP] = true
				records = append(records, rec)
			}
		}
	}

	return records
}

func fromHackerTarget(domain string) []Record {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := httpClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var records []Record
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) >= 2 {
			ip := strings.TrimSpace(parts[1])
			if reIP.MatchString(ip) {
				records = append(records, Record{IP: ip})
			}
		}
	}
	return records
}

func fromViewDNS(domain string) []Record {
	// ViewDNS IP history API (JSON format)
	url := fmt.Sprintf("https://viewdns.info/iphistory/?domain=%s&output=json", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var result struct {
		Response struct {
			Records []struct {
				IP        string `json:"ip"`
				Location  string `json:"location"`
				Owner     string `json:"owner"`
				LastSeen  string `json:"lastseen"`
				FirstSeen string `json:"firstseen"`
			} `json:"records"`
		} `json:"response"`
	}

	var records []Record
	if err := json.Unmarshal(body, &result); err == nil {
		for _, r := range result.Response.Records {
			if r.IP != "" {
				records = append(records, Record{
					IP:        r.IP,
					FirstSeen: r.FirstSeen,
					LastSeen:  r.LastSeen,
				})
			}
		}
	}
	return records
}
