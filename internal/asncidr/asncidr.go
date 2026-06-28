package asncidr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ASNInfo struct {
	ASN         string
	Name        string
	Description string
	Prefixes    []string // IPv4 CIDR ranges
	Prefixes6   []string // IPv6 CIDR ranges
}

var client = &http.Client{Timeout: 15 * time.Second}

// LookupASN expands an ASN number (e.g. "AS13335" or "13335") to its CIDR prefixes via bgpview.io.
func LookupASN(asn string) *ASNInfo {
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var result struct {
		Status string `json:"status"`
		Data   struct {
			IPv4Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
			IPv6Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Status != "ok" {
		return nil
	}

	info := &ASNInfo{ASN: "AS" + asn}
	for _, p := range result.Data.IPv4Prefixes {
		info.Prefixes = append(info.Prefixes, p.Prefix)
	}
	for _, p := range result.Data.IPv6Prefixes {
		info.Prefixes6 = append(info.Prefixes6, p.Prefix)
	}

	// Also fetch ASN details
	resp2, err := client.Get(fmt.Sprintf("https://api.bgpview.io/asn/%s", asn))
	if err == nil && resp2.StatusCode == 200 {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 32*1024))
		var detail struct {
			Data struct {
				Name        string `json:"name"`
				Description string `json:"description_short"`
			} `json:"data"`
		}
		if json.Unmarshal(body2, &detail) == nil {
			info.Name = detail.Data.Name
			info.Description = detail.Data.Description
		}
	}
	return info
}

// LookupIP finds the ASN for a given IP and returns its prefixes.
func LookupIP(ip string) *ASNInfo {
	url := fmt.Sprintf("https://api.bgpview.io/ip/%s", ip)
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var result struct {
		Data struct {
			Prefixes []struct {
				ASN struct {
					ASN int `json:"asn"`
				} `json:"asn"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	if len(result.Data.Prefixes) == 0 {
		return nil
	}
	asnNum := result.Data.Prefixes[0].ASN.ASN
	if asnNum == 0 {
		return nil
	}
	return LookupASN(fmt.Sprintf("%d", asnNum))
}
