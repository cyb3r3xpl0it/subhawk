package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Info struct {
	IP            string `json:"ipAddress"`
	AbuseScore    int    `json:"abuseConfidenceScore"` // 0-100
	CountryCode   string `json:"countryCode"`
	ISP           string `json:"isp"`
	Domain        string `json:"domain"`
	TotalReports  int    `json:"totalReports"`
	LastReported  string `json:"lastReportedAt"`
	IsWhitelisted bool   `json:"isWhitelisted"`
}

var client = &http.Client{Timeout: 10 * time.Second}

// Lookup queries the AbuseIPDB API (requires API key).
// Returns nil if no key is provided or the request fails.
func Lookup(ip, apiKey string) *Info {
	if apiKey == "" {
		return nil
	}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))

	var result struct {
		Data Info `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	return &result.Data
}
