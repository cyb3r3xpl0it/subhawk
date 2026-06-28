package greynoise

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Info struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`          // true = seen scanning the internet
	Riot           bool   `json:"riot"`           // true = known benign (CDN, DNS, etc.)
	Classification string `json:"classification"` // "malicious", "benign", "unknown"
	Name           string `json:"name"`           // e.g. "Cloudflare"
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

var client = &http.Client{Timeout: 10 * time.Second}

// Lookup queries the GreyNoise Community API (free, no key needed).
func Lookup(ip string) *Info {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "subhawk/1.5")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 404) {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))

	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	if info.Message == "This IP is not in our dataset" || info.IP == "" {
		info.IP = ip
		info.Classification = "unknown"
	}
	return &info
}
