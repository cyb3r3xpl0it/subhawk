package asn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Info struct {
	IP      string `json:"ip"`
	ASN     string `json:"org"`
	Country string `json:"country"`
	City    string `json:"city"`
	Region  string `json:"region"`
}

var client = &http.Client{Timeout: 8 * time.Second}

// Lookup queries ipinfo.io for ASN and geo data (free, no API key).
func Lookup(ip string) *Info {
	resp, err := client.Get(fmt.Sprintf("https://ipinfo.io/%s/json", ip))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	if info.IP == "" {
		return nil
	}
	return &info
}
