package internetdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Info struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	CVEs      []string `json:"vulns"`
	Tags      []string `json:"tags"`
	Hostnames []string `json:"hostnames"`
	CPEs      []string `json:"cpes"`
}

var client = &http.Client{Timeout: 10 * time.Second}

// Lookup queries the free Shodan InternetDB API (no key needed) for IP metadata.
func Lookup(ip string) *Info {
	resp, err := client.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", ip))
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	info.IP = ip
	return &info
}
