package cvelookup

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CVE struct {
	ID          string
	Description string
	CVSS        float64
	Severity    string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Published   string
	URL         string
	HasExploit  bool
}

type Result struct {
	Tech    string
	Version string
	CVEs    []CVE
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Lookup searches NVD and OSV for CVEs matching the given technology and version.
func Lookup(techName, version string) *Result {
	result := &Result{Tech: techName, Version: version}

	nvdCVEs := fromNVD(techName, version)
	result.CVEs = append(result.CVEs, nvdCVEs...)

	osvCVEs := fromOSV(techName, version)
	// Deduplicate by ID
	seen := map[string]bool{}
	for _, c := range result.CVEs {
		seen[c.ID] = true
	}
	for _, c := range osvCVEs {
		if !seen[c.ID] {
			seen[c.ID] = true
			result.CVEs = append(result.CVEs, c)
		}
	}

	if len(result.CVEs) == 0 {
		return nil
	}
	return result
}

// LookupAll runs CVE lookups for multiple techs concurrently and returns all results.
func LookupAll(techs []struct{ Name, Version string }) []Result {
	type job struct {
		idx int
		res *Result
	}
	ch := make(chan job, len(techs))
	for i, t := range techs {
		go func(idx int, name, ver string) {
			ch <- job{idx: idx, res: Lookup(name, ver)}
		}(i, t.Name, t.Version)
	}
	var results []Result
	for range techs {
		j := <-ch
		if j.res != nil {
			results = append(results, *j.res)
		}
	}
	return results
}

func fromNVD(tech, version string) []CVE {
	// NVD CVE API 2.0
	query := tech
	if version != "" {
		query = tech + " " + version
	}
	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20",
		url.QueryEscape(query))

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "subhawk/1.7")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var nvd struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CvssMetricV2 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil
	}

	var cves []CVE
	for _, v := range nvd.Vulnerabilities {
		c := CVE{
			ID:        v.CVE.ID,
			Published: v.CVE.Published,
			URL:       "https://nvd.nist.gov/vuln/detail/" + v.CVE.ID,
		}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				c.Description = truncate(d.Value, 200)
				break
			}
		}
		// CVSS score (prefer v3.1 > v3.0 > v2)
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			c.CVSS = v.CVE.Metrics.CvssMetricV31[0].CVSSData.BaseScore
			c.Severity = v.CVE.Metrics.CvssMetricV31[0].CVSSData.BaseSeverity
		} else if len(v.CVE.Metrics.CvssMetricV30) > 0 {
			c.CVSS = v.CVE.Metrics.CvssMetricV30[0].CVSSData.BaseScore
			c.Severity = v.CVE.Metrics.CvssMetricV30[0].CVSSData.BaseSeverity
		} else if len(v.CVE.Metrics.CvssMetricV2) > 0 {
			c.CVSS = v.CVE.Metrics.CvssMetricV2[0].CVSSData.BaseScore
			c.Severity = v.CVE.Metrics.CvssMetricV2[0].BaseSeverity
		}
		// Only include medium+ severity
		if c.CVSS >= 5.0 || c.Severity == "HIGH" || c.Severity == "CRITICAL" {
			cves = append(cves, c)
		}
	}
	return cves
}

func fromOSV(tech, version string) []CVE {
	// OSV.dev API
	payload := fmt.Sprintf(`{"package":{"name":%q},"version":%q}`,
		strings.ToLower(tech), version)

	resp, err := httpClient.Post("https://api.osv.dev/v1/query",
		"application/json", strings.NewReader(payload))
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	var osv struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Modified string `json:"modified"`
			Severity []struct {
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(body, &osv); err != nil {
		return nil
	}

	var cves []CVE
	for _, v := range osv.Vulns {
		c := CVE{
			ID:          v.ID,
			Description: truncate(v.Summary, 200),
			Published:   v.Modified,
			URL:         "https://osv.dev/vulnerability/" + v.ID,
		}
		cves = append(cves, c)
	}
	return cves
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
