package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
)

type Format string

const (
	FormatText   Format = "text"
	FormatJSON   Format = "json"
	FormatCSV    Format = "csv"
	FormatNuclei Format = "nuclei"
	FormatBurp   Format = "burp"
	FormatSARIF  Format = "sarif"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorCyan   = "\033[36m"
	colorMagenta = "\033[35m"
)

type burpEntry struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Protocol string `json:"protocol"`
}

// SARIF 2.1.0 structures
type sarifLog struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       map[string]any  `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"` // error, warning, note
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type Writer struct {
	mu       sync.Mutex
	format   Format
	file     *os.File
	noColor  bool
	burpBuf  []burpEntry
	sarifBuf []sarifResult
}

func New(format Format, outputFile string, noColor bool) (*Writer, error) {
	w := &Writer{format: format, noColor: noColor}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, err
		}
		w.file = f
	}
	return w, nil
}

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.format == FormatBurp && w.file != nil {
		scope := map[string]interface{}{
			"target": map[string]interface{}{
				"scope": map[string]interface{}{
					"advanced_mode": true,
					"exclude":       []interface{}{},
					"include":       w.burpBuf,
				},
			},
		}
		data, _ := json.MarshalIndent(scope, "", "  ")
		w.file.Write(data)
	}

	if w.format == FormatSARIF {
		log := sarifLog{
			Version: "2.1.0",
			Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
			Runs: []sarifRun{{
				Tool: sarifTool{Driver: sarifDriver{
					Name:           "SubHawk",
					Version:        "1.4.0",
					InformationURI: "https://github.com/cyb3r3xpl0it/subhawk",
					Rules: []sarifRule{
						{ID: "SH001", Name: "SubdomainTakeover", ShortDescription: sarifMessage{Text: "Subdomain takeover vulnerability"}},
						{ID: "SH002", Name: "CORSMisconfiguration", ShortDescription: sarifMessage{Text: "CORS misconfiguration detected"}},
						{ID: "SH003", Name: "SSLIssue", ShortDescription: sarifMessage{Text: "SSL/TLS certificate issue"}},
						{ID: "SH004", Name: "ExposedFile", ShortDescription: sarifMessage{Text: "Sensitive file exposed"}},
						{ID: "SH005", Name: "OpenRedirect", ShortDescription: sarifMessage{Text: "Open redirect vulnerability"}},
						{ID: "SH006", Name: "PublicBucket", ShortDescription: sarifMessage{Text: "Public cloud storage bucket"}},
						{ID: "SH007", Name: "DefaultCredentials", ShortDescription: sarifMessage{Text: "Default credentials accepted"}},
					},
				}},
				Results: w.sarifBuf,
			}},
		}
		data, _ := json.MarshalIndent(log, "", "  ")
		if w.file != nil {
			w.file.Write(data)
		} else {
			fmt.Println(string(data))
		}
	}

	if w.file != nil {
		w.file.Close()
	}
}

func (w *Writer) color(c, text string) string {
	if w.noColor {
		return text
	}
	return c + text + colorReset
}

func (w *Writer) Write(r resolver.Result) {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case FormatJSON:
		data, _ := json.Marshal(r)
		line := string(data)
		fmt.Println(line)
		if w.file != nil {
			fmt.Fprintln(w.file, line)
		}

	case FormatCSV:
		w.writeCSV(r)

	case FormatNuclei:
		w.writeNuclei(r)

	case FormatBurp:
		w.writeBurp(r)

	case FormatSARIF:
		w.writeSARIF(r)

	default:
		fmt.Println(w.formatText(r))
		if w.file != nil {
			fmt.Fprintln(w.file, r.Subdomain)
		}
	}
}

func (w *Writer) writeCSV(r resolver.Result) {
	httpStatus, httpTitle, httpTech := "", "", ""
	if r.HTTP != nil {
		httpStatus = fmt.Sprintf("%d", r.HTTP.StatusCode)
		httpTitle = r.HTTP.Title
		httpTech = strings.Join(r.HTTP.Tech, ";")
	}
	tkover := ""
	if r.Takeover != nil {
		tkover = r.Takeover.Service
	}
	ports := ""
	for i, p := range r.OpenPorts {
		if i > 0 {
			ports += ";"
		}
		ports += fmt.Sprintf("%d", p)
	}
	line := fmt.Sprintf("%s,%s,%s,%v,%s,%s,%s,%s,%s,%s",
		r.Subdomain, strings.Join(r.IPs, ";"), r.CNAME,
		r.Active, httpStatus, httpTitle, httpTech,
		tkover, r.Cloud, ports,
	)
	fmt.Println(line)
	if w.file != nil {
		fmt.Fprintln(w.file, line)
	}
}

func (w *Writer) writeNuclei(r resolver.Result) {
	if !r.Active {
		return
	}
	scheme := "http"
	if r.HTTP != nil && strings.HasPrefix(r.HTTP.URL, "https") {
		scheme = "https"
	}
	line := fmt.Sprintf("%s://%s", scheme, r.Subdomain)
	fmt.Println(line)
	if w.file != nil {
		fmt.Fprintln(w.file, line)
	}
}

func (w *Writer) writeBurp(r resolver.Result) {
	if !r.Active {
		return
	}
	proto := "http"
	if r.HTTP != nil && strings.HasPrefix(r.HTTP.URL, "https") {
		proto = "https"
	}
	line := fmt.Sprintf("[burp] %s://%s", proto, r.Subdomain)
	fmt.Println(line)
	w.burpBuf = append(w.burpBuf, burpEntry{
		Enabled:  true,
		Host:     r.Subdomain,
		Protocol: proto,
	})
}

func (w *Writer) writeSARIF(r resolver.Result) {
	uri := "https://" + r.Subdomain

	if r.Takeover != nil {
		w.sarifBuf = append(w.sarifBuf, sarifResult{
			RuleID:  "SH001",
			Level:   "error",
			Message: sarifMessage{Text: fmt.Sprintf("Subdomain %s is vulnerable to takeover via %s", r.Subdomain, r.Takeover.Service)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}},
		})
	}
	if r.CORS != nil && r.CORS.Vulnerable {
		w.sarifBuf = append(w.sarifBuf, sarifResult{
			RuleID:  "SH002",
			Level:   "warning",
			Message: sarifMessage{Text: fmt.Sprintf("CORS misconfiguration on %s: allows arbitrary origin", r.Subdomain)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}},
		})
	}
	if r.TLS != nil && (!r.TLS.Valid || r.TLS.Expired) {
		msg := fmt.Sprintf("SSL/TLS issue on %s", r.Subdomain)
		if r.TLS.Expired {
			msg = fmt.Sprintf("SSL certificate expired on %s", r.Subdomain)
		}
		w.sarifBuf = append(w.sarifBuf, sarifResult{
			RuleID:  "SH003",
			Level:   "warning",
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}},
		})
	}
	for _, f := range r.ExposedFiles {
		w.sarifBuf = append(w.sarifBuf, sarifResult{
			RuleID:  "SH004",
			Level:   "error",
			Message: sarifMessage{Text: fmt.Sprintf("Exposed sensitive file %s on %s (HTTP %d)", f.Path, r.Subdomain, f.StatusCode)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.URL}}}},
		})
	}
	for _, or_ := range r.OpenRedirects {
		w.sarifBuf = append(w.sarifBuf, sarifResult{
			RuleID:  "SH005",
			Level:   "warning",
			Message: sarifMessage{Text: fmt.Sprintf("Open redirect via parameter '%s' on %s", or_.Param, r.Subdomain)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: or_.URL}}}},
		})
	}
	for _, b := range r.Buckets {
		if b.Public {
			w.sarifBuf = append(w.sarifBuf, sarifResult{
				RuleID:  "SH006",
				Level:   "error",
				Message: sarifMessage{Text: fmt.Sprintf("Public %s bucket: %s (writable: %v)", b.Provider, b.URL, b.Writable)},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: b.URL}}}},
			})
		}
	}
	for _, dc := range r.DefaultCreds {
		w.sarifBuf = append(w.sarifBuf, sarifResult{
			RuleID:  "SH007",
			Level:   "error",
			Message: sarifMessage{Text: fmt.Sprintf("Default credentials %s:%s accepted on %s", dc.Username, dc.Password, r.Subdomain)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}},
		})
	}
}

func (w *Writer) formatText(r resolver.Result) string {
	var sb strings.Builder

	switch {
	case r.Takeover != nil:
		sb.WriteString(w.color(colorYellow, "[TAKEOVER]"))
		sb.WriteString(fmt.Sprintf(" %s", r.Subdomain))
		sb.WriteString(w.color(colorYellow, fmt.Sprintf(" [%s]", r.Takeover.Service)))

	case r.IsWildcard:
		sb.WriteString(w.color(colorGray, "[~]"))
		sb.WriteString(fmt.Sprintf(" %s", r.Subdomain))
		sb.WriteString(w.color(colorGray, " [wildcard]"))

	case r.Active:
		sb.WriteString(w.color(colorGreen, "[+]"))
		sb.WriteString(fmt.Sprintf(" %s", r.Subdomain))
		if len(r.IPs) > 0 {
			sb.WriteString(w.color(colorGray, fmt.Sprintf(" [%s]", strings.Join(r.IPs, ", "))))
		}
		if r.Cloud != "" {
			sb.WriteString(w.color(colorMagenta, fmt.Sprintf(" [%s]", r.Cloud)))
		}
		if len(r.OpenPorts) > 0 {
			ports := make([]string, len(r.OpenPorts))
			for i, p := range r.OpenPorts {
				ports[i] = fmt.Sprintf("%d", p)
			}
			sb.WriteString(w.color(colorCyan, fmt.Sprintf(" [ports:%s]", strings.Join(ports, ","))))
		}
		if r.HTTP != nil {
			sb.WriteString(w.color(colorCyan, fmt.Sprintf(" [%d]", r.HTTP.StatusCode)))
			if r.HTTP.Title != "" {
				sb.WriteString(w.color(colorCyan, fmt.Sprintf(" [%s]", r.HTTP.Title)))
			}
			if r.HTTP.Server != "" {
				sb.WriteString(w.color(colorGray, fmt.Sprintf(" [%s]", r.HTTP.Server)))
			}
			if len(r.HTTP.Tech) > 0 {
				sb.WriteString(w.color(colorMagenta, fmt.Sprintf(" [%s]", strings.Join(r.HTTP.Tech, ", "))))
			}
		}
		if r.WAF != "" {
			sb.WriteString(w.color(colorYellow, fmt.Sprintf(" [WAF:%s]", r.WAF)))
		}
		if r.SecurityHeaders != nil {
			sb.WriteString(w.color(colorGray, fmt.Sprintf(" [headers:%d/100]", r.SecurityHeaders.Score)))
		}
		if r.CORS != nil && r.CORS.Vulnerable {
			sb.WriteString(w.color(colorRed, " [CORS:vulnerable]"))
		}
		if r.TLS != nil {
			if r.TLS.Expired {
				sb.WriteString(w.color(colorRed, " [SSL:expired]"))
			} else if !r.TLS.Valid {
				sb.WriteString(w.color(colorRed, " [SSL:invalid]"))
			} else if r.TLS.DaysUntilExpiry < 30 {
				sb.WriteString(w.color(colorYellow, fmt.Sprintf(" [SSL:expires-%dd]", r.TLS.DaysUntilExpiry)))
			}
		}
		if r.FaviconHash != "" {
			sb.WriteString(w.color(colorGray, fmt.Sprintf(" [favicon:%s]", r.FaviconHash)))
		}
		if r.ASN != nil {
			sb.WriteString(w.color(colorGray, fmt.Sprintf(" [%s/%s]", r.ASN.ASN, r.ASN.Country)))
		}
		if len(r.AdminPanels) > 0 {
			sb.WriteString(w.color(colorYellow, fmt.Sprintf(" [admin:%d]", len(r.AdminPanels))))
		}
		if r.JS != nil && len(r.JS.Secrets) > 0 {
			sb.WriteString(w.color(colorRed, fmt.Sprintf(" [secrets:%d]", len(r.JS.Secrets))))
		}
		if len(r.ExposedFiles) > 0 {
			sb.WriteString(w.color(colorRed, fmt.Sprintf(" [exposed:%d]", len(r.ExposedFiles))))
		}
		if len(r.Buckets) > 0 {
			pub := 0
			for _, b := range r.Buckets {
				if b.Public {
					pub++
				}
			}
			if pub > 0 {
				sb.WriteString(w.color(colorRed, fmt.Sprintf(" [buckets:%d]", pub)))
			}
		}
		if len(r.OpenRedirects) > 0 {
			sb.WriteString(w.color(colorYellow, fmt.Sprintf(" [redirect:%d]", len(r.OpenRedirects))))
		}
		if len(r.DefaultCreds) > 0 {
			sb.WriteString(w.color(colorRed, fmt.Sprintf(" [creds:%d]", len(r.DefaultCreds))))
		}
		if r.RealIP != "" {
			sb.WriteString(w.color(colorMagenta, fmt.Sprintf(" [realip:%s]", r.RealIP)))
		}
		if len(r.VHosts) > 0 {
			sb.WriteString(w.color(colorCyan, fmt.Sprintf(" [vhosts:%d]", len(r.VHosts))))
		}
		if r.ScreenshotPath != "" {
			sb.WriteString(w.color(colorGray, fmt.Sprintf(" [screenshot]")))
		}

	default:
		sb.WriteString(w.color(colorRed, "[-]"))
		sb.WriteString(fmt.Sprintf(" %s", r.Subdomain))
	}

	return sb.String()
}

func (w *Writer) WriteHeader() {
	if w.format == FormatCSV {
		header := "subdomain,ips,cname,active,http_status,http_title,http_tech,takeover,cloud,ports"
		fmt.Println(header)
		if w.file != nil {
			fmt.Fprintln(w.file, header)
		}
	}
}

func Banner() {
	fmt.Print(`
 ____        _     _   _                _
/ ___| _   _| |__ | | | | __ ___      _| | __
\___ \| | | | '_ \| |_| |/ _` + "`" + ` \ \ /\ / / |/ /
 ___) | |_| | |_) |  _  | (_| |\ V  V /|   <
|____/ \__,_|_.__/|_| |_|\__,_| \_/\_/ |_|\_\

         Subdomain Enumeration Tool  v1.4

`)
}
