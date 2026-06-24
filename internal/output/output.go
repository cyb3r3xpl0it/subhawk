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

type Writer struct {
	mu      sync.Mutex
	format  Format
	file    *os.File
	noColor bool
	burpBuf []burpEntry
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

         Subdomain Enumeration Tool  v1.2

`)
}
