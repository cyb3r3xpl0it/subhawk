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
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorCyan   = "\033[36m"
)

type Writer struct {
	mu      sync.Mutex
	format  Format
	file    *os.File
	noColor bool
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
		httpStatus := ""
		httpTitle := ""
		if r.HTTP != nil {
			httpStatus = fmt.Sprintf("%d", r.HTTP.StatusCode)
			httpTitle = r.HTTP.Title
		}
		takeover := ""
		if r.Takeover != nil {
			takeover = r.Takeover.Service
		}
		line := fmt.Sprintf("%s,%s,%s,%v,%s,%s,%s",
			r.Subdomain,
			strings.Join(r.IPs, ";"),
			r.CNAME,
			r.Active,
			httpStatus,
			httpTitle,
			takeover,
		)
		fmt.Println(line)
		if w.file != nil {
			fmt.Fprintln(w.file, line)
		}

	default:
		line := w.formatText(r)
		fmt.Println(line)
		if w.file != nil {
			fmt.Fprintln(w.file, r.Subdomain)
		}
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
		if r.HTTP != nil {
			sb.WriteString(w.color(colorCyan, fmt.Sprintf(" [%d]", r.HTTP.StatusCode)))
			if r.HTTP.Title != "" {
				sb.WriteString(w.color(colorCyan, fmt.Sprintf(" [%s]", r.HTTP.Title)))
			}
			if r.HTTP.Server != "" {
				sb.WriteString(w.color(colorGray, fmt.Sprintf(" [%s]", r.HTTP.Server)))
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
		header := "subdomain,ips,cname,active,http_status,http_title,takeover"
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

         Subdomain Enumeration Tool  v1.0

`)
}
