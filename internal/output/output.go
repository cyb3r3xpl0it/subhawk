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

type Writer struct {
	mu     sync.Mutex
	format Format
	file   *os.File
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

func (w *Writer) Write(r resolver.Result) {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case FormatJSON:
		data, _ := json.Marshal(map[string]interface{}{
			"subdomain": r.Subdomain,
			"ips":       r.IPs,
			"cname":     r.CNAME,
			"active":    r.Active,
		})
		line := string(data)
		fmt.Println(line)
		if w.file != nil {
			fmt.Fprintln(w.file, line)
		}

	case FormatCSV:
		line := fmt.Sprintf("%s,%s,%s,%v", r.Subdomain, strings.Join(r.IPs, ";"), r.CNAME, r.Active)
		fmt.Println(line)
		if w.file != nil {
			fmt.Fprintln(w.file, line)
		}

	default:
		var line string
		if r.Active {
			ips := strings.Join(r.IPs, ", ")
			if w.noColor {
				line = fmt.Sprintf("[+] %s [%s]", r.Subdomain, ips)
			} else {
				line = fmt.Sprintf("\033[32m[+]\033[0m %s \033[90m[%s]\033[0m", r.Subdomain, ips)
			}
		} else {
			if w.noColor {
				line = fmt.Sprintf("[-] %s", r.Subdomain)
			} else {
				line = fmt.Sprintf("\033[31m[-]\033[0m %s", r.Subdomain)
			}
		}
		fmt.Println(line)
		if w.file != nil {
			fmt.Fprintln(w.file, r.Subdomain)
		}
	}
}

func (w *Writer) WriteHeader() {
	if w.format == FormatCSV {
		header := "subdomain,ips,cname,active"
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
