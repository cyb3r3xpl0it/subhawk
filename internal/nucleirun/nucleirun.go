package nucleirun

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Result struct {
	Subdomain string
	Findings  []Finding
}

type Finding struct {
	TemplateID string
	Severity   string
	Name       string
	URL        string
}

// Available checks if the nuclei binary is in PATH.
func Available() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// Run executes nuclei against the given subdomains.
// templateArgs: e.g. []string{"-t", "cves/"} or nil for defaults
// severity: e.g. "medium,high,critical" or "" for all
func Run(subdomains []string, templateArgs []string, severity string, timeout time.Duration) []Result {
	if !Available() || len(subdomains) == 0 {
		return nil
	}

	tmpFile, err := os.CreateTemp("", "subhawk-nuclei-*.txt")
	if err != nil {
		return nil
	}
	defer os.Remove(tmpFile.Name())
	for _, s := range subdomains {
		fmt.Fprintln(tmpFile, "https://"+s)
		fmt.Fprintln(tmpFile, "http://"+s)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-json", "-silent", "-no-color",
		"-timeout", fmt.Sprintf("%d", int(timeout.Seconds())),
	}
	if severity != "" {
		args = append(args, "-severity", severity)
	}
	if len(templateArgs) > 0 {
		args = append(args, templateArgs...)
	} else {
		args = append(args, "-t", "http/exposures/", "-t", "http/vulnerabilities/", "-t", "http/misconfiguration/")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(subdomains)+1))
	defer cancel()

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	cmd.Stdout = &out
	_ = cmd.Run()

	return parseOutput(out.String(), subdomains)
}

func parseOutput(output string, subdomains []string) []Result {
	resultMap := map[string]*Result{}
	for _, s := range subdomains {
		resultMap[s] = &Result{Subdomain: s}
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		templateID := extractJSON(line, "template-id")
		name := extractJSON(line, "name")
		severity := extractJSON(line, "severity")
		matchedAt := extractJSON(line, "matched-at")
		if templateID == "" || matchedAt == "" {
			continue
		}
		for sub, r := range resultMap {
			if strings.Contains(matchedAt, sub) {
				r.Findings = append(r.Findings, Finding{
					TemplateID: templateID,
					Severity:   severity,
					Name:       name,
					URL:        matchedAt,
				})
				break
			}
		}
	}

	var results []Result
	for _, r := range resultMap {
		if len(r.Findings) > 0 {
			results = append(results, *r)
		}
	}
	return results
}

func extractJSON(line, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
