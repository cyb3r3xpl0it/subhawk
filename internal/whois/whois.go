package whois

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type Info struct {
	Domain      string
	Registrar   string
	CreatedAt   string
	ExpiresAt   string
	UpdatedAt   string
	NameServers []string
	Status      []string
	Emails      []string
	DNSSEC      string
	Raw         string
}

var (
	reRegistrar = regexp.MustCompile(`(?i)registrar\s*:\s*(.+)`)
	reCreated   = regexp.MustCompile(`(?i)(?:creation date|created|registered)\s*:\s*(.+)`)
	reExpires   = regexp.MustCompile(`(?i)(?:expiry date|expiration date|expires)\s*:\s*(.+)`)
	reUpdated   = regexp.MustCompile(`(?i)(?:updated date|last updated)\s*:\s*(.+)`)
	reNS        = regexp.MustCompile(`(?i)name server\s*:\s*(.+)`)
	reStatus    = regexp.MustCompile(`(?i)domain status\s*:\s*(.+)`)
	reEmail     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reDNSSEC    = regexp.MustCompile(`(?i)dnssec\s*:\s*(.+)`)
	reWhoisRef  = regexp.MustCompile(`(?i)whois server\s*:\s*(.+)`)
)

func queryServer(server, domain string, timeout time.Duration) (string, error) {
	if !strings.Contains(server, ":") {
		server = server + ":43"
	}
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "%s\r\n", domain)

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text() + "\n")
	}
	return sb.String(), nil
}

// Lookup performs a WHOIS query, first via IANA to find the authoritative server.
func Lookup(domain string, timeout time.Duration) *Info {
	raw1, err := queryServer("whois.iana.org", domain, timeout)
	if err != nil {
		return nil
	}

	server := "whois.iana.org"
	if m := reWhoisRef.FindStringSubmatch(raw1); len(m) > 1 {
		server = strings.TrimSpace(m[1])
	}

	raw := raw1
	if server != "whois.iana.org" {
		if raw2, err := queryServer(server, domain, timeout); err == nil && len(raw2) > len(raw1) {
			raw = raw2
		}
	}

	info := &Info{Domain: domain, Raw: raw}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if m := reRegistrar.FindStringSubmatch(line); len(m) > 1 && info.Registrar == "" {
			info.Registrar = strings.TrimSpace(m[1])
		}
		if m := reCreated.FindStringSubmatch(line); len(m) > 1 && info.CreatedAt == "" {
			info.CreatedAt = strings.TrimSpace(m[1])
		}
		if m := reExpires.FindStringSubmatch(line); len(m) > 1 && info.ExpiresAt == "" {
			info.ExpiresAt = strings.TrimSpace(m[1])
		}
		if m := reUpdated.FindStringSubmatch(line); len(m) > 1 && info.UpdatedAt == "" {
			info.UpdatedAt = strings.TrimSpace(m[1])
		}
		if m := reNS.FindStringSubmatch(line); len(m) > 1 {
			ns := strings.ToLower(strings.TrimSpace(m[1]))
			if ns != "" {
				info.NameServers = append(info.NameServers, ns)
			}
		}
		if m := reStatus.FindStringSubmatch(line); len(m) > 1 {
			info.Status = append(info.Status, strings.TrimSpace(m[1]))
		}
		if m := reDNSSEC.FindStringSubmatch(line); len(m) > 1 && info.DNSSEC == "" {
			info.DNSSEC = strings.TrimSpace(m[1])
		}
	}

	emails := reEmail.FindAllString(raw, -1)
	seen := map[string]bool{}
	for _, e := range emails {
		e = strings.ToLower(e)
		if !seen[e] && !strings.Contains(e, "example") {
			seen[e] = true
			info.Emails = append(info.Emails, e)
		}
	}

	seenNS := map[string]bool{}
	unique := info.NameServers[:0]
	for _, ns := range info.NameServers {
		if !seenNS[ns] {
			seenNS[ns] = true
			unique = append(unique, ns)
		}
	}
	info.NameServers = unique
	return info
}
