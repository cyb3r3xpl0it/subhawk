package axfr

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ZoneTransfer attempts AXFR on all nameservers of the domain.
func ZoneTransfer(domain string) ([]string, error) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	nss, err := net.LookupNS(strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, fmt.Errorf("NS lookup failed: %w", err)
	}

	for _, ns := range nss {
		subs, err := transferFrom(domain, ns.Host)
		if err == nil && len(subs) > 0 {
			return subs, nil
		}
	}
	return nil, fmt.Errorf("zone transfer not allowed on any nameserver")
}

func transferFrom(domain, ns string) ([]string, error) {
	host := strings.TrimSuffix(ns, ".")
	addr := net.JoinHostPort(host, "53")

	t := &dns.Transfer{DialTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	m := new(dns.Msg)
	m.SetAxfr(domain)

	ch, err := t.In(m, addr)
	if err != nil {
		return nil, err
	}

	rootDomain := strings.TrimSuffix(domain, ".")
	seen := map[string]bool{}
	var results []string

	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		for _, rr := range env.RR {
			name := strings.TrimSuffix(rr.Header().Name, ".")
			if name != "" && strings.HasSuffix(name, rootDomain) && !seen[name] {
				seen[name] = true
				results = append(results, name)
			}
		}
	}
	return results, nil
}
