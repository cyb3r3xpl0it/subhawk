package zonewalk

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Walk enumerates subdomains of domain via NSEC record chain walking.
// Returns discovered subdomains. Returns empty slice if zone is not NSEC-signed or blocks walking.
func Walk(domain string, nameserver string, timeout time.Duration) []string {
	if nameserver == "" {
		nameserver = "8.8.8.8:53"
	}
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}

	c := &dns.Client{Net: "tcp", Timeout: timeout}
	seen := map[string]bool{}
	var found []string
	current := domain

	for i := 0; i < 1000; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(current), dns.TypeNSEC)
		msg.SetEdns0(4096, true)
		msg.RecursionDesired = true

		resp, _, err := c.Exchange(msg, nameserver)
		if err != nil || resp == nil {
			break
		}

		var nextName string
		for _, rr := range append(resp.Answer, resp.Ns...) {
			if nsec, ok := rr.(*dns.NSEC); ok {
				nextName = strings.ToLower(strings.TrimSuffix(nsec.NextDomain, "."))
				break
			}
		}
		if nextName == "" {
			break
		}
		if seen[nextName] {
			break
		}
		seen[nextName] = true

		if strings.HasSuffix(nextName, "."+domain) && nextName != domain {
			found = append(found, nextName)
		}
		if nextName == domain || strings.TrimSuffix(nextName, ".") == domain {
			break
		}
		current = nextName
	}

	return found
}

// DetectNSEC3 checks if the zone uses NSEC3 (hash-based, cannot be walked directly).
func DetectNSEC3(domain string, nameserver string, timeout time.Duration) (bool, string) {
	if nameserver == "" {
		nameserver = "8.8.8.8:53"
	}
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}

	c := &dns.Client{Net: "tcp", Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fmt.Sprintf("doesnotexist12345.%s", domain)), dns.TypeA)
	msg.SetEdns0(4096, true)

	resp, _, err := c.Exchange(msg, nameserver)
	if err != nil || resp == nil {
		return false, ""
	}

	for _, rr := range resp.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			return true, fmt.Sprintf("NSEC3 (iterations=%d, salt=%s)", nsec3.Iterations, nsec3.Salt)
		}
	}
	return false, ""
}
