package dnsrecords

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Records struct {
	A      []string
	AAAA   []string
	MX     []string
	TXT    []string
	NS     []string
	CNAME  string
	SOA    string
	SRV    []string
	CAA    []string
	PTR    []string
	DMARC  string
	SPF    string
	DNSKEY []string
	DS     []string
	TLSA   []string
	NAPTR  []string
	HTTPS  []string
}

// ValidTypes lists all supported record type names.
var ValidTypes = []string{
	"A", "AAAA", "CNAME", "MX", "TXT", "NS",
	"SOA", "SRV", "CAA", "PTR", "DMARC", "SPF",
	"DNSKEY", "DS", "TLSA", "NAPTR", "HTTPS",
}

// Common SRV prefixes to probe during discovery.
var srvPrefixes = []string{
	"_http._tcp", "_https._tcp",
	"_sip._tcp", "_sip._udp",
	"_xmpp-client._tcp", "_xmpp-server._tcp",
	"_ldap._tcp", "_ldaps._tcp",
	"_kerberos._tcp", "_kerberos._udp",
	"_smtp._tcp", "_submission._tcp",
	"_imap._tcp", "_imaps._tcp",
	"_pop3._tcp", "_pop3s._tcp",
	"_ftp._tcp", "_ssh._tcp",
	"_rdp._tcp", "_vpn._tcp",
	"_matrix._tcp", "_turn._tcp",
}

// ParseTypes normalizes input strings into an uppercase set.
// nil means "all types".
func ParseTypes(input []string) map[string]bool {
	if len(input) == 0 {
		return nil
	}
	set := make(map[string]bool, len(input))
	for _, t := range input {
		set[strings.ToUpper(strings.TrimSpace(t))] = true
	}
	return set
}

// Lookup fetches DNS records for subdomain concurrently.
// types == nil means fetch all.
func Lookup(subdomain, nameserver string, timeout time.Duration, types map[string]bool) Records {
	want := func(t string) bool { return types == nil || types[t] }

	c := &dns.Client{Timeout: timeout}
	fqdn := dns.Fqdn(subdomain)

	query := func(qtype uint16) ([]dns.RR, error) {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)
		m.RecursionDesired = true
		r, _, err := c.Exchange(m, nameserver)
		if err != nil {
			return nil, err
		}
		if r.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("rcode %d", r.Rcode)
		}
		return r.Answer, nil
	}

	var (
		rec Records
		mu  sync.Mutex
		wg  sync.WaitGroup
	)

	run := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}

	// A
	if want("A") || want("PTR") {
		run(func() {
			rrs, err := query(dns.TypeA)
			if err != nil {
				return
			}
			var ips []string
			mu.Lock()
			for _, rr := range rrs {
				if a, ok := rr.(*dns.A); ok && want("A") {
					rec.A = append(rec.A, a.A.String())
					ips = append(ips, a.A.String())
				}
			}
			mu.Unlock()

			// PTR — reverse lookup of A IPs
			if want("PTR") && len(ips) > 0 {
				var ptrs []string
				for _, ip := range ips {
					if names, err := net.LookupAddr(ip); err == nil {
						for _, n := range names {
							ptrs = append(ptrs, strings.TrimSuffix(n, "."))
						}
					}
				}
				if len(ptrs) > 0 {
					mu.Lock()
					rec.PTR = append(rec.PTR, ptrs...)
					mu.Unlock()
				}
			}
		})
	}

	// AAAA
	if want("AAAA") {
		run(func() {
			rrs, err := query(dns.TypeAAAA)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					rec.AAAA = append(rec.AAAA, aaaa.AAAA.String())
				}
			}
		})
	}

	// CNAME
	if want("CNAME") {
		run(func() {
			rrs, err := query(dns.TypeCNAME)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if cname, ok := rr.(*dns.CNAME); ok {
					rec.CNAME = strings.TrimSuffix(cname.Target, ".")
					break
				}
			}
		})
	}

	// MX
	if want("MX") {
		run(func() {
			rrs, err := query(dns.TypeMX)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if mx, ok := rr.(*dns.MX); ok {
					rec.MX = append(rec.MX, fmt.Sprintf("%d %s", mx.Preference, strings.TrimSuffix(mx.Mx, ".")))
				}
			}
		})
	}

	// TXT + SPF (filtered from TXT)
	if want("TXT") || want("SPF") || want("DMARC") {
		run(func() {
			rrs, err := query(dns.TypeTXT)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if txt, ok := rr.(*dns.TXT); ok {
					val := strings.Join(txt.Txt, "")
					if want("TXT") {
						rec.TXT = append(rec.TXT, val)
					}
					if want("SPF") && strings.HasPrefix(val, "v=spf1") {
						rec.SPF = val
					}
				}
			}
		})
	}

	// NS
	if want("NS") {
		run(func() {
			rrs, err := query(dns.TypeNS)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if ns, ok := rr.(*dns.NS); ok {
					rec.NS = append(rec.NS, strings.TrimSuffix(ns.Ns, "."))
				}
			}
		})
	}

	// SOA
	if want("SOA") {
		run(func() {
			rrs, err := query(dns.TypeSOA)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if soa, ok := rr.(*dns.SOA); ok {
					rec.SOA = fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d ttl=%d",
						strings.TrimSuffix(soa.Ns, "."),
						strings.TrimSuffix(soa.Mbox, "."),
						soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl,
					)
					break
				}
			}
		})
	}

	// CAA
	if want("CAA") {
		run(func() {
			rrs, err := query(dns.TypeCAA)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if caa, ok := rr.(*dns.CAA); ok {
					rec.CAA = append(rec.CAA, fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value))
				}
			}
		})
	}

	// DNSKEY
	if want("DNSKEY") {
		run(func() {
			rrs, err := query(dns.TypeDNSKEY)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if key, ok := rr.(*dns.DNSKEY); ok {
					rec.DNSKEY = append(rec.DNSKEY, fmt.Sprintf("flags=%d alg=%d keytag=%d", key.Flags, key.Algorithm, key.KeyTag()))
				}
			}
		})
	}

	// DS
	if want("DS") {
		run(func() {
			rrs, err := query(dns.TypeDS)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if ds, ok := rr.(*dns.DS); ok {
					rec.DS = append(rec.DS, fmt.Sprintf("keytag=%d alg=%d dtype=%d digest=%s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
				}
			}
		})
	}

	// TLSA
	if want("TLSA") {
		run(func() {
			target := "_443._tcp." + fqdn
			m := new(dns.Msg)
			m.SetQuestion(target, dns.TypeTLSA)
			m.RecursionDesired = true
			r, _, err := c.Exchange(m, nameserver)
			if err != nil || r.Rcode != dns.RcodeSuccess {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range r.Answer {
				if tlsa, ok := rr.(*dns.TLSA); ok {
					rec.TLSA = append(rec.TLSA, fmt.Sprintf("usage=%d selector=%d mtype=%d cert=%s",
						tlsa.Usage, tlsa.Selector, tlsa.MatchingType, tlsa.Certificate))
				}
			}
		})
	}

	// NAPTR
	if want("NAPTR") {
		run(func() {
			rrs, err := query(dns.TypeNAPTR)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if naptr, ok := rr.(*dns.NAPTR); ok {
					rec.NAPTR = append(rec.NAPTR, fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s",
						naptr.Order, naptr.Preference, naptr.Flags,
						naptr.Service, naptr.Regexp,
						strings.TrimSuffix(naptr.Replacement, ".")))
				}
			}
		})
	}

	// HTTPS (SVCB)
	if want("HTTPS") {
		run(func() {
			rrs, err := query(dns.TypeHTTPS)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range rrs {
				if h, ok := rr.(*dns.HTTPS); ok {
					rec.HTTPS = append(rec.HTTPS, fmt.Sprintf("prio=%d target=%s", h.Priority, strings.TrimSuffix(h.Target, ".")))
				}
			}
		})
	}

	// DMARC — query _dmarc.subdomain TXT
	if want("DMARC") {
		run(func() {
			target := "_dmarc." + fqdn
			m := new(dns.Msg)
			m.SetQuestion(target, dns.TypeTXT)
			m.RecursionDesired = true
			r, _, err := c.Exchange(m, nameserver)
			if err != nil || r.Rcode != dns.RcodeSuccess {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rr := range r.Answer {
				if txt, ok := rr.(*dns.TXT); ok {
					val := strings.Join(txt.Txt, "")
					if strings.HasPrefix(val, "v=DMARC1") {
						rec.DMARC = val
						break
					}
				}
			}
		})
	}

	// SRV — probe common service prefixes
	if want("SRV") {
		for _, prefix := range srvPrefixes {
			prefix := prefix
			run(func() {
				target := prefix + "." + fqdn
				m := new(dns.Msg)
				m.SetQuestion(target, dns.TypeSRV)
				m.RecursionDesired = true
				r, _, err := c.Exchange(m, nameserver)
				if err != nil || r.Rcode != dns.RcodeSuccess {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, rr := range r.Answer {
					if srv, ok := rr.(*dns.SRV); ok {
						rec.SRV = append(rec.SRV, fmt.Sprintf("%s %d %d %d %s",
							prefix, srv.Priority, srv.Weight, srv.Port,
							strings.TrimSuffix(srv.Target, ".")))
					}
				}
			})
		}
	}

	wg.Wait()
	return rec
}
