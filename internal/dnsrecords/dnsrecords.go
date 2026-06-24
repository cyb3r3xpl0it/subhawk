package dnsrecords

import (
	"context"
	"net"
	"strings"
	"time"
)

type Records struct {
	A    []string
	AAAA []string
	MX   []string
	TXT  []string
	NS   []string
	CNAME string
}

func Lookup(subdomain string, nameserver string, timeout time.Duration) Records {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", nameserver)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
	defer cancel()

	var rec Records

	if addrs, err := r.LookupHost(ctx, subdomain); err == nil {
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				rec.A = append(rec.A, a)
			} else {
				rec.AAAA = append(rec.AAAA, a)
			}
		}
	}

	if cname, err := r.LookupCNAME(ctx, subdomain); err == nil {
		rec.CNAME = strings.TrimSuffix(cname, ".")
	}

	if mxs, err := r.LookupMX(ctx, subdomain); err == nil {
		for _, mx := range mxs {
			rec.MX = append(rec.MX, strings.TrimSuffix(mx.Host, "."))
		}
	}

	if txts, err := r.LookupTXT(ctx, subdomain); err == nil {
		rec.TXT = append(rec.TXT, txts...)
	}

	if nss, err := r.LookupNS(ctx, subdomain); err == nil {
		for _, ns := range nss {
			rec.NS = append(rec.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	return rec
}
