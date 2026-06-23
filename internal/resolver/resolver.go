package resolver

import (
	"context"
	"net"
	"time"
)

type Result struct {
	Subdomain string
	IPs       []string
	CNAME     string
	Active    bool
}

var defaultResolvers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

type Resolver struct {
	resolvers []string
	timeout   time.Duration
}

func New(resolvers []string, timeout time.Duration) *Resolver {
	if len(resolvers) == 0 {
		resolvers = defaultResolvers
	}
	return &Resolver{resolvers: resolvers, timeout: timeout}
}

func (r *Resolver) Resolve(subdomain string) Result {
	result := Result{Subdomain: subdomain}

	for _, ns := range r.resolvers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: r.timeout}
				return d.DialContext(ctx, "udp", ns)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		defer cancel()

		addrs, err := resolver.LookupHost(ctx, subdomain)
		if err == nil && len(addrs) > 0 {
			result.IPs = addrs
			result.Active = true

			cname, cerr := resolver.LookupCNAME(ctx, subdomain)
			if cerr == nil {
				result.CNAME = cname
			}
			return result
		}
	}
	return result
}
