package wildcard

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// Detect checks if a domain has wildcard DNS and returns the wildcard IPs.
func Detect(domain string, nameserver string, timeout time.Duration) (bool, []string) {
	// Generate a random subdomain that almost certainly doesn't exist
	random := fmt.Sprintf("%x.%s", rand.Int63(), domain)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", nameserver)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, random)
	if err != nil || len(addrs) == 0 {
		return false, nil
	}
	return true, addrs
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
