package neighbors

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var defaultResolver = &net.Resolver{PreferGo: true}

type Host struct {
	IP        string
	Hostnames []string
}

// Scan performs reverse DNS (PTR) lookups on all 254 IPs in the /24 subnet of ip.
func Scan(ip string, timeout time.Duration) []Host {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}
	prefix := strings.Join(parts[:3], ".")

	var mu sync.Mutex
	var results []Host
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for i := 1; i <= 254; i++ {
		target := fmt.Sprintf("%s.%d", prefix, i)
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			names, err := defaultResolver.LookupAddr(ctx, addr)
			if err != nil || len(names) == 0 {
				return
			}
			clean := make([]string, len(names))
			for i, n := range names {
				clean[i] = strings.TrimSuffix(n, ".")
			}
			mu.Lock()
			results = append(results, Host{IP: addr, Hostnames: clean})
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return results
}

// ScanFromIPs scans /24 subnets for each unique subnet in ips.
func ScanFromIPs(ips []string, timeout time.Duration) []Host {
	seen := map[string]bool{}
	var all []Host
	for _, ip := range ips {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			continue
		}
		subnet := strings.Join(parts[:3], ".")
		if seen[subnet] {
			continue
		}
		seen[subnet] = true
		all = append(all, Scan(ip, timeout)...)
	}
	return all
}
