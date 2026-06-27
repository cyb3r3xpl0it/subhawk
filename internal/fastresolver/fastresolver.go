package fastresolver

import (
	"context"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Result holds resolved IPs for one subdomain.
type Result struct {
	Subdomain string
	IPs       []string
	CNAME     string
}

// Resolve resolves a single subdomain against the given nameservers using raw UDP.
func Resolve(ctx context.Context, subdomain string, nameservers []string, timeout time.Duration) Result {
	r := Result{Subdomain: subdomain}
	if len(nameservers) == 0 {
		nameservers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	c := &dns.Client{Net: "udp", Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeA)
	msg.RecursionDesired = true

	ns := nameservers[rand.Intn(len(nameservers))]
	resp, _, err := c.ExchangeContext(ctx, msg, ns)
	if err != nil || resp == nil {
		return r
	}

	for _, ans := range resp.Answer {
		switch v := ans.(type) {
		case *dns.A:
			r.IPs = append(r.IPs, v.A.String())
		case *dns.CNAME:
			r.CNAME = v.Target
		}
	}
	return r
}

// BulkResolve resolves many subdomains concurrently using raw UDP.
// concurrency controls how many goroutines run at once.
func BulkResolve(ctx context.Context, subdomains []string, nameservers []string, timeout time.Duration, concurrency int) []Result {
	if concurrency <= 0 {
		concurrency = 500
	}
	results := make([]Result, len(subdomains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, sub := range subdomains {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, s string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = Resolve(ctx, s, nameservers, timeout)
		}(i, sub)
	}
	wg.Wait()
	return results
}

// ValidateResolvers filters out broken DNS resolvers by doing a test query.
func ValidateResolvers(resolvers []string, timeout time.Duration) []string {
	var mu sync.Mutex
	var valid []string
	var wg sync.WaitGroup

	for _, ns := range resolvers {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			c := &dns.Client{Net: "udp", Timeout: timeout}
			msg := new(dns.Msg)
			msg.SetQuestion("google.com.", dns.TypeA)
			msg.RecursionDesired = true
			resp, _, err := c.Exchange(msg, r)
			if err == nil && resp != nil && len(resp.Answer) > 0 {
				mu.Lock()
				valid = append(valid, r)
				mu.Unlock()
			}
		}(ns)
	}
	wg.Wait()
	return valid
}

// LoadResolverList reads a newline-separated file of resolver IPs and formats them as host:port.
func LoadResolverList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.SplitHostPort(line); err != nil {
			line = line + ":53"
		}
		out = append(out, line)
	}
	return out, nil
}
