package resolver

import (
	"testing"
	"time"
)

func TestNew_DefaultResolvers(t *testing.T) {
	r := New(nil, 5*time.Second)
	if len(r.resolvers) == 0 {
		t.Fatal("expected default resolvers, got none")
	}
}

func TestNew_CustomResolvers(t *testing.T) {
	custom := []string{"8.8.8.8:53", "1.1.1.1:53"}
	r := New(custom, 5*time.Second)
	if len(r.resolvers) != 2 {
		t.Fatalf("expected 2 resolvers, got %d", len(r.resolvers))
	}
}

func TestResolve_KnownDomain(t *testing.T) {
	r := New(nil, 5*time.Second)
	result := r.Resolve("google.com")
	if !result.Active {
		t.Error("expected google.com to resolve as active")
	}
	if len(result.IPs) == 0 {
		t.Error("expected at least one IP for google.com")
	}
}

func TestResolve_InvalidDomain(t *testing.T) {
	r := New(nil, 3*time.Second)
	result := r.Resolve("this-domain-does-not-exist-subhawk-test.invalid")
	if result.Active {
		t.Error("expected invalid domain to be inactive")
	}
}

func TestResolve_SubdomainField(t *testing.T) {
	r := New(nil, 5*time.Second)
	sub := "www.google.com"
	result := r.Resolve(sub)
	if result.Subdomain != sub {
		t.Errorf("expected Subdomain=%q, got %q", sub, result.Subdomain)
	}
}
