package summary

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
)

type Stats struct {
	mu              sync.Mutex
	Total           int
	Active          int
	Wildcards       int
	Takeovers       int
	CORSIssues      int
	MissingHSTS     int
	SSLExpiring     int
	SSLExpired      int
	WAFDetected     int
	ByCloud         map[string]int
	ByStatus        map[int]int
	ByTech          map[string]int
	AdminPanels     int
	JSSecrets       int
	ExposedFiles    int
	PublicBuckets   int
	OpenRedirects   int
	DefaultCreds    int
	VHostsFound     int
	GraphQLFound    int
	SwaggerFound    int
	BannersFound    int
	CertRelated     int
	NeighborsFound  int
	InternetDBCVEs  int
	MaliciousIPs    int
	CookieIssues    int
	MixedContent    int
	JWTsFound       int
	SSRFFound       int
	Log4ShellFound  int
	NucleiFindings  int
	DSStoreFound    int
	TechsDetected   int
	CVEsFound       int
	FuzzHits        int
	DangerousMethods int
	CachePoisoned   int
	DebugEndpoints  int
}

func New() *Stats {
	return &Stats{
		ByCloud:  make(map[string]int),
		ByStatus: make(map[int]int),
		ByTech:   make(map[string]int),
	}
}

func (s *Stats) Add(r resolver.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Total++
	if !r.Active {
		return
	}
	s.Active++

	if r.IsWildcard {
		s.Wildcards++
	}
	if r.Takeover != nil {
		s.Takeovers++
	}
	if r.Cloud != "" {
		s.ByCloud[r.Cloud]++
	}
	if r.HTTP != nil {
		s.ByStatus[r.HTTP.StatusCode]++
		for _, t := range r.HTTP.Tech {
			s.ByTech[t]++
		}
	}
	if r.SecurityHeaders != nil && !r.SecurityHeaders.HSTS {
		s.MissingHSTS++
	}
	if r.CORS != nil && r.CORS.Vulnerable {
		s.CORSIssues++
	}
	if r.TLS != nil {
		if r.TLS.Expired {
			s.SSLExpired++
		} else if r.TLS.DaysUntilExpiry < 30 {
			s.SSLExpiring++
		}
	}
	if r.WAF != "" {
		s.WAFDetected++
	}
	if len(r.AdminPanels) > 0 {
		s.AdminPanels += len(r.AdminPanels)
	}
	if r.JS != nil && len(r.JS.Secrets) > 0 {
		s.JSSecrets += len(r.JS.Secrets)
	}
	s.ExposedFiles += len(r.ExposedFiles)
	s.OpenRedirects += len(r.OpenRedirects)
	s.DefaultCreds += len(r.DefaultCreds)
	s.VHostsFound += len(r.VHosts)
	s.BannersFound += len(r.Banners)
	s.NeighborsFound += len(r.Neighbors)
	for _, b := range r.Buckets {
		if b.Public {
			s.PublicBuckets++
		}
	}
	if r.APIs != nil {
		if r.APIs.HasGraphQL {
			s.GraphQLFound++
		}
		if r.APIs.HasSwagger {
			s.SwaggerFound++
		}
	}
	if r.CertCorrelate != nil {
		s.CertRelated += len(r.CertCorrelate.RelatedDomains)
	}
	if r.InternetDB != nil {
		s.InternetDBCVEs += len(r.InternetDB.CVEs)
	}
	if r.GreyNoise != nil && r.GreyNoise.Classification == "malicious" {
		s.MaliciousIPs++
	}
	if r.Cookies != nil {
		s.CookieIssues += len(r.Cookies.Issues)
	}
	s.MixedContent += len(r.MixedContent)
	s.JWTsFound += len(r.JWTs)
	s.SSRFFound += len(r.SSRFParams)
	if r.Log4ShellVuln {
		s.Log4ShellFound++
	}
	if r.NucleiFindings != nil {
		s.NucleiFindings += len(r.NucleiFindings.Findings)
	}
	if len(r.DSStoreFiles) > 0 {
		s.DSStoreFound++
	}
	s.TechsDetected += len(r.Techs)
	s.CVEsFound += len(r.CVEs)
	s.FuzzHits += len(r.FuzzHits)
	if r.HTTPMethods != nil {
		s.DangerousMethods += len(r.HTTPMethods.DangerousMethods)
	}
	s.CachePoisoned += len(r.CachePoison)
	s.DebugEndpoints += len(r.ErrorDisc)
}

func (s *Stats) Print() {
	s.mu.Lock()
	defer s.mu.Unlock()

	sep := strings.Repeat("─", 40)
	fmt.Printf("\n\033[1m[*] Summary\033[0m\n%s\n", sep)
	fmt.Printf("  Total enumerated  : %d\n", s.Total)
	fmt.Printf("  Active            : %d\n", s.Active)
	fmt.Printf("  Wildcards filtered: %d\n", s.Wildcards)

	if len(s.ByCloud) > 0 {
		fmt.Printf("%s\n  Cloud providers:\n", sep)
		for _, k := range sortedKeys(s.ByCloud) {
			fmt.Printf("    %-20s %d\n", k, s.ByCloud[k])
		}
	}

	if len(s.ByStatus) > 0 {
		fmt.Printf("%s\n  HTTP status codes:\n", sep)
		codes := make([]int, 0, len(s.ByStatus))
		for k := range s.ByStatus {
			codes = append(codes, k)
		}
		sort.Ints(codes)
		for _, code := range codes {
			fmt.Printf("    %-6d %d\n", code, s.ByStatus[code])
		}
	}

	if len(s.ByTech) > 0 {
		fmt.Printf("%s\n  Technologies:\n", sep)
		top := topN(s.ByTech, 10)
		for _, k := range top {
			fmt.Printf("    %-20s %d\n", k, s.ByTech[k])
		}
	}

	fmt.Printf("%s\n  Security findings:\n", sep)
	printFinding("Takeovers", s.Takeovers, "\033[31m")
	printFinding("CORS vulnerable", s.CORSIssues, "\033[31m")
	printFinding("Open redirects", s.OpenRedirects, "\033[33m")
	printFinding("Default credentials", s.DefaultCreds, "\033[31m")
	printFinding("Exposed files", s.ExposedFiles, "\033[31m")
	printFinding("Public buckets", s.PublicBuckets, "\033[31m")
	printFinding("Missing HSTS", s.MissingHSTS, "\033[33m")
	printFinding("SSL expired", s.SSLExpired, "\033[31m")
	printFinding("SSL expiring (<30d)", s.SSLExpiring, "\033[33m")
	printFinding("WAF detected", s.WAFDetected, "\033[32m")
	printFinding("Admin panels found", s.AdminPanels, "\033[33m")
	printFinding("JS secrets detected", s.JSSecrets, "\033[31m")
	printFinding("Virtual hosts found", s.VHostsFound, "\033[36m")
	printFinding("GraphQL endpoints", s.GraphQLFound, "\033[33m")
	printFinding("Swagger/OpenAPI found", s.SwaggerFound, "\033[33m")
	printFinding("Banners grabbed", s.BannersFound, "\033[36m")
	printFinding("Cert-related domains", s.CertRelated, "\033[36m")
	printFinding("Neighbors found", s.NeighborsFound, "\033[36m")
	printFinding("InternetDB CVEs", s.InternetDBCVEs, "\033[31m")
	printFinding("Malicious IPs (GreyNoise)", s.MaliciousIPs, "\033[31m")
	printFinding("Cookie issues", s.CookieIssues, "\033[33m")
	printFinding("Mixed content", s.MixedContent, "\033[33m")
	printFinding("JWT tokens found", s.JWTsFound, "\033[33m")
	printFinding("SSRF params found", s.SSRFFound, "\033[31m")
	printFinding("Log4Shell detections", s.Log4ShellFound, "\033[31m")
	printFinding("Nuclei findings", s.NucleiFindings, "\033[31m")
	printFinding(".DS_Store exposed", s.DSStoreFound, "\033[31m")
	printFinding("Techs detected", s.TechsDetected, "\033[36m")
	printFinding("CVEs found", s.CVEsFound, "\033[31m")
	printFinding("Fuzz hits", s.FuzzHits, "\033[33m")
	printFinding("Dangerous HTTP methods", s.DangerousMethods, "\033[31m")
	printFinding("Cache poisoning", s.CachePoisoned, "\033[31m")
	printFinding("Debug endpoints", s.DebugEndpoints, "\033[31m")
	fmt.Println(sep)
}

func printFinding(label string, count int, color string) {
	if count == 0 {
		fmt.Printf("    %-24s \033[90m0\033[0m\n", label)
		return
	}
	fmt.Printf("    %-24s %s%d\033[0m\n", label, color, count)
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
	return keys
}

func topN(m map[string]int, n int) []string {
	keys := sortedKeys(m)
	if len(keys) > n {
		return keys[:n]
	}
	return keys
}
