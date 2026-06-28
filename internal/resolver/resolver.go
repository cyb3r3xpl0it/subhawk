package resolver

import (
	"context"
	"net"
	"time"
)

type SecurityHeadersInfo struct {
	HSTS              bool
	CSP               bool
	XFrameOptions     bool
	XContentTypeOpts  bool
	ReferrerPolicy    bool
	PermissionsPolicy bool
	XXSSProtection    bool
	Missing           []string
	Score             int
}

type CORSInfo struct {
	Vulnerable            bool
	AllowsArbitraryOrigin bool
	AllowsCredentials     bool
	AllowOrigin           string
}

type TLSInfo struct {
	Valid            bool
	SelfSigned       bool
	Expired          bool
	HostnameMismatch bool
	DaysUntilExpiry  int
	Version          string
	Issuer           string
	Subject          string
	SANs             []string
	WeakProtocol     bool
}

type ASNInfo struct {
	IP      string
	ASN     string
	Country string
	City    string
	Region  string
}

type AdminPanel struct {
	URL        string
	StatusCode int
	Title      string
}

type JSInfo struct {
	JSFiles   []string
	Endpoints []string
	URLs      []string
	Secrets   []string
}

type HTTPInfo struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	Tech       []string
}

type TakeoverInfo struct {
	Service     string
	Fingerprint string
}

type DNSRecords struct {
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

type ExposedFile struct {
	Path       string
	StatusCode int
	Size       int64
	URL        string
}

type BucketResult struct {
	URL      string
	Provider string
	Name     string
	Public   bool
	Writable bool
}

type OpenRedirect struct {
	URL   string
	Param string
}

type DefaultCred struct {
	Username string
	Password string
	Method   string
}

type BannerInfo struct {
	Port    int
	Service string
	Raw     string
}

type APIEndpoint struct {
	URL     string
	Type    string
	Details string
}

type APIResult struct {
	Endpoints    []APIEndpoint
	HasGraphQL   bool
	HasSwagger   bool
	HasGRPC      bool
	HasWebSocket bool
}

type WHOISInfo struct {
	Registrar   string
	CreatedAt   string
	ExpiresAt   string
	DNSSEC      string
	Emails      []string
}

type NeighborHost struct {
	IP        string
	Hostnames []string
}

type CertInfo struct {
	RelatedDomains []string
	CertCN         string
	CertIssuer     string
	Fingerprint    string
}

type InternetDBInfo struct {
	Ports     []int
	CVEs      []string
	Tags      []string
	Hostnames []string
	CPEs      []string
}

type GreyNoiseInfo struct {
	Noise          bool
	Riot           bool
	Classification string
	Name           string
	LastSeen       string
}

type AbuseIPDBInfo struct {
	AbuseScore   int
	TotalReports int
	CountryCode  string
	ISP          string
}

type PathDiscResult struct {
	Paths           []string
	DisallowedPaths []string
}

type CookieIssue struct {
	Name  string
	Issue string
}

type CookieCheckResult struct {
	Issues []CookieIssue
	Total  int
	Secure int
}

type JWTFinding struct {
	Token     string
	Algorithm string
	Issues    []string
}

type NucleiResult struct {
	Findings []NucleiFinding
}

type NucleiFinding struct {
	TemplateID string
	Severity   string
	Name       string
	URL        string
}

type Result struct {
	Subdomain       string
	IPs             []string
	CNAME           string
	Active          bool
	IsWildcard      bool
	Source          string
	Cloud           string
	WAF             string
	FaviconHash     string
	RealIP          string
	ScreenshotPath  string
	OpenPorts       []int
	VHosts          []string
	ExposedFiles    []ExposedFile
	Buckets         []BucketResult
	OpenRedirects   []OpenRedirect
	DefaultCreds    []DefaultCred
	Banners         []BannerInfo
	ZoneWalked      []string
	NSECInfo        string
	DNS             *DNSRecords
	HTTP            *HTTPInfo
	Takeover        *TakeoverInfo
	SecurityHeaders *SecurityHeadersInfo
	CORS            *CORSInfo
	TLS             *TLSInfo
	ASN             *ASNInfo
	AdminPanels     []AdminPanel
	JS              *JSInfo
	APIs            *APIResult
	WHOIS           *WHOISInfo
	CertCorrelate   *CertInfo
	Neighbors       []NeighborHost
	InternetDB      *InternetDBInfo
	GreyNoise       *GreyNoiseInfo
	AbuseIPDB       *AbuseIPDBInfo
	Paths           *PathDiscResult
	DSStoreFiles    []string
	Cookies         *CookieCheckResult
	MixedContent    []string
	JWTs            []JWTFinding
	SSRFParams      []string
	Log4ShellVuln   bool
	NucleiFindings  *NucleiResult
	ASNCIDRs        []string
	DNSHistory      []string
	ReverseWhois    []string
}

var defaultResolvers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

type Resolver struct {
	resolvers   []string
	timeout     time.Duration
	wildcardIPs map[string]bool
}

func New(resolvers []string, timeout time.Duration) *Resolver {
	if len(resolvers) == 0 {
		resolvers = defaultResolvers
	}
	return &Resolver{
		resolvers:   resolvers,
		timeout:     timeout,
		wildcardIPs: map[string]bool{},
	}
}

func (r *Resolver) SetWildcardIPs(ips []string) {
	for _, ip := range ips {
		r.wildcardIPs[ip] = true
	}
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

			if len(r.wildcardIPs) > 0 {
				wildcard := true
				for _, ip := range addrs {
					if !r.wildcardIPs[ip] {
						wildcard = false
						break
					}
				}
				result.IsWildcard = wildcard
			}

			cname, cerr := resolver.LookupCNAME(ctx, subdomain)
			if cerr == nil {
				result.CNAME = cname
			}
			return result
		}
	}
	return result
}
