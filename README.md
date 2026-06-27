# SubHawk

Fast subdomain enumeration and security analysis tool written in Go. Combines passive sources, active DNS brute-force, HTTP probing, takeover detection, port scanning, cloud detection, tech fingerprinting, security audits, and an interactive TUI.

## Features

### Enumeration
- **18 passive sources**: crt.sh, AlienVault OTX, HackerTarget, RapidDNS, URLScan, Wayback Machine, ThreatMiner, TLS certificate scraping, CommonCrawl, LeakIX, GitHub code search + VirusTotal, SecurityTrails, Shodan, Censys, Chaos, FullHunt, Bevigil (API key)
- **DNS zone transfer (AXFR)**: attempts zone transfer on all nameservers
- **Active brute-force**: concurrent DNS resolution with custom resolvers and rate limiting
- **Fast resolver**: raw UDP massdns-style bulk resolution (10x+ faster, `--fast-resolve`)
- **Resolver validation**: filter broken resolvers before scanning (`--validate-resolvers`)
- **Resolver list**: load hundreds of resolvers from file (`--resolver-file`)
- **Wildcard detection**: automatically detects and filters wildcard DNS responses
- **Full DNS records**: 17 record types — A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR, DMARC, SPF, DNSKEY, DS, TLSA, NAPTR, HTTPS
- **Permutation engine**: generates and tests mutations from found subdomains
- **Recursive enumeration**: enumerates subdomains of found subdomains

### HTTP & Cloud
- **Cloud detection**: AWS (EC2, CloudFront, S3, ELB), GCP, Azure, Cloudflare, Fastly, Akamai, GitHub Pages, Vercel, Netlify, Heroku, DigitalOcean
- **HTTP probing**: status code, page title, server header, redirect following
- **Tech fingerprinting**: WordPress, Laravel, Django, Next.js, Nginx, Cloudflare, and 20+ more
- **Takeover detection**: 18 services (GitHub Pages, Heroku, S3, Netlify, Vercel, Azure, and more)
- **Port scanning**: checks 30 common ports on active subdomains
- **Virtual host fuzzing**: discover hidden vhosts by sending different Host headers (`--vhost`)
- **Screenshots**: capture PNG screenshots of each active subdomain via headless Chrome (`--screenshot`)

### Security Audit
- **Security headers**: audit HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy (score 0-100)
- **CORS check**: detect misconfigured CORS (reflected arbitrary origin, wildcard, null+credentials)
- **SSL/TLS audit**: certificate validity, expiry days, self-signed, hostname mismatch, weak protocol
- **WAF detection**: fingerprint 14 WAF/CDN providers (Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity, and more)
- **Favicon hash**: Shodan-compatible MurmurHash3 of favicon for asset pivoting
- **ASN/GeoIP**: autonomous system number and geolocation via ipinfo.io (no API key needed)
- **JS scraping**: discover endpoints, URLs, and exposed secrets from JavaScript files
- **Admin panel detection**: probe 30 common admin and login paths
- **Exposed files**: detect `.git`, `.env`, `.DS_Store`, backup files, config files, and 30+ more sensitive paths (`--exposed`)
- **Cloud bucket check**: enumerate and test S3, GCS, and Azure Blob containers for public access (`--buckets`)
- **Open redirect**: test 20+ common redirect parameters for open redirect vulnerabilities (`--open-redirect`)
- **Default credentials**: test detected admin panels for common default credential pairs (`--default-creds`)
- **CDN real IP bypass**: find the real IP behind Cloudflare/CDN via SPF records, MX, historical DNS, and common bypass subdomains (`--cdn-bypass`)
- **Email security score**: SPF, DMARC, DKIM score (0-100, grade A-F)

### Output & Reporting
- **Summary report**: aggregated findings — cloud breakdown, HTTP status codes, tech stack, security issues
- **HTML report**: standalone self-contained HTML report with dark theme and filterable table (`--report`)
- **SQLite storage**: save all results to a local database with `--db results.db`
- **SARIF output**: GitHub Actions security tab compatible (`-f sarif`)
- **Interactive TUI**: real-time progress display with counters and live findings
- **Output formats**: colored text, JSON, CSV, Nuclei, Burp Suite scope, SARIF

### Workflow
- **Resume**: saves checkpoint and continues interrupted scans
- **Diff mode**: shows only new subdomains compared to a previous run
- **Exclude**: filter subdomains by list or glob patterns
- **Multi-domain**: enumerate a list of domains from a file
- **Config file**: store API keys in `~/.config/subhawk/config.yaml`
- **Cross-platform**: Linux, macOS, Windows

## Installation

### From releases

Download the latest binary from [Releases](https://github.com/cyb3r3xpl0it/subhawk/releases).

### From source

```bash
go install github.com/cyb3r3xpl0it/subhawk@latest
```

> **Screenshots** (`--screenshot`) require Google Chrome or Chromium installed on the system.

## Quick start

```bash
# Passive enumeration only
subhawk -d example.com

# Active scan with brute-force
subhawk -d example.com -w wordlists/common.txt -a -p -T --axfr

# Maximum speed with fast resolver
subhawk -d example.com -w wordlists/common.txt --fast-resolve --resolver-file resolvers.txt --validate-resolvers

# Full security audit
subhawk -d example.com -a -p --headers --cors --ssl --waf --favicon --asn --js-scrape --admin-detect --exposed --open-redirect --cdn-bypass --summary

# Cloud & bucket check
subhawk -d example.com --buckets --cdn-bypass

# Admin panels + default credentials
subhawk -d example.com --admin-detect --default-creds

# Virtual host discovery
subhawk -d example.com -w wordlists/common.txt --vhost

# Take screenshots
subhawk -d example.com -a -p --screenshot --screenshot-dir ./shots

# Generate HTML report
subhawk -d example.com -a -p --headers --cors --ssl --report report.html

# GitHub Actions (SARIF output)
subhawk -d example.com -a -f sarif -o results.sarif

# Email security score
subhawk -d example.com --email-score

# Save to SQLite + HTML report
subhawk -d example.com -a -p --db results.db --report report.html --summary

# Interactive TUI mode
subhawk -d example.com -w wordlists/common.txt --tui

# Compare with previous run
subhawk -d example.com --diff previous_results.json

# Resume an interrupted scan
subhawk -d example.com --resume
```

## Flags

### Targets
| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain |
| `-D, --domains-file` | File with list of domains (one per line) |

### Sources
| Flag | Default | Description |
|------|---------|-------------|
| `-w, --wordlist` | — | Wordlist for DNS brute-force |
| `--axfr` | `false` | Attempt DNS zone transfer on all nameservers |

### DNS Resolution
| Flag | Default | Description |
|------|---------|-------------|
| `-r, --resolvers` | — | Custom DNS resolvers, comma-separated |
| `--resolver-file` | — | File with resolver IPs (one per line) |
| `--fast-resolve` | `false` | Raw UDP bulk resolver (massdns-style, 10x faster) |
| `--validate-resolvers` | `false` | Validate all resolvers before scanning |
| `-t, --threads` | `50` | Concurrent DNS resolvers |
| `--timeout` | `5` | DNS timeout in seconds |
| `--rate-limit` | `0` | Max DNS requests per second (0 = unlimited) |

### Analysis
| Flag | Default | Description |
|------|---------|-------------|
| `-p, --probe` | `false` | HTTP probe + tech fingerprinting |
| `-T, --takeover` | `false` | Subdomain takeover detection |
| `--portscan` | `false` | Scan 30 common ports on active subdomains |
| `--dns-records` | — | DNS record types to fetch, comma-separated (empty = all 17) |
| `--permutation` | `false` | Generate and test permutations from found subdomains |
| `--recursive` | `0` | Recursive enumeration depth (0 = disabled) |
| `--vhost` | `false` | Virtual host fuzzing (uses `--wordlist`) |

### Security Audit
| Flag | Default | Description |
|------|---------|-------------|
| `--headers` | `false` | Audit HTTP security headers |
| `--cors` | `false` | Check for CORS misconfigurations |
| `--ssl` | `false` | Audit SSL/TLS certificates |
| `--waf` | `false` | Detect WAF/CDN provider |
| `--favicon` | `false` | Calculate Shodan-compatible favicon hash |
| `--asn` | `false` | Lookup ASN and GeoIP for each IP |
| `--js-scrape` | `false` | Scrape JS files for endpoints and secrets |
| `--admin-detect` | `false` | Probe 30 common admin/login paths |
| `--exposed` | `false` | Check for exposed sensitive files (.git, .env, backups…) |
| `--buckets` | `false` | Check for public S3, GCS, and Azure buckets |
| `--open-redirect` | `false` | Test for open redirect vulnerabilities |
| `--default-creds` | `false` | Test admin panels for default credentials |
| `--cdn-bypass` | `false` | Find real IP behind CDN/Cloudflare |
| `--email-score` | `false` | Calculate email security score (SPF/DMARC/DKIM) |
| `--screenshot` | `false` | Take screenshots (requires Chrome/Chromium) |
| `--screenshot-dir` | `screenshots` | Directory to save screenshots |

### Filtering
| Flag | Description |
|------|-------------|
| `-a, --active` | Show only active (resolved) subdomains |
| `--exclude` | Comma-separated subdomains/glob patterns to exclude |
| `--exclude-file` | File with exclusion patterns (one per line) |
| `--diff` | Show only new subdomains vs. a previous results file |

### Output
| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | — | Output file |
| `-f, --format` | `text` | Format: `text`, `json`, `csv`, `nuclei`, `burp`, `sarif` |
| `--db` | — | Save results to SQLite database |
| `--report` | — | Generate standalone HTML report |
| `--no-color` | `false` | Disable colored output |
| `--summary` | `false` | Print summary report at end of scan |
| `--tui` | `false` | Interactive TUI mode |

### State
| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | `~/.config/subhawk/config.yaml` | Config file path |
| `--resume` | `false` | Resume from checkpoint of a previous interrupted scan |

## Sources

| Source | Type | Requires |
|--------|------|----------|
| crt.sh | Certificate Transparency | Free |
| AlienVault OTX | Passive DNS | Free |
| HackerTarget | Host search | Free |
| RapidDNS | DNS database | Free |
| URLScan.io | URL scanner | Free |
| Wayback Machine | Historical URLs | Free |
| ThreatMiner | Threat intel | Free |
| TLS Scraper | Live certificate SANs | Free |
| CommonCrawl | Web crawl index | Free |
| LeakIX | Leak database | Free (limited) |
| GitHub | Code search | Free (token recommended) |
| VirusTotal | Passive DNS | API key |
| SecurityTrails | DNS history | API key |
| Shodan | Internet scanner | API key |
| Censys | Certificate search | API key |
| Chaos | ProjectDiscovery DNS | API key |
| FullHunt | Attack surface | API key |
| Bevigil | Mobile app intel | API key |

## Config file

Run `subhawk init-config` to create the default config file, then add your API keys:

```yaml
api_keys:
  virustotal: ""
  securitytrails: ""
  shodan: ""
  censys_id: ""
  censys_secret: ""
  chaos: ""
  fullhunt: ""
  bevigil: ""
  leakix: ""
  github_token: ""
```

Default config location by OS:

| OS | Path |
|----|------|
| Linux | `~/.config/subhawk/config.yaml` |
| macOS | `~/Library/Application Support/subhawk/config.yaml` |
| Windows | `%APPDATA%\subhawk\config.yaml` |

## Output example

```
[+] api.example.com [1.2.3.4] [AWS CloudFront] [200] [API Portal] [nginx, Next.js] [WAF:Cloudflare] [headers:72/100] [AS13335/US]
[+] mail.example.com [1.2.3.6] [200] [Webmail] [headers:45/100] [CORS:vulnerable] [SSL:expires-12d] [realip:5.6.7.8]
[+] admin.example.com [1.2.3.7] [401] [WAF:AWS WAF] [admin:3] [secrets:2] [exposed:1] [creds:1]
[+] dev.example.com [1.2.3.8] [200] [Dev App] [buckets:2] [redirect:1] [vhosts:3] [screenshot]
[TAKEOVER] old.example.com [GitHub Pages]
[~] wildcard.example.com [wildcard]
[-] test.example.com

[*] Summary
────────────────────────────────────────
  Total enumerated  : 247
  Active            : 103
  Wildcards filtered: 5

  Cloud providers:
    AWS                  48
    Cloudflare           31
    GCP                  12

  Security findings:
    Takeovers               1
    CORS vulnerable         3
    Open redirects          2
    Default credentials     1
    Exposed files           7
    Public buckets          2
    Missing HSTS           22
    SSL expiring (<30d)     4
    WAF detected           31
    Admin panels found      9
    JS secrets detected     6
    Virtual hosts found    14
```

## DNS record types

| Type | Description |
|------|-------------|
| `A`, `AAAA` | IPv4 / IPv6 addresses |
| `CNAME` | Canonical name (takeover detection) |
| `MX` | Mail exchange |
| `TXT` | Text (SPF, DKIM, verification) |
| `NS` | Nameservers |
| `SOA` | Start of authority |
| `SRV` | Service locator (LDAP, SIP, Kerberos) |
| `CAA` | CA authorization |
| `PTR` | Reverse DNS |
| `DMARC` | Email policy |
| `SPF` | Sender policy |
| `DNSKEY`, `DS` | DNSSEC |
| `TLSA` | Certificate pinning (DANE) |
| `NAPTR` | VoIP/SIP |
| `HTTPS` | HTTP/3, ECH support |

## License

MIT — see [LICENSE](LICENSE)
