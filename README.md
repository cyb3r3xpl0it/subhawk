# SubHawk

Fast subdomain enumeration and security analysis tool written in Go. Combines passive sources, active DNS brute-force, HTTP probing, takeover detection, port scanning, cloud detection, tech fingerprinting, security audits, and an interactive TUI.

## Features

### Enumeration
- **12 passive sources**: crt.sh, AlienVault OTX, HackerTarget, RapidDNS, URLScan, Wayback Machine, ThreatMiner, TLS certificate scraping + VirusTotal, SecurityTrails, Shodan, Censys (API key)
- **DNS zone transfer (AXFR)**: attempts zone transfer on all nameservers
- **Active brute-force**: concurrent DNS resolution with custom resolvers and rate limiting
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

### Security Audit (v1.3.0)
- **Security headers**: audit HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy (score 0-100)
- **CORS check**: detect misconfigured CORS (reflected arbitrary origin, wildcard, null+credentials)
- **SSL/TLS audit**: certificate validity, expiry days, self-signed, hostname mismatch, weak protocol
- **WAF detection**: fingerprint 14 WAF/CDN providers (Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity, and more)
- **Favicon hash**: Shodan-compatible MurmurHash3 of favicon for asset pivoting
- **ASN/GeoIP**: autonomous system number and geolocation via ipinfo.io (no API key needed)
- **JS scraping**: discover endpoints, URLs, and exposed secrets from JavaScript files
- **Admin panel detection**: probe 30 common admin and login paths
- **Email security score**: SPF, DMARC, DKIM score (0-100, grade A-F)

### Workflow
- **Summary report**: aggregated findings — cloud breakdown, HTTP status codes, tech stack, security issues
- **SQLite storage**: save all results to a local database with `--db results.db`
- **Interactive TUI**: real-time progress display with counters and live findings
- **Resume**: saves checkpoint and continues interrupted scans
- **Diff mode**: shows only new subdomains compared to a previous run
- **Exclude**: filter subdomains by list or glob patterns
- **Multi-domain**: enumerate a list of domains from a file
- **Output formats**: colored text, JSON, CSV, Nuclei, Burp Suite scope
- **Config file**: store API keys in `~/.config/subhawk/config.yaml`
- **Cross-platform**: Linux, macOS, Windows

## Installation

### From releases

Download the latest binary from [Releases](https://github.com/cyb3r3xpl0it/subhawk/releases).

### From source

```bash
go install github.com/cyb3r3xpl0it/subhawk@latest
```

## Quick start

```bash
# Passive enumeration only
subhawk -d example.com

# Show only active subdomains
subhawk -d example.com -a

# Full passive + active scan
subhawk -d example.com -w wordlists/common.txt -a -p -T --portscan --permutation --axfr

# Full security audit
subhawk -d example.com -a -p --headers --cors --ssl --waf --favicon --asn --js-scrape --admin-detect --summary

# Email security score
subhawk -d example.com --email-score

# Specific DNS record types
subhawk -d example.com --dns-records MX,SPF,DMARC
subhawk -d example.com --dns-records SRV,NAPTR,CAA,TLSA

# Save to SQLite database
subhawk -d example.com -a -p --db results.db

# Interactive TUI mode
subhawk -d example.com -w wordlists/common.txt --tui

# Export to Nuclei
subhawk -d example.com -a -f nuclei -o targets.txt

# Export Burp Suite scope
subhawk -d example.com -a -f burp -o scope.json

# Compare with previous run (show only new subdomains)
subhawk -d example.com --diff previous_results.json

# Resume an interrupted scan
subhawk -d example.com --resume

# Multiple domains from file
subhawk -D domains.txt -a -p --summary
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

### Analysis
| Flag | Default | Description |
|------|---------|-------------|
| `-p, --probe` | `false` | HTTP probe + tech fingerprinting |
| `-T, --takeover` | `false` | Subdomain takeover detection |
| `--portscan` | `false` | Scan 30 common ports on active subdomains |
| `--dns-records` | — | DNS record types to fetch, comma-separated (empty = all 17 types) |
| `--permutation` | `false` | Generate and test permutations from found subdomains |
| `--recursive` | `0` | Recursive enumeration depth (0 = disabled) |

### Security Audit
| Flag | Default | Description |
|------|---------|-------------|
| `--headers` | `false` | Audit HTTP security headers (HSTS, CSP, X-Frame-Options, …) |
| `--cors` | `false` | Check for CORS misconfigurations |
| `--ssl` | `false` | Audit SSL/TLS certificates |
| `--waf` | `false` | Detect WAF/CDN provider |
| `--favicon` | `false` | Calculate Shodan-compatible favicon hash |
| `--asn` | `false` | Lookup ASN and GeoIP for each IP |
| `--js-scrape` | `false` | Scrape JS files for endpoints and secrets |
| `--admin-detect` | `false` | Probe 30 common admin/login paths |
| `--email-score` | `false` | Calculate email security score (SPF/DMARC/DKIM) |

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
| `-f, --format` | `text` | Format: `text`, `json`, `csv`, `nuclei`, `burp` |
| `--db` | — | Save results to SQLite database (e.g. `results.db`) |
| `--no-color` | `false` | Disable colored output |
| `--summary` | `false` | Print summary report at end of scan |
| `--tui` | `false` | Interactive TUI mode |

### Performance
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --threads` | `50` | Concurrent DNS resolvers |
| `--timeout` | `5` | DNS timeout in seconds |
| `--rate-limit` | `0` | Max DNS requests per second (0 = unlimited) |
| `-r, --resolvers` | — | Custom DNS resolvers, comma-separated (e.g. `8.8.8.8:53`) |

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
| VirusTotal | Passive DNS | API key |
| SecurityTrails | DNS history | API key |
| Shodan | Internet scanner | API key |
| Censys | Certificate search | API key |

## DNS record types

| Type | Description | Use case |
|------|-------------|----------|
| `A` | IPv4 address | Host discovery |
| `AAAA` | IPv6 address | IPv6 hosts |
| `CNAME` | Canonical name | Takeover detection |
| `MX` | Mail exchange | Email infrastructure |
| `TXT` | Text records | SPF, DKIM, verification tokens |
| `NS` | Nameservers | Zone delegation |
| `SOA` | Start of authority | Zone serial, change tracking |
| `SRV` | Service locator | Internal services (LDAP, SIP, Kerberos) |
| `CAA` | CA authorization | Certificate policy misconfigurations |
| `PTR` | Reverse DNS | Real hostname from IP |
| `DMARC` | Email policy | Email spoofing posture |
| `SPF` | Sender policy | Email spoofing posture |
| `DNSKEY` | DNSSEC public key | DNSSEC validation |
| `DS` | Delegation signer | DNSSEC chain |
| `TLSA` | Certificate pinning | DANE validation |
| `NAPTR` | Naming authority | VoIP/SIP infrastructure |
| `HTTPS` | HTTPS/SVCB binding | HTTP/3, ECH support |

## Config file

Run `subhawk init-config` to create the default config file, then add your API keys:

```yaml
api_keys:
  virustotal: ""
  securitytrails: ""
  shodan: ""
  censys_id: ""
  censys_secret: ""
```

Default config location by OS:

| OS | Path |
|----|------|
| Linux | `~/.config/subhawk/config.yaml` |
| macOS | `~/Library/Application Support/subhawk/config.yaml` |
| Windows | `%APPDATA%\subhawk\config.yaml` |

Use `-c` to specify a custom path:

```bash
subhawk -d example.com -c /path/to/config.yaml
```

## Output example

```
[+] api.example.com [1.2.3.4] [AWS CloudFront] [200] [API Portal] [nginx, Next.js] [WAF:Cloudflare] [headers:72/100] [AS13335/US]
[+] mail.example.com [1.2.3.6] [200] [Webmail] [headers:45/100] [CORS:vulnerable] [SSL:expires-12d]
[+] admin.example.com [1.2.3.7] [401] [WAF:AWS WAF] [admin:3] [secrets:2]
[TAKEOVER] old.example.com [GitHub Pages]
[~] wildcard.example.com [wildcard]
[-] test.example.com

[*] Summary
────────────────────────────────────────
  Total enumerated  : 120
  Active            : 84
  Wildcards filtered: 3
  Security findings:
    Takeovers               1
    CORS vulnerable         2
    Missing HSTS            18
    SSL expiring (<30d)     3
    Admin panels found      7
    JS secrets detected     4
```

## Email security score example

```
[*] Email Security Score for example.com: 86/100 (Grade B)
    SPF  (33): v=spf1 include:_spf.google.com -all
    DMARC(20): v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
    DKIM (34): found
```

## License

MIT — see [LICENSE](LICENSE)
