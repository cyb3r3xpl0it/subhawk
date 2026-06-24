# SubHawk

Fast subdomain enumeration tool written in Go. Combines passive sources, active DNS brute-force, HTTP probing, takeover detection, port scanning, cloud detection, tech fingerprinting, recursive enumeration, and more.

## Features

- **12 passive sources**: crt.sh, AlienVault OTX, HackerTarget, RapidDNS, URLScan, Wayback Machine, ThreatMiner, TLS certificate scraping + VirusTotal, SecurityTrails, Shodan, Censys (API key)
- **DNS zone transfer (AXFR)**: attempts zone transfer on all nameservers
- **Active brute-force**: concurrent DNS resolution with custom resolvers and rate limiting
- **Wildcard detection**: automatically detects and filters wildcard DNS responses
- **Full DNS records**: A, AAAA, MX, TXT, NS per subdomain
- **Cloud detection**: identifies AWS, GCP, Azure, Cloudflare, Fastly, Akamai, and more
- **HTTP probing**: status code, page title, server header
- **Tech fingerprinting**: WordPress, Laravel, Django, Next.js, Nginx, Cloudflare, and 20+ more
- **Takeover detection**: 18 services (GitHub Pages, Heroku, S3, Netlify, Vercel, Azure, and more)
- **Port scanning**: checks 30 common ports on active subdomains
- **Permutation engine**: generates mutations from found subdomains
- **Recursive enumeration**: enumerates subdomains of found subdomains
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

# Full recon: all features enabled
subhawk -d example.com -w wordlists/common.txt -a -p -T --portscan --permutation --dns-records --axfr

# Export to Nuclei
subhawk -d example.com -a -f nuclei -o targets.txt

# Export Burp Suite scope
subhawk -d example.com -a -f burp -o scope.json

# Compare with previous run (show only new subdomains)
subhawk -d example.com --diff previous_results.json

# Resume an interrupted scan
subhawk -d example.com --resume

# Multiple domains from file
subhawk -D domains.txt -a -p
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
| `--dns-records` | `false` | Fetch full DNS records (A, AAAA, MX, TXT, NS) |
| `--permutation` | `false` | Generate and test permutations from found subdomains |
| `--recursive` | `0` | Recursive enumeration depth (0 = disabled) |

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
| `--no-color` | `false` | Disable colored output |

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

## Config file

Run `subhawk init-config` to create the default config file, then add your API keys:

```yaml
# ~/.config/subhawk/config.yaml
api_keys:
  virustotal: ""
  securitytrails: ""
  shodan: ""
  censys_id: ""
  censys_secret: ""
```

## Cloud detection

SubHawk automatically identifies the cloud provider from CNAMEs and IP ranges:

AWS (EC2, CloudFront, S3, ELB), Google Cloud, Azure, Cloudflare, Fastly, Akamai, GitHub Pages, Vercel, Netlify, Heroku, DigitalOcean.

## Takeover detection

SubHawk checks CNAMEs against 18 known vulnerable services:

GitHub Pages, Heroku, Amazon S3, Netlify, Vercel, Fastly, Shopify, Tumblr, Zendesk, Freshdesk, Surge.sh, readme.io, Ghost, Azure, Bitbucket, HubSpot, Intercom, Webflow.

## Output example

```
[+] api.example.com [1.2.3.4] [AWS CloudFront] [ports:80,443] [200] [API Portal] [nginx, Next.js]
[+] dev.example.com [1.2.3.5] [Cloudflare] [401] [Unauthorized]
[TAKEOVER] old.example.com [GitHub Pages]
[~] wildcard.example.com [wildcard]
[-] test.example.com
```

## License

MIT — see [LICENSE](LICENSE)
