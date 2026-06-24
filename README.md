# SubHawk

Fast subdomain enumeration tool written in Go. Combines passive sources, active DNS brute-force, HTTP probing, takeover detection, wildcard filtering, and permutation engine.

## Features

- **10 passive sources**: crt.sh, AlienVault OTX, HackerTarget, RapidDNS, URLScan, Wayback Machine, ThreatMiner + VirusTotal, SecurityTrails, Shodan, Censys (API key)
- **Active brute-force**: concurrent DNS resolution with custom resolvers
- **Wildcard detection**: automatically detects and filters wildcard DNS responses
- **HTTP probing**: status code, page title, server header
- **Takeover detection**: 18 services (GitHub Pages, Heroku, S3, Netlify, Vercel, Azure, and more)
- **Permutation engine**: generates mutations from found subdomains
- **Multi-domain**: enumerate a list of domains from a file
- **Output formats**: colored text, JSON, CSV
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

# Full recon: brute-force + probe + takeover + permutations
subhawk -d example.com -w wordlists/common.txt -p -T --permutation

# Save results as JSON
subhawk -d example.com -f json -o results.json

# Multiple domains from file
subhawk -D domains.txt -a -p
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d` | — | Target domain |
| `-D, --domains-file` | — | File with list of domains (one per line) |
| `-w, --wordlist` | — | Wordlist for brute-force |
| `-o, --output` | — | Output file |
| `-f, --format` | `text` | Output format: `text`, `json`, `csv` |
| `-c, --config` | `~/.config/subhawk/config.yaml` | Config file path |
| `-t, --threads` | `50` | Concurrent DNS threads |
| `--timeout` | `5` | DNS timeout in seconds |
| `-r, --resolvers` | — | Custom resolvers, comma-separated (e.g. `8.8.8.8:53`) |
| `-a, --active` | `false` | Show only active (resolved) subdomains |
| `-p, --probe` | `false` | HTTP probe active subdomains |
| `-T, --takeover` | `false` | Check for subdomain takeover vulnerabilities |
| `--permutation` | `false` | Generate and test permutations from found subdomains |
| `--no-color` | `false` | Disable colored output |

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

## Takeover detection

SubHawk checks CNAMEs against 18 known vulnerable services:

GitHub Pages, Heroku, Amazon S3, Netlify, Vercel, Fastly, Shopify, Tumblr, Zendesk, Freshdesk, Surge.sh, readme.io, Ghost, Azure, Bitbucket, HubSpot, Intercom, Webflow.

## Output example

```
[+] api.example.com [1.2.3.4]  [200] [API Portal] [nginx]
[+] dev.example.com [1.2.3.5]  [401] [Unauthorized]
[TAKEOVER] old.example.com [GitHub Pages]
[~] *.example.com [wildcard]
[-] test.example.com
```

## License

MIT — see [LICENSE](LICENSE)
