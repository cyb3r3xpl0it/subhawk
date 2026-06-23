# SubHawk

Fast subdomain enumeration tool written in Go. Combines passive sources with active DNS brute-force.

## Features

- **Passive sources**: crt.sh, AlienVault OTX, HackerTarget, RapidDNS
- **Active brute-force**: concurrent DNS resolution with custom resolvers
- **Output formats**: colored text, JSON, CSV
- **Cross-platform**: Linux, macOS, Windows

## Installation

### From releases

Download the latest binary from [Releases](https://github.com/cyb3r3xpl0it/subhawk/releases).

### From source

```bash
go install github.com/cyb3r3xpl0it/subhawk@latest
```

## Usage

```bash
# Passive enumeration only
subhawk -d example.com

# Active only results
subhawk -d example.com -a

# With wordlist brute-force
subhawk -d example.com -w wordlists/common.txt

# JSON output to file
subhawk -d example.com -f json -o results.json

# Custom resolvers and threads
subhawk -d example.com -r 8.8.8.8:53,1.1.1.1:53 -t 100
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d` | required | Target domain |
| `-w` | — | Wordlist for brute-force |
| `-o` | — | Output file |
| `-f` | `text` | Format: `text`, `json`, `csv` |
| `-t` | `50` | Concurrent DNS threads |
| `--timeout` | `5` | DNS timeout in seconds |
| `-r` | — | Custom resolvers (comma-separated) |
| `-a` | `false` | Show active subdomains only |
| `--no-color` | `false` | Disable colored output |

## License

MIT — see [LICENSE](LICENSE)
