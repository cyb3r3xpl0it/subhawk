package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/axfr"
	"github.com/cyb3r3xpl0it/subhawk/internal/checkpoint"
	"github.com/cyb3r3xpl0it/subhawk/internal/cloud"
	"github.com/cyb3r3xpl0it/subhawk/internal/config"
	"github.com/cyb3r3xpl0it/subhawk/internal/dnsrecords"
	"github.com/cyb3r3xpl0it/subhawk/internal/output"
	"github.com/cyb3r3xpl0it/subhawk/internal/permutation"
	"github.com/cyb3r3xpl0it/subhawk/internal/portscan"
	"github.com/cyb3r3xpl0it/subhawk/internal/probe"
	"github.com/cyb3r3xpl0it/subhawk/internal/ratelimit"
	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
	"github.com/cyb3r3xpl0it/subhawk/internal/sources"
	"github.com/cyb3r3xpl0it/subhawk/internal/takeover"
	"github.com/cyb3r3xpl0it/subhawk/internal/wildcard"
	"github.com/spf13/cobra"
)

var (
	domain        string
	domainsFile   string
	wordlist      string
	outputFile    string
	outputFmt     string
	configFile    string
	diffFile      string
	excludeList   string
	excludeFile   string
	threads       int
	timeout       int
	rateLimit     int
	recursiveDepth int
	resolvers     []string
	activeOnly    bool
	noColor       bool
	doProbe       bool
	doTakeover    bool
	doPerm        bool
	doPortScan    bool
	doDNSRecords  bool
	doResume      bool
	doAxfr        bool
)

var rootCmd = &cobra.Command{
	Use:   "subhawk",
	Short: "SubHawk - Subdomain Enumeration Tool",
	Long:  `SubHawk enumerates subdomains via passive sources, DNS brute-force, and active analysis.`,
	RunE:  run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Targets
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain")
	rootCmd.Flags().StringVarP(&domainsFile, "domains-file", "D", "", "File with list of domains")

	// Sources
	rootCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Wordlist for brute-force")
	rootCmd.Flags().BoolVar(&doAxfr, "axfr", false, "Attempt DNS zone transfer")

	// Output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	rootCmd.Flags().StringVarP(&outputFmt, "format", "f", "text", "Output format: text, json, csv, nuclei, burp")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	rootCmd.Flags().BoolVarP(&activeOnly, "active", "a", false, "Show only active subdomains")

	// Analysis
	rootCmd.Flags().BoolVarP(&doProbe, "probe", "p", false, "HTTP probe + tech fingerprinting")
	rootCmd.Flags().BoolVarP(&doTakeover, "takeover", "T", false, "Subdomain takeover detection")
	rootCmd.Flags().BoolVar(&doPerm, "permutation", false, "Generate permutations from found subdomains")
	rootCmd.Flags().BoolVar(&doPortScan, "portscan", false, "Scan common ports on active subdomains")
	rootCmd.Flags().BoolVar(&doDNSRecords, "dns-records", false, "Fetch full DNS records (A, AAAA, MX, TXT, NS)")
	rootCmd.Flags().IntVar(&recursiveDepth, "recursive", 0, "Recursive enumeration depth (0=disabled)")

	// Filtering
	rootCmd.Flags().StringVar(&excludeList, "exclude", "", "Comma-separated subdomains/patterns to exclude")
	rootCmd.Flags().StringVar(&excludeFile, "exclude-file", "", "File with exclusion patterns (one per line)")
	rootCmd.Flags().StringVar(&diffFile, "diff", "", "Show only NEW subdomains compared to this results file")

	// Performance
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Concurrent DNS resolvers")
	rootCmd.Flags().IntVar(&timeout, "timeout", 5, "DNS timeout in seconds")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "Max DNS requests per second (0=unlimited)")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", nil, "Custom DNS resolvers (e.g. 8.8.8.8:53)")

	// State
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Config file (default ~/.config/subhawk/config.yaml)")
	rootCmd.Flags().BoolVar(&doResume, "resume", false, "Resume previous scan from checkpoint")

	// Subcommands
	rootCmd.AddCommand(&cobra.Command{
		Use:   "init-config",
		Short: "Create default config at ~/.config/subhawk/config.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := config.WriteDefault(""); err != nil {
				return err
			}
			home, _ := os.UserHomeDir()
			fmt.Printf("[*] Config created at %s/.config/subhawk/config.yaml\n", home)
			return nil
		},
	})
}

func run(cmd *cobra.Command, args []string) error {
	if domain == "" && domainsFile == "" {
		return fmt.Errorf("--domain or --domains-file is required")
	}

	output.Banner()

	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Build domain list
	domains := []string{}
	if domain != "" {
		domains = append(domains, domain)
	}
	if domainsFile != "" {
		extra, err := readLines(domainsFile)
		if err != nil {
			return fmt.Errorf("reading domains file: %w", err)
		}
		domains = append(domains, extra...)
	}

	// Load diff set
	diffSet := map[string]bool{}
	if diffFile != "" {
		if err := loadDiffSet(diffFile, diffSet); err != nil {
			fmt.Fprintf(os.Stderr, "[!] diff file error: %v\n", err)
		} else {
			fmt.Printf("[*] Diff mode: ignoring %d known subdomains\n", len(diffSet))
		}
	}

	// Load exclude patterns
	excludePatterns := buildExcludePatterns()

	writer, err := output.New(output.Format(outputFmt), outputFile, noColor)
	if err != nil {
		return fmt.Errorf("output error: %w", err)
	}
	defer writer.Close()

	writer.WriteHeader()

	srcOpts := sources.Options{
		WordlistPath:      wordlist,
		VirusTotalKey:     cfg.APIKeys.VirusTotal,
		SecurityTrailsKey: cfg.APIKeys.SecurityTrails,
		ShodanKey:         cfg.APIKeys.Shodan,
		CensysID:          cfg.APIKeys.CensysID,
		CensysSecret:      cfg.APIKeys.CensysSecret,
	}

	for _, d := range domains {
		if err := enumerate(d, srcOpts, writer, diffSet, excludePatterns, 0); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error enumerating %s: %v\n", d, err)
		}
	}

	return nil
}

func enumerate(domain string, srcOpts sources.Options, writer *output.Writer, diffSet, excludePatterns map[string]bool, depth int) error {
	tout := time.Duration(timeout) * time.Second
	ns := "8.8.8.8:53"
	if len(resolvers) > 0 {
		ns = resolvers[0]
	}

	fmt.Printf("[*] Target  : %s", domain)
	if depth > 0 {
		fmt.Printf(" (recursive depth %d)", depth)
	}
	fmt.Printf("\n[*] Threads : %d\n", threads)

	// Zone transfer
	if doAxfr {
		fmt.Printf("[~] Attempting zone transfer...\n")
		if subs, err := axfr.ZoneTransfer(domain); err == nil {
			fmt.Printf("[!] Zone transfer SUCCESS: %d records\n", len(subs))
		} else {
			fmt.Printf("[*] Zone transfer: %v\n", err)
		}
	}

	// Wildcard detection
	res := resolver.New(resolvers, tout)
	if isWild, wIPs := wildcard.Detect(domain, ns, tout); isWild {
		fmt.Printf("[!] Wildcard DNS detected → filtering %v\n", wIPs)
		res.SetWildcardIPs(wIPs)
	} else {
		fmt.Printf("[*] No wildcard detected\n")
	}

	// Rate limiter
	rl := ratelimit.New(rateLimit)
	defer rl.Stop()

	// Checkpoint resume
	var ckpt *checkpoint.State
	if doResume {
		ckpt, _ = checkpoint.Load(domain)
		if ckpt != nil {
			fmt.Printf("[*] Resuming from checkpoint: %d subdomains found previously\n", len(ckpt.Found))
		}
	}
	if ckpt == nil {
		ckpt = checkpoint.New(domain)
	}

	completedSources := map[string]bool{}
	for _, s := range ckpt.CompletedSources {
		completedSources[s] = true
	}

	allSubs := map[string]bool{}
	for _, s := range ckpt.Found {
		allSubs[s] = true
	}

	// Source enumeration
	var mu sync.Mutex
	subCh := make(chan string, 5000)
	srcList := sources.All(srcOpts)
	var srcWg sync.WaitGroup

	for _, src := range srcList {
		if completedSources[src.Name()] {
			fmt.Printf("[~] Source: %s (skipped - already completed)\n", src.Name())
			continue
		}
		srcWg.Add(1)
		go func(s sources.Source) {
			defer srcWg.Done()
			fmt.Printf("[~] Source: %s\n", s.Name())
			subs, err := s.Enumerate(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", s.Name(), err)
			} else {
				mu.Lock()
				for _, sub := range subs {
					if !allSubs[sub] {
						allSubs[sub] = true
						subCh <- sub
					}
				}
				ckpt.CompletedSources = append(ckpt.CompletedSources, s.Name())
				checkpoint.Save(ckpt)
				mu.Unlock()
			}
		}(src)
	}

	go func() {
		srcWg.Wait()
		close(subCh)
	}()

	// DNS resolution
	sem := make(chan struct{}, threads)
	var resolveWg sync.WaitGroup
	found := 0
	total := 0
	var activeSubs []resolver.Result

	for sub := range subCh {
		if isExcluded(sub, excludePatterns) || diffSet[sub] {
			continue
		}
		total++
		resolveWg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer resolveWg.Done()
			defer func() { <-sem }()

			rl.Wait()
			result := res.Resolve(s)
			if result.IsWildcard {
				return
			}
			if activeOnly && !result.Active {
				return
			}
			if result.Active {
				result.Cloud = cloud.Detect(result.CNAME, result.IPs)
				mu.Lock()
				found++
				activeSubs = append(activeSubs, result)
				ckpt.Found = append(ckpt.Found, s)
				mu.Unlock()
				checkpoint.Save(ckpt)
			}
			writer.Write(result)
		}(sub)
	}
	resolveWg.Wait()

	// Full DNS records
	if doDNSRecords && len(activeSubs) > 0 {
		fmt.Printf("\n[*] Fetching full DNS records for %d subdomains...\n", len(activeSubs))
		var dnsWg sync.WaitGroup
		dnsSem := make(chan struct{}, threads)
		for i := range activeSubs {
			dnsWg.Add(1)
			dnsSem <- struct{}{}
			go func(idx int) {
				defer dnsWg.Done()
				defer func() { <-dnsSem }()
				rec := dnsrecords.Lookup(activeSubs[idx].Subdomain, ns, tout)
				activeSubs[idx].DNS = &resolver.DNSRecords{
					A: rec.A, AAAA: rec.AAAA,
					MX: rec.MX, TXT: rec.TXT, NS: rec.NS,
					CNAME: rec.CNAME,
				}
				writer.Write(activeSubs[idx])
			}(i)
		}
		dnsWg.Wait()
	}

	// Port scanning
	if doPortScan && len(activeSubs) > 0 {
		fmt.Printf("\n[*] Port scanning %d active subdomains...\n", len(activeSubs))
		var psWg sync.WaitGroup
		psSem := make(chan struct{}, 10)
		for i := range activeSubs {
			psWg.Add(1)
			psSem <- struct{}{}
			go func(idx int) {
				defer psWg.Done()
				defer func() { <-psSem }()
				activeSubs[idx].OpenPorts = portscan.Scan(
					activeSubs[idx].Subdomain,
					portscan.DefaultPorts,
					3*time.Second,
				)
				if len(activeSubs[idx].OpenPorts) > 0 {
					writer.Write(activeSubs[idx])
				}
			}(i)
		}
		psWg.Wait()
	}

	// Permutations
	if doPerm && len(activeSubs) > 0 {
		fmt.Printf("\n[*] Generating permutations from %d found subdomains...\n", len(activeSubs))
		foundNames := make([]string, len(activeSubs))
		for i, r := range activeSubs {
			foundNames[i] = r.Subdomain
		}
		perms := permutation.Generate(foundNames, domain)
		fmt.Printf("[*] Testing %d permutations...\n", len(perms))

		var permWg sync.WaitGroup
		permSem := make(chan struct{}, threads)
		for _, p := range perms {
			mu.Lock()
			known := allSubs[p]
			if !known {
				allSubs[p] = true
			}
			mu.Unlock()
			if known || isExcluded(p, excludePatterns) || diffSet[p] {
				continue
			}
			permWg.Add(1)
			permSem <- struct{}{}
			go func(sub string) {
				defer permWg.Done()
				defer func() { <-permSem }()
				rl.Wait()
				result := res.Resolve(sub)
				if result.IsWildcard || !result.Active {
					return
				}
				result.Cloud = cloud.Detect(result.CNAME, result.IPs)
				mu.Lock()
				found++
				activeSubs = append(activeSubs, result)
				mu.Unlock()
				writer.Write(result)
			}(p)
		}
		permWg.Wait()
	}

	// HTTP probing + tech fingerprinting
	if doProbe && len(activeSubs) > 0 {
		fmt.Printf("\n[*] HTTP probing %d active subdomains...\n", len(activeSubs))
		var probeWg sync.WaitGroup
		probeSem := make(chan struct{}, 20)
		for i := range activeSubs {
			probeWg.Add(1)
			probeSem <- struct{}{}
			go func(idx int) {
				defer probeWg.Done()
				defer func() { <-probeSem }()
				activeSubs[idx].HTTP = probe.Probe(activeSubs[idx].Subdomain)
				if activeSubs[idx].HTTP != nil {
					writer.Write(activeSubs[idx])
				}
			}(i)
		}
		probeWg.Wait()
	}

	// Takeover detection
	if doTakeover && len(activeSubs) > 0 {
		fmt.Printf("\n[*] Checking takeover for %d subdomains...\n", len(activeSubs))
		var tkWg sync.WaitGroup
		tkSem := make(chan struct{}, 20)
		for i := range activeSubs {
			if activeSubs[i].CNAME == "" {
				continue
			}
			tkWg.Add(1)
			tkSem <- struct{}{}
			go func(idx int) {
				defer tkWg.Done()
				defer func() { <-tkSem }()
				info := takeover.Check(activeSubs[idx])
				if info != nil {
					activeSubs[idx].Takeover = info
					writer.Write(activeSubs[idx])
				}
			}(i)
		}
		tkWg.Wait()
	}

	// Recursive enumeration
	if recursiveDepth > depth && len(activeSubs) > 0 {
		fmt.Printf("\n[*] Recursive enumeration (depth %d → %d)...\n", depth, depth+1)
		for _, r := range activeSubs {
			sub := r.Subdomain
			if sub == domain {
				continue
			}
			enumerate(sub, srcOpts, writer, diffSet, excludePatterns, depth+1)
		}
	}

	fmt.Printf("\n[*] Total enumerated : %d\n", total)
	fmt.Printf("[*] Active subdomains: %d\n", found)
	if outputFile != "" {
		fmt.Printf("[*] Saved to         : %s\n", outputFile)
	}

	// Clear checkpoint on successful completion
	if doResume {
		checkpoint.Clear(domain)
	}

	return nil
}

func buildExcludePatterns() map[string]bool {
	patterns := map[string]bool{}
	if excludeList != "" {
		for _, p := range strings.Split(excludeList, ",") {
			patterns[strings.TrimSpace(p)] = true
		}
	}
	if excludeFile != "" {
		lines, _ := readLines(excludeFile)
		for _, l := range lines {
			patterns[l] = true
		}
	}
	return patterns
}

func isExcluded(sub string, patterns map[string]bool) bool {
	if patterns[sub] {
		return true
	}
	for pattern := range patterns {
		if matched, _ := path.Match(pattern, sub); matched {
			return true
		}
	}
	return false
}

func loadDiffSet(file string, set map[string]bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	// Try JSON (array of results or subdomains)
	var results []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(data, &results); err == nil {
		for _, r := range results {
			if r.Subdomain != "" {
				set[r.Subdomain] = true
			}
		}
		return nil
	}
	// Fallback: plain text, one subdomain per line
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			set[line] = true
		}
	}
	return scanner.Err()
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
