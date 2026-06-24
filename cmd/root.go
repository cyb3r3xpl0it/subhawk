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

	"github.com/cyb3r3xpl0it/subhawk/internal/admindetect"
	"github.com/cyb3r3xpl0it/subhawk/internal/asn"
	"github.com/cyb3r3xpl0it/subhawk/internal/axfr"
	"github.com/cyb3r3xpl0it/subhawk/internal/checkpoint"
	"github.com/cyb3r3xpl0it/subhawk/internal/cloud"
	"github.com/cyb3r3xpl0it/subhawk/internal/config"
	"github.com/cyb3r3xpl0it/subhawk/internal/cors"
	"github.com/cyb3r3xpl0it/subhawk/internal/dnsrecords"
	"github.com/cyb3r3xpl0it/subhawk/internal/emailscore"
	"github.com/cyb3r3xpl0it/subhawk/internal/favicon"
	"github.com/cyb3r3xpl0it/subhawk/internal/headers"
	"github.com/cyb3r3xpl0it/subhawk/internal/jsscrape"
	"github.com/cyb3r3xpl0it/subhawk/internal/output"
	"github.com/cyb3r3xpl0it/subhawk/internal/permutation"
	"github.com/cyb3r3xpl0it/subhawk/internal/portscan"
	"github.com/cyb3r3xpl0it/subhawk/internal/probe"
	"github.com/cyb3r3xpl0it/subhawk/internal/ratelimit"
	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
	"github.com/cyb3r3xpl0it/subhawk/internal/sources"
	"github.com/cyb3r3xpl0it/subhawk/internal/ssl"
	"github.com/cyb3r3xpl0it/subhawk/internal/store"
	"github.com/cyb3r3xpl0it/subhawk/internal/summary"
	"github.com/cyb3r3xpl0it/subhawk/internal/takeover"
	"github.com/cyb3r3xpl0it/subhawk/internal/tui"
	"github.com/cyb3r3xpl0it/subhawk/internal/waf"
	"github.com/cyb3r3xpl0it/subhawk/internal/wildcard"
	"github.com/spf13/cobra"
)

var (
	domain         string
	domainsFile    string
	wordlist       string
	outputFile     string
	outputFmt      string
	configFile     string
	diffFile       string
	excludeList    string
	excludeFile    string
	dbPath         string
	threads        int
	timeout        int
	rateLimit      int
	recursiveDepth int
	resolvers      []string
	dnsRecordTypes []string
	activeOnly     bool
	noColor        bool
	doProbe        bool
	doTakeover     bool
	doPerm         bool
	doPortScan     bool
	doResume       bool
	doAxfr         bool
	doHeaders      bool
	doCORS         bool
	doSSL          bool
	doWAF          bool
	doFavicon      bool
	doASN          bool
	doJS           bool
	doAdmin        bool
	doEmailScore   bool
	doSummary      bool
	doTUI          bool
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
	rootCmd.Flags().StringVar(&dbPath, "db", "", "Save results to SQLite database (e.g. results.db)")

	// Analysis
	rootCmd.Flags().BoolVarP(&doProbe, "probe", "p", false, "HTTP probe + tech fingerprinting")
	rootCmd.Flags().BoolVarP(&doTakeover, "takeover", "T", false, "Subdomain takeover detection")
	rootCmd.Flags().BoolVar(&doPerm, "permutation", false, "Generate permutations from found subdomains")
	rootCmd.Flags().BoolVar(&doPortScan, "portscan", false, "Scan common ports on active subdomains")
	rootCmd.Flags().StringSliceVar(&dnsRecordTypes, "dns-records", nil, "Fetch DNS records: A,AAAA,CNAME,MX,TXT,NS (empty = all)")
	rootCmd.Flags().IntVar(&recursiveDepth, "recursive", 0, "Recursive enumeration depth (0=disabled)")

	// Security analysis (v1.3.0)
	rootCmd.Flags().BoolVar(&doHeaders, "headers", false, "Audit HTTP security headers")
	rootCmd.Flags().BoolVar(&doCORS, "cors", false, "Check for CORS misconfigurations")
	rootCmd.Flags().BoolVar(&doSSL, "ssl", false, "Audit SSL/TLS certificates")
	rootCmd.Flags().BoolVar(&doWAF, "waf", false, "Detect WAF/CDN")
	rootCmd.Flags().BoolVar(&doFavicon, "favicon", false, "Calculate favicon hash (Shodan-compatible)")
	rootCmd.Flags().BoolVar(&doASN, "asn", false, "Lookup ASN/GeoIP information")
	rootCmd.Flags().BoolVar(&doJS, "js-scrape", false, "Scrape JS files for endpoints and secrets")
	rootCmd.Flags().BoolVar(&doAdmin, "admin-detect", false, "Detect admin/login panels")
	rootCmd.Flags().BoolVar(&doEmailScore, "email-score", false, "Calculate email security score (SPF/DMARC/DKIM)")
	rootCmd.Flags().BoolVar(&doSummary, "summary", false, "Print summary report at end of scan")
	rootCmd.Flags().BoolVar(&doTUI, "tui", false, "Interactive TUI mode")

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

	// TUI mode: run in alt-screen with a bubbletea program
	var tuiProg *tui.Program
	if doTUI {
		tuiProg = tui.New()
		go func() {
			if err := tuiProg.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] TUI error: %v\n", err)
			}
		}()
	} else {
		output.Banner()
	}

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

	// SQLite database
	var db *store.DB
	if dbPath != "" {
		db, err = store.Open(dbPath)
		if err != nil {
			return fmt.Errorf("database error: %w", err)
		}
		defer db.Close()
		fmt.Printf("[*] Database  : %s\n", dbPath)
	}

	// Summary stats
	var stats *summary.Stats
	if doSummary {
		stats = summary.New()
	}

	srcOpts := sources.Options{
		WordlistPath:      wordlist,
		VirusTotalKey:     cfg.APIKeys.VirusTotal,
		SecurityTrailsKey: cfg.APIKeys.SecurityTrails,
		ShodanKey:         cfg.APIKeys.Shodan,
		CensysID:          cfg.APIKeys.CensysID,
		CensysSecret:      cfg.APIKeys.CensysSecret,
	}

	for _, d := range domains {
		if err := enumerate(d, srcOpts, writer, db, stats, tuiProg, diffSet, excludePatterns, 0); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error enumerating %s: %v\n", d, err)
		}
	}

	// Email security score (per-domain)
	if doEmailScore {
		for _, d := range domains {
			sc := emailscore.Calculate(d)
			fmt.Printf("\n[*] Email Security Score for %s: %d/100 (Grade %s)\n", d, sc.Total, sc.Grade)
			if sc.SPFRecord != "" {
				fmt.Printf("    SPF  (%2d): %s\n", sc.SPF, sc.SPFRecord)
			} else {
				fmt.Printf("    SPF  (%2d): not found\n", sc.SPF)
			}
			if sc.DMARCRecord != "" {
				fmt.Printf("    DMARC(%2d): %s\n", sc.DMARC, sc.DMARCRecord)
			} else {
				fmt.Printf("    DMARC(%2d): not found\n", sc.DMARC)
			}
			if sc.DKIMFound {
				fmt.Printf("    DKIM (%2d): found\n", sc.DKIM)
			} else {
				fmt.Printf("    DKIM (%2d): not found\n", sc.DKIM)
			}
		}
	}

	// Summary report
	if doSummary && stats != nil {
		stats.Print()
	}

	// Signal TUI done
	if tuiProg != nil {
		tuiProg.Done()
		time.Sleep(200 * time.Millisecond)
	}

	return nil
}

func enumerate(domain string, srcOpts sources.Options, writer *output.Writer, db *store.DB, stats *summary.Stats, tuiProg *tui.Program, diffSet, excludePatterns map[string]bool, depth int) error {
	tout := time.Duration(timeout) * time.Second
	ns := "8.8.8.8:53"
	if len(resolvers) > 0 {
		ns = resolvers[0]
	}

	logf := func(format string, a ...interface{}) {
		if tuiProg != nil {
			tuiProg.AddInfo(fmt.Sprintf(format, a...))
		} else {
			fmt.Printf(format+"\n", a...)
		}
	}

	logf("[*] Target  : %s", domain)
	if depth > 0 {
		logf("[*] Recursive depth: %d", depth)
	}
	logf("[*] Threads : %d", threads)

	// Zone transfer
	if doAxfr {
		logf("[~] Attempting zone transfer...")
		if subs, err := axfr.ZoneTransfer(domain); err == nil {
			logf("[!] Zone transfer SUCCESS: %d records", len(subs))
		} else {
			logf("[*] Zone transfer: %v", err)
		}
	}

	// Wildcard detection
	res := resolver.New(resolvers, tout)
	if isWild, wIPs := wildcard.Detect(domain, ns, tout); isWild {
		logf("[!] Wildcard DNS detected → filtering %v", wIPs)
		res.SetWildcardIPs(wIPs)
	} else {
		logf("[*] No wildcard detected")
	}

	// Rate limiter
	rl := ratelimit.New(rateLimit)
	defer rl.Stop()

	// Checkpoint resume
	var ckpt *checkpoint.State
	if doResume {
		ckpt, _ = checkpoint.Load(domain)
		if ckpt != nil {
			logf("[*] Resuming from checkpoint: %d subdomains found previously", len(ckpt.Found))
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

	if tuiProg != nil {
		tuiProg.SetPhase("Enumerating sources")
	}

	// Source enumeration
	var mu sync.Mutex
	subCh := make(chan string, 5000)
	srcList := sources.All(srcOpts)
	var srcWg sync.WaitGroup

	for _, src := range srcList {
		if completedSources[src.Name()] {
			logf("[~] Source: %s (skipped)", src.Name())
			continue
		}
		srcWg.Add(1)
		go func(s sources.Source) {
			defer srcWg.Done()
			logf("[~] Source: %s", s.Name())
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

	if tuiProg != nil {
		tuiProg.SetPhase("Resolving DNS")
	}

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
				if tuiProg != nil {
					tuiProg.AddFound(s)
				}
			} else if tuiProg == nil {
				writer.Write(result)
			}
			if tuiProg == nil {
				if result.Active {
					writer.Write(result)
				}
			}
		}(sub)
	}
	resolveWg.Wait()

	// Full DNS records
	if len(dnsRecordTypes) >= 0 && dnsRecordTypes != nil {
		types := dnsrecords.ParseTypes(dnsRecordTypes)
		label := "all"
		if len(dnsRecordTypes) > 0 {
			label = strings.Join(dnsRecordTypes, ",")
		}
		logf("[*] Fetching DNS records [%s] for %d subdomains...", label, len(activeSubs))
		var dnsWg sync.WaitGroup
		dnsSem := make(chan struct{}, threads)
		for i := range activeSubs {
			dnsWg.Add(1)
			dnsSem <- struct{}{}
			go func(idx int) {
				defer dnsWg.Done()
				defer func() { <-dnsSem }()
				rec := dnsrecords.Lookup(activeSubs[idx].Subdomain, ns, tout, types)
				activeSubs[idx].DNS = &resolver.DNSRecords{
					A: rec.A, AAAA: rec.AAAA,
					MX: rec.MX, TXT: rec.TXT, NS: rec.NS,
					CNAME: rec.CNAME, SOA: rec.SOA,
					SRV: rec.SRV, CAA: rec.CAA, PTR: rec.PTR,
					DMARC: rec.DMARC, SPF: rec.SPF,
					DNSKEY: rec.DNSKEY, DS: rec.DS,
					TLSA: rec.TLSA, NAPTR: rec.NAPTR,
					HTTPS: rec.HTTPS,
				}
			}(i)
		}
		dnsWg.Wait()
	}

	// Port scanning
	if doPortScan && len(activeSubs) > 0 {
		logf("[*] Port scanning %d active subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Port scanning")
		}
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
			}(i)
		}
		psWg.Wait()
	}

	// Permutations
	if doPerm && len(activeSubs) > 0 {
		logf("[*] Generating permutations from %d found subdomains...", len(activeSubs))
		foundNames := make([]string, len(activeSubs))
		for i, r := range activeSubs {
			foundNames[i] = r.Subdomain
		}
		perms := permutation.Generate(foundNames, domain)
		logf("[*] Testing %d permutations...", len(perms))
		if tuiProg != nil {
			tuiProg.SetPhase("Permutations")
		}

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
				if tuiProg != nil {
					tuiProg.AddFound(sub)
				} else {
					writer.Write(result)
				}
			}(p)
		}
		permWg.Wait()
	}

	// HTTP probing + tech fingerprinting
	if doProbe && len(activeSubs) > 0 {
		logf("[*] HTTP probing %d active subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("HTTP probing")
		}
		var probeWg sync.WaitGroup
		probeSem := make(chan struct{}, 20)
		for i := range activeSubs {
			probeWg.Add(1)
			probeSem <- struct{}{}
			go func(idx int) {
				defer probeWg.Done()
				defer func() { <-probeSem }()
				activeSubs[idx].HTTP = probe.Probe(activeSubs[idx].Subdomain)
			}(i)
		}
		probeWg.Wait()
	}

	// WAF detection
	if doWAF && len(activeSubs) > 0 {
		logf("[*] WAF detection for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("WAF detection")
		}
		var wafWg sync.WaitGroup
		wafSem := make(chan struct{}, 20)
		for i := range activeSubs {
			wafWg.Add(1)
			wafSem <- struct{}{}
			go func(idx int) {
				defer wafWg.Done()
				defer func() { <-wafSem }()
				activeSubs[idx].WAF = waf.Detect(activeSubs[idx].Subdomain)
			}(i)
		}
		wafWg.Wait()
	}

	// Security headers audit
	if doHeaders && len(activeSubs) > 0 {
		logf("[*] Security headers audit for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Security headers")
		}
		var hWg sync.WaitGroup
		hSem := make(chan struct{}, 20)
		for i := range activeSubs {
			hWg.Add(1)
			hSem <- struct{}{}
			go func(idx int) {
				defer hWg.Done()
				defer func() { <-hSem }()
				info := headers.Audit(activeSubs[idx].Subdomain)
				activeSubs[idx].SecurityHeaders = (*resolver.SecurityHeadersInfo)(info)
			}(i)
		}
		hWg.Wait()
	}

	// CORS check
	if doCORS && len(activeSubs) > 0 {
		logf("[*] CORS check for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("CORS check")
		}
		var corsWg sync.WaitGroup
		corsSem := make(chan struct{}, 20)
		for i := range activeSubs {
			corsWg.Add(1)
			corsSem <- struct{}{}
			go func(idx int) {
				defer corsWg.Done()
				defer func() { <-corsSem }()
				info := cors.Check(activeSubs[idx].Subdomain)
				activeSubs[idx].CORS = (*resolver.CORSInfo)(info)
				if info != nil && info.Vulnerable && tuiProg != nil {
					tuiProg.AddCORS()
				}
			}(i)
		}
		corsWg.Wait()
	}

	// SSL/TLS audit
	if doSSL && len(activeSubs) > 0 {
		logf("[*] SSL/TLS audit for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("SSL/TLS audit")
		}
		var sslWg sync.WaitGroup
		sslSem := make(chan struct{}, 20)
		for i := range activeSubs {
			sslWg.Add(1)
			sslSem <- struct{}{}
			go func(idx int) {
				defer sslWg.Done()
				defer func() { <-sslSem }()
				info := ssl.Audit(activeSubs[idx].Subdomain)
				activeSubs[idx].TLS = (*resolver.TLSInfo)(info)
			}(i)
		}
		sslWg.Wait()
	}

	// Favicon hash
	if doFavicon && len(activeSubs) > 0 {
		logf("[*] Favicon hashing for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Favicon hash")
		}
		var favWg sync.WaitGroup
		favSem := make(chan struct{}, 20)
		for i := range activeSubs {
			favWg.Add(1)
			favSem <- struct{}{}
			go func(idx int) {
				defer favWg.Done()
				defer func() { <-favSem }()
				activeSubs[idx].FaviconHash = favicon.Hash(activeSubs[idx].Subdomain)
			}(i)
		}
		favWg.Wait()
	}

	// ASN/GeoIP
	if doASN && len(activeSubs) > 0 {
		logf("[*] ASN/GeoIP lookup for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("ASN lookup")
		}
		var asnWg sync.WaitGroup
		asnSem := make(chan struct{}, 10)
		for i := range activeSubs {
			if len(activeSubs[i].IPs) == 0 {
				continue
			}
			asnWg.Add(1)
			asnSem <- struct{}{}
			go func(idx int) {
				defer asnWg.Done()
				defer func() { <-asnSem }()
				info := asn.Lookup(activeSubs[idx].IPs[0])
				activeSubs[idx].ASN = (*resolver.ASNInfo)(info)
			}(i)
		}
		asnWg.Wait()
	}

	// JS scraping
	if doJS && len(activeSubs) > 0 {
		logf("[*] JS scraping for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("JS scraping")
		}
		var jsWg sync.WaitGroup
		jsSem := make(chan struct{}, 10)
		for i := range activeSubs {
			jsWg.Add(1)
			jsSem <- struct{}{}
			go func(idx int) {
				defer jsWg.Done()
				defer func() { <-jsSem }()
				result := jsscrape.Scrape(activeSubs[idx].Subdomain)
				activeSubs[idx].JS = (*resolver.JSInfo)(result)
			}(i)
		}
		jsWg.Wait()
	}

	// Admin panel detection
	if doAdmin && len(activeSubs) > 0 {
		logf("[*] Admin panel detection for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Admin detection")
		}
		var adminWg sync.WaitGroup
		adminSem := make(chan struct{}, 10)
		for i := range activeSubs {
			adminWg.Add(1)
			adminSem <- struct{}{}
			go func(idx int) {
				defer adminWg.Done()
				defer func() { <-adminSem }()
				panels := admindetect.Detect(activeSubs[idx].Subdomain)
				for _, p := range panels {
					activeSubs[idx].AdminPanels = append(activeSubs[idx].AdminPanels,
						resolver.AdminPanel{URL: p.URL, StatusCode: p.StatusCode, Title: p.Title})
				}
			}(i)
		}
		adminWg.Wait()
	}

	// Takeover detection
	if doTakeover && len(activeSubs) > 0 {
		logf("[*] Checking takeover for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Takeover check")
		}
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
					if tuiProg != nil {
						tuiProg.AddTakeover(activeSubs[idx].Subdomain + " [" + info.Service + "]")
					}
				}
			}(i)
		}
		tkWg.Wait()
	}

	// Write all final results, update stats, save to DB
	if tuiProg != nil {
		tuiProg.SetPhase("Writing results")
	}
	for _, r := range activeSubs {
		writer.Write(r)
		if stats != nil {
			stats.Add(r)
		}
		if db != nil {
			_ = db.Save(domain, r)
		}
	}

	// Recursive enumeration
	if recursiveDepth > depth && len(activeSubs) > 0 {
		logf("[*] Recursive enumeration (depth %d → %d)...", depth, depth+1)
		for _, r := range activeSubs {
			sub := r.Subdomain
			if sub == domain {
				continue
			}
			enumerate(sub, srcOpts, writer, db, stats, tuiProg, diffSet, excludePatterns, depth+1)
		}
	}

	if tuiProg == nil {
		fmt.Printf("\n[*] Total enumerated : %d\n", total)
		fmt.Printf("[*] Active subdomains: %d\n", found)
		if outputFile != "" {
			fmt.Printf("[*] Saved to         : %s\n", outputFile)
		}
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
