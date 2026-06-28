package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/admindetect"
	"github.com/cyb3r3xpl0it/subhawk/internal/apidiscover"
	"github.com/cyb3r3xpl0it/subhawk/internal/asn"
	"github.com/cyb3r3xpl0it/subhawk/internal/axfr"
	"github.com/cyb3r3xpl0it/subhawk/internal/banner"
	"github.com/cyb3r3xpl0it/subhawk/internal/buckets"
	"github.com/cyb3r3xpl0it/subhawk/internal/cdnbypass"
	"github.com/cyb3r3xpl0it/subhawk/internal/certcorrelate"
	"github.com/cyb3r3xpl0it/subhawk/internal/checkpoint"
	"github.com/cyb3r3xpl0it/subhawk/internal/cloud"
	"github.com/cyb3r3xpl0it/subhawk/internal/config"
	"github.com/cyb3r3xpl0it/subhawk/internal/cors"
	"github.com/cyb3r3xpl0it/subhawk/internal/defaultcreds"
	"github.com/cyb3r3xpl0it/subhawk/internal/dnsrecords"
	"github.com/cyb3r3xpl0it/subhawk/internal/dork"
	"github.com/cyb3r3xpl0it/subhawk/internal/emailscore"
	"github.com/cyb3r3xpl0it/subhawk/internal/exposed"
	"github.com/cyb3r3xpl0it/subhawk/internal/fastresolver"
	"github.com/cyb3r3xpl0it/subhawk/internal/favicon"
	"github.com/cyb3r3xpl0it/subhawk/internal/headers"
	"github.com/cyb3r3xpl0it/subhawk/internal/jsscrape"
	"github.com/cyb3r3xpl0it/subhawk/internal/monitor"
	"github.com/cyb3r3xpl0it/subhawk/internal/neighbors"
	"github.com/cyb3r3xpl0it/subhawk/internal/openredirect"
	"github.com/cyb3r3xpl0it/subhawk/internal/output"
	"github.com/cyb3r3xpl0it/subhawk/internal/permutation"
	"github.com/cyb3r3xpl0it/subhawk/internal/portscan"
	"github.com/cyb3r3xpl0it/subhawk/internal/probe"
	"github.com/cyb3r3xpl0it/subhawk/internal/profile"
	"github.com/cyb3r3xpl0it/subhawk/internal/ratelimit"
	"github.com/cyb3r3xpl0it/subhawk/internal/report"
	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
	"github.com/cyb3r3xpl0it/subhawk/internal/screenshot"
	"github.com/cyb3r3xpl0it/subhawk/internal/sources"
	"github.com/cyb3r3xpl0it/subhawk/internal/ssl"
	"github.com/cyb3r3xpl0it/subhawk/internal/store"
	"github.com/cyb3r3xpl0it/subhawk/internal/summary"
	"github.com/cyb3r3xpl0it/subhawk/internal/takeover"
	"github.com/cyb3r3xpl0it/subhawk/internal/tui"
	"github.com/cyb3r3xpl0it/subhawk/internal/vhostfuzz"
	"github.com/cyb3r3xpl0it/subhawk/internal/waf"
	"github.com/cyb3r3xpl0it/subhawk/internal/whois"
	"github.com/cyb3r3xpl0it/subhawk/internal/wildcard"
	"github.com/cyb3r3xpl0it/subhawk/internal/zonewalk"
	"github.com/spf13/cobra"
)

var (
	// Targets
	domain      string
	domainsFile string

	// Sources
	wordlist     string
	resolverFile string

	// Output
	outputFile    string
	outputFmt     string
	configFile    string
	diffFile      string
	excludeList   string
	excludeFile   string
	dbPath        string
	reportPath    string
	screenshotDir string

	// Performance
	threads        int
	timeout        int
	rateLimit      int
	recursiveDepth int
	resolvers      []string
	dnsRecordTypes []string

	// Feature flags
	activeOnly        bool
	noColor           bool
	doProbe           bool
	doTakeover        bool
	doPerm            bool
	doPortScan        bool
	doResume          bool
	doAxfr            bool
	doHeaders         bool
	doCORS            bool
	doSSL             bool
	doWAF             bool
	doFavicon         bool
	doASN             bool
	doJS              bool
	doAdmin           bool
	doEmailScore      bool
	doSummary         bool
	doTUI             bool
	doFastResolve       bool
	doValidateResolvers bool
	doVHost             bool
	doExposed           bool
	doBuckets           bool
	doOpenRedirect      bool
	doDefaultCreds      bool
	doScreenshot        bool
	doCDNBypass         bool
	doBanner            bool
	doAPIDiscover       bool
	doWhois             bool
	doZoneWalk          bool
	doCertCorrelate     bool
	doNeighbors         bool
	doDork              bool
	profileName         string
	watchInterval       string
	stdinMode           bool
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
	rootCmd.Flags().StringVarP(&outputFmt, "format", "f", "text", "Output format: text, json, jsonl, csv, nuclei, burp, sarif")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	rootCmd.Flags().BoolVarP(&activeOnly, "active", "a", false, "Show only active subdomains")
	rootCmd.Flags().StringVar(&dbPath, "db", "", "Save results to SQLite database (e.g. results.db)")
	rootCmd.Flags().StringVar(&reportPath, "report", "", "Generate HTML report (e.g. report.html)")
	rootCmd.Flags().StringVar(&screenshotDir, "screenshot-dir", "screenshots", "Directory to save screenshots")

	// Analysis
	rootCmd.Flags().BoolVarP(&doProbe, "probe", "p", false, "HTTP probe + tech fingerprinting")
	rootCmd.Flags().BoolVarP(&doTakeover, "takeover", "T", false, "Subdomain takeover detection")
	rootCmd.Flags().BoolVar(&doPerm, "permutation", false, "Generate permutations from found subdomains")
	rootCmd.Flags().BoolVar(&doPortScan, "portscan", false, "Scan common ports on active subdomains")
	rootCmd.Flags().StringSliceVar(&dnsRecordTypes, "dns-records", nil, "Fetch DNS records: A,AAAA,MX,TXT (empty = all)")
	rootCmd.Flags().IntVar(&recursiveDepth, "recursive", 0, "Recursive enumeration depth (0=disabled)")

	// Security audit
	rootCmd.Flags().BoolVar(&doHeaders, "headers", false, "Audit HTTP security headers")
	rootCmd.Flags().BoolVar(&doCORS, "cors", false, "Check for CORS misconfigurations")
	rootCmd.Flags().BoolVar(&doSSL, "ssl", false, "Audit SSL/TLS certificates")
	rootCmd.Flags().BoolVar(&doWAF, "waf", false, "Detect WAF/CDN")
	rootCmd.Flags().BoolVar(&doFavicon, "favicon", false, "Calculate favicon hash (Shodan-compatible)")
	rootCmd.Flags().BoolVar(&doASN, "asn", false, "Lookup ASN/GeoIP information")
	rootCmd.Flags().BoolVar(&doJS, "js-scrape", false, "Scrape JS files for endpoints and secrets")
	rootCmd.Flags().BoolVar(&doAdmin, "admin-detect", false, "Detect admin/login panels")
	rootCmd.Flags().BoolVar(&doEmailScore, "email-score", false, "Calculate email security score (SPF/DMARC/DKIM)")
	rootCmd.Flags().BoolVar(&doVHost, "vhost", false, "Virtual host fuzzing (requires --wordlist)")
	rootCmd.Flags().BoolVar(&doExposed, "exposed", false, "Check for exposed sensitive files (.git, .env, backups, etc.)")
	rootCmd.Flags().BoolVar(&doBuckets, "buckets", false, "Check for public cloud storage buckets (S3, GCS, Azure)")
	rootCmd.Flags().BoolVar(&doOpenRedirect, "open-redirect", false, "Test for open redirect vulnerabilities")
	rootCmd.Flags().BoolVar(&doDefaultCreds, "default-creds", false, "Test admin panels for default credentials")
	rootCmd.Flags().BoolVar(&doScreenshot, "screenshot", false, "Take screenshots of active subdomains (requires Chrome)")
	rootCmd.Flags().BoolVar(&doCDNBypass, "cdn-bypass", false, "Attempt to find real IP behind CDN/Cloudflare")

	// Filtering
	rootCmd.Flags().StringVar(&excludeList, "exclude", "", "Comma-separated subdomains/patterns to exclude")
	rootCmd.Flags().StringVar(&excludeFile, "exclude-file", "", "File with exclusion patterns (one per line)")
	rootCmd.Flags().StringVar(&diffFile, "diff", "", "Show only new subdomains vs. a previous results file")

	// Performance
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Concurrent DNS resolvers")
	rootCmd.Flags().IntVar(&timeout, "timeout", 5, "DNS timeout in seconds")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "Max DNS requests per second (0=unlimited)")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", nil, "Custom DNS resolvers (e.g. 8.8.8.8:53)")
	rootCmd.Flags().StringVar(&resolverFile, "resolver-file", "", "File with resolver IPs (one per line)")
	rootCmd.Flags().BoolVar(&doFastResolve, "fast-resolve", false, "Use raw UDP resolver for higher throughput (massdns-style)")
	rootCmd.Flags().BoolVar(&doValidateResolvers, "validate-resolvers", false, "Validate resolvers before scanning")

	// v1.5.0 — extended analysis
	rootCmd.Flags().BoolVar(&doBanner, "banner", false, "TCP banner grabbing on open ports")
	rootCmd.Flags().BoolVar(&doAPIDiscover, "api-discover", false, "Discover GraphQL, Swagger/OpenAPI, gRPC, WebSocket endpoints")
	rootCmd.Flags().BoolVar(&doWhois, "whois", false, "WHOIS lookup for the root domain")
	rootCmd.Flags().BoolVar(&doZoneWalk, "zone-walk", false, "DNSSEC zone walking via NSEC chain")
	rootCmd.Flags().BoolVar(&doCertCorrelate, "cert-correlate", false, "Find related domains via TLS certificate correlation")
	rootCmd.Flags().BoolVar(&doNeighbors, "neighbors", false, "Reverse DNS scan of /24 subnet for each active IP")
	rootCmd.Flags().BoolVar(&doDork, "dork", false, "Search engine dorking (Google/Bing site: dork)")
	rootCmd.Flags().StringVar(&profileName, "profile", "", "Preset profile: quick, stealth, osint, bug-bounty, full")
	rootCmd.Flags().StringVar(&watchInterval, "watch", "", "Watch mode: rescan on interval (e.g. 30m, 1h)")
	rootCmd.Flags().BoolVar(&stdinMode, "stdin", false, "Read subdomains from stdin instead of enumeration")

	// Summary & UI
	rootCmd.Flags().BoolVar(&doSummary, "summary", false, "Print summary report at end of scan")
	rootCmd.Flags().BoolVar(&doTUI, "tui", false, "Interactive TUI mode")

	// State
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Config file (default ~/.config/subhawk/config.yaml)")
	rootCmd.Flags().BoolVar(&doResume, "resume", false, "Resume previous scan from checkpoint")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "profiles",
		Short: "List available scan profiles",
		Run: func(cmd *cobra.Command, args []string) {
			profile.List()
		},
	})

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
	// Apply profile settings before flag validation
	if profileName != "" {
		p, err := profile.Apply(profileName)
		if err != nil {
			return err
		}
		if p.DoAxfr {
			doAxfr = true
		}
		if p.DoDork {
			doDork = true
		}
		if p.DoZoneWalk {
			doZoneWalk = true
		}
		if p.DoProbe {
			doProbe = true
		}
		if p.DoTakeover {
			doTakeover = true
		}
		if p.DoPerm {
			doPerm = true
		}
		if p.DoPortScan {
			doPortScan = true
		}
		if p.DoHeaders {
			doHeaders = true
		}
		if p.DoCORS {
			doCORS = true
		}
		if p.DoSSL {
			doSSL = true
		}
		if p.DoWAF {
			doWAF = true
		}
		if p.DoFavicon {
			doFavicon = true
		}
		if p.DoASN {
			doASN = true
		}
		if p.DoJS {
			doJS = true
		}
		if p.DoAdmin {
			doAdmin = true
		}
		if p.DoExposed {
			doExposed = true
		}
		if p.DoBuckets {
			doBuckets = true
		}
		if p.DoOpenRedirect {
			doOpenRedirect = true
		}
		if p.DoDefaultCreds {
			doDefaultCreds = true
		}
		if p.DoCDNBypass {
			doCDNBypass = true
		}
		if p.DoBanner {
			doBanner = true
		}
		if p.DoAPIDiscover {
			doAPIDiscover = true
		}
		if p.DoWhois {
			doWhois = true
		}
		if p.DoCertCorr {
			doCertCorrelate = true
		}
		if p.DoNeighbors {
			doNeighbors = true
		}
		if p.DoSummary {
			doSummary = true
		}
	}

	if domain == "" && domainsFile == "" && !stdinMode {
		return fmt.Errorf("--domain, --domains-file, or --stdin is required")
	}

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
	var domains []string
	if stdinMode {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if d := strings.TrimSpace(scanner.Text()); d != "" {
				domains = append(domains, d)
			}
		}
		if len(domains) == 0 {
			return fmt.Errorf("no domains received from stdin")
		}
	}
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

	// Diff set
	diffSet := map[string]bool{}
	if diffFile != "" {
		if err := loadDiffSet(diffFile, diffSet); err != nil {
			fmt.Fprintf(os.Stderr, "[!] diff file error: %v\n", err)
		} else {
			fmt.Printf("[*] Diff mode: ignoring %d known subdomains\n", len(diffSet))
		}
	}

	excludePatterns := buildExcludePatterns()

	writer, err := output.New(output.Format(outputFmt), outputFile, noColor)
	if err != nil {
		return fmt.Errorf("output error: %w", err)
	}
	defer writer.Close()
	writer.WriteHeader()

	var db *store.DB
	if dbPath != "" {
		db, err = store.Open(dbPath)
		if err != nil {
			return fmt.Errorf("database error: %w", err)
		}
		defer db.Close()
		fmt.Printf("[*] Database  : %s\n", dbPath)
	}

	var stats *summary.Stats
	if doSummary {
		stats = summary.New()
	}

	// Load extra resolvers from file
	if resolverFile != "" {
		extra, err := fastresolver.LoadResolverList(resolverFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] resolver file: %v\n", err)
		} else {
			resolvers = append(resolvers, extra...)
		}
	}

	// Validate resolvers
	if doValidateResolvers && len(resolvers) > 0 {
		tout := time.Duration(timeout) * time.Second
		fmt.Printf("[*] Validating %d resolvers...\n", len(resolvers))
		resolvers = fastresolver.ValidateResolvers(resolvers, tout)
		fmt.Printf("[*] %d valid resolvers\n", len(resolvers))
	}

	srcOpts := sources.Options{
		WordlistPath:      wordlist,
		VirusTotalKey:     cfg.APIKeys.VirusTotal,
		SecurityTrailsKey: cfg.APIKeys.SecurityTrails,
		ShodanKey:         cfg.APIKeys.Shodan,
		CensysID:          cfg.APIKeys.CensysID,
		CensysSecret:      cfg.APIKeys.CensysSecret,
		ChaosKey:          cfg.APIKeys.Chaos,
		FullHuntKey:       cfg.APIKeys.FullHunt,
		BevigilKey:        cfg.APIKeys.Bevigil,
		LeakIXKey:         cfg.APIKeys.LeakIX,
		GitHubToken:       cfg.APIKeys.GitHubToken,
	}

	// WHOIS lookup per domain
	if doWhois {
		for _, d := range domains {
			info := whois.Lookup(d, time.Duration(timeout)*time.Second*3)
			if info != nil {
				fmt.Printf("\n[*] WHOIS %s\n", d)
				if info.Registrar != "" {
					fmt.Printf("    Registrar  : %s\n", info.Registrar)
				}
				if info.CreatedAt != "" {
					fmt.Printf("    Created    : %s\n", info.CreatedAt)
				}
				if info.ExpiresAt != "" {
					fmt.Printf("    Expires    : %s\n", info.ExpiresAt)
				}
				if info.DNSSEC != "" {
					fmt.Printf("    DNSSEC     : %s\n", info.DNSSEC)
				}
				if len(info.NameServers) > 0 {
					fmt.Printf("    Nameservers: %s\n", strings.Join(info.NameServers, ", "))
				}
				if len(info.Emails) > 0 {
					fmt.Printf("    Emails     : %s\n", strings.Join(info.Emails, ", "))
				}
			}
		}
	}

	// Zone walking
	if doZoneWalk {
		ns := "8.8.8.8:53"
		if len(resolvers) > 0 {
			ns = resolvers[0]
		}
		for _, d := range domains {
			tout := time.Duration(timeout) * time.Second
			walked := zonewalk.Walk(d, ns, tout)
			if len(walked) > 0 {
				fmt.Printf("[!] NSEC zone walk: %d subdomains found for %s\n", len(walked), d)
				for _, s := range walked {
					fmt.Printf("    %s\n", s)
				}
			} else {
				isNSEC3, detail := zonewalk.DetectNSEC3(d, ns, tout)
				if isNSEC3 {
					fmt.Printf("[*] Zone walk: %s uses %s (cannot be walked)\n", d, detail)
				} else {
					fmt.Printf("[*] Zone walk: %s is not DNSSEC-signed or blocks walking\n", d)
				}
			}
		}
	}

	// Google/Bing dorking (add found subs to sources for resolution)
	var dorkSubs []string
	if doDork {
		for _, d := range domains {
			found := dork.Dork(d)
			fmt.Printf("[*] Dork: %d subdomains found for %s\n", len(found), d)
			dorkSubs = append(dorkSubs, found...)
		}
	}
	_ = dorkSubs

	var allResults []resolver.Result

	// Watch mode
	if watchInterval != "" {
		interval, err := time.ParseDuration(watchInterval)
		if err != nil {
			return fmt.Errorf("invalid --watch duration %q: %w", watchInterval, err)
		}
		monitor.Watch(interval, func() []string {
			var subs []string
			for _, d := range domains {
				results, _ := enumerate(d, srcOpts, writer, db, stats, tuiProg, diffSet, excludePatterns, 0)
				for _, r := range results {
					subs = append(subs, r.Subdomain)
				}
			}
			return subs
		}, func(newSubs []string) {
			for _, s := range newSubs {
				fmt.Printf("[NEW] %s\n", s)
			}
		})
		return nil
	}

	for _, d := range domains {
		results, err := enumerate(d, srcOpts, writer, db, stats, tuiProg, diffSet, excludePatterns, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error enumerating %s: %v\n", d, err)
		}
		allResults = append(allResults, results...)
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

	// HTML report
	if reportPath != "" && len(allResults) > 0 {
		dom := domain
		if dom == "" && len(domains) > 0 {
			dom = domains[0]
		}
		if err := report.Generate(dom, allResults, reportPath); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Report error: %v\n", err)
		} else {
			fmt.Printf("[*] HTML report : %s\n", reportPath)
		}
	}

	if doSummary && stats != nil {
		stats.Print()
	}

	if tuiProg != nil {
		tuiProg.Done()
		time.Sleep(200 * time.Millisecond)
	}

	return nil
}

func enumerate(domain string, srcOpts sources.Options, writer *output.Writer, db *store.DB, stats *summary.Stats, tuiProg *tui.Program, diffSet, excludePatterns map[string]bool, depth int) ([]resolver.Result, error) {
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

	if doAxfr {
		logf("[~] Attempting zone transfer...")
		if subs, err := axfr.ZoneTransfer(domain); err == nil {
			logf("[!] Zone transfer SUCCESS: %d records", len(subs))
		} else {
			logf("[*] Zone transfer: %v", err)
		}
	}

	res := resolver.New(resolvers, tout)
	if isWild, wIPs := wildcard.Detect(domain, ns, tout); isWild {
		logf("[!] Wildcard DNS detected → filtering %v", wIPs)
		res.SetWildcardIPs(wIPs)
	} else {
		logf("[*] No wildcard detected")
	}

	rl := ratelimit.New(rateLimit)
	defer rl.Stop()

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
	subCh := make(chan string, 10000)
	srcList := sources.All(srcOpts)
	var srcWg sync.WaitGroup

	for _, src := range srcList {
		if completedSources[src.Name()] {
			continue
		}
		srcWg.Add(1)
		go func(s sources.Source) {
			defer srcWg.Done()
			logf("[~] Source: %s", s.Name())
			subs, err := s.Enumerate(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", s.Name(), err)
				return
			}
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
		}(src)
	}

	go func() {
		srcWg.Wait()
		close(subCh)
	}()

	if tuiProg != nil {
		tuiProg.SetPhase("Resolving DNS")
	}

	// Collect all candidate subdomains for fast-resolve mode
	var candidateList []string

	if doFastResolve {
		// Drain channel into slice, then bulk-resolve
		for sub := range subCh {
			if !isExcluded(sub, excludePatterns) && !diffSet[sub] {
				candidateList = append(candidateList, sub)
			}
		}
	}

	found := 0
	total := 0
	var activeSubs []resolver.Result

	if doFastResolve && len(candidateList) > 0 {
		logf("[*] Fast-resolving %d candidates...", len(candidateList))
		ctx := context.Background()
		frResults := fastresolver.BulkResolve(ctx, candidateList, resolvers, tout, threads*5)
		for _, fr := range frResults {
			total++
			if len(fr.IPs) == 0 {
				continue
			}
			result := resolver.Result{
				Subdomain: fr.Subdomain,
				IPs:       fr.IPs,
				CNAME:     fr.CNAME,
				Active:    true,
			}
			result.Cloud = cloud.Detect(result.CNAME, result.IPs)
			mu.Lock()
			found++
			activeSubs = append(activeSubs, result)
			ckpt.Found = append(ckpt.Found, fr.Subdomain)
			mu.Unlock()
			checkpoint.Save(ckpt)
			if tuiProg != nil {
				tuiProg.AddFound(fr.Subdomain)
			}
		}
	} else {
		// Standard resolver path
		sem := make(chan struct{}, threads)
		var resolveWg sync.WaitGroup

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
				} else if tuiProg == nil && !activeOnly {
					writer.Write(result)
				}
			}(sub)
		}
		resolveWg.Wait()
	}

	// Full DNS records
	if dnsRecordTypes != nil {
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
					A: rec.A, AAAA: rec.AAAA, MX: rec.MX, TXT: rec.TXT, NS: rec.NS,
					CNAME: rec.CNAME, SOA: rec.SOA, SRV: rec.SRV, CAA: rec.CAA, PTR: rec.PTR,
					DMARC: rec.DMARC, SPF: rec.SPF, DNSKEY: rec.DNSKEY, DS: rec.DS,
					TLSA: rec.TLSA, NAPTR: rec.NAPTR, HTTPS: rec.HTTPS,
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
				activeSubs[idx].OpenPorts = portscan.Scan(activeSubs[idx].Subdomain, portscan.DefaultPorts, 3*time.Second)
			}(i)
		}
		psWg.Wait()
	}

	// Permutations
	if doPerm && len(activeSubs) > 0 {
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
				}
			}(p)
		}
		permWg.Wait()
	}

	// HTTP probing
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
		parallel(len(activeSubs), 20, func(idx int) {
			activeSubs[idx].WAF = waf.Detect(activeSubs[idx].Subdomain)
		})
	}

	// Security headers
	if doHeaders && len(activeSubs) > 0 {
		logf("[*] Security headers audit for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Security headers")
		}
		parallel(len(activeSubs), 20, func(idx int) {
			info := headers.Audit(activeSubs[idx].Subdomain)
			activeSubs[idx].SecurityHeaders = (*resolver.SecurityHeadersInfo)(info)
		})
	}

	// CORS check
	if doCORS && len(activeSubs) > 0 {
		logf("[*] CORS check for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("CORS check")
		}
		parallel(len(activeSubs), 20, func(idx int) {
			info := cors.Check(activeSubs[idx].Subdomain)
			activeSubs[idx].CORS = (*resolver.CORSInfo)(info)
			if info != nil && info.Vulnerable && tuiProg != nil {
				tuiProg.AddCORS()
			}
		})
	}

	// SSL/TLS audit
	if doSSL && len(activeSubs) > 0 {
		logf("[*] SSL/TLS audit for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("SSL/TLS audit")
		}
		parallel(len(activeSubs), 20, func(idx int) {
			info := ssl.Audit(activeSubs[idx].Subdomain)
			activeSubs[idx].TLS = (*resolver.TLSInfo)(info)
		})
	}

	// Favicon hash
	if doFavicon && len(activeSubs) > 0 {
		logf("[*] Favicon hashing for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Favicon hash")
		}
		parallel(len(activeSubs), 20, func(idx int) {
			activeSubs[idx].FaviconHash = favicon.Hash(activeSubs[idx].Subdomain)
		})
	}

	// ASN/GeoIP
	if doASN && len(activeSubs) > 0 {
		logf("[*] ASN/GeoIP lookup for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("ASN lookup")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			if len(activeSubs[idx].IPs) > 0 {
				info := asn.Lookup(activeSubs[idx].IPs[0])
				activeSubs[idx].ASN = (*resolver.ASNInfo)(info)
			}
		})
	}

	// JS scraping
	if doJS && len(activeSubs) > 0 {
		logf("[*] JS scraping for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("JS scraping")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			result := jsscrape.Scrape(activeSubs[idx].Subdomain)
			activeSubs[idx].JS = (*resolver.JSInfo)(result)
		})
	}

	// Admin panel detection
	if doAdmin && len(activeSubs) > 0 {
		logf("[*] Admin panel detection for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Admin detection")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			panels := admindetect.Detect(activeSubs[idx].Subdomain)
			for _, p := range panels {
				activeSubs[idx].AdminPanels = append(activeSubs[idx].AdminPanels,
					resolver.AdminPanel{URL: p.URL, StatusCode: p.StatusCode, Title: p.Title})
			}
		})
	}

	// Exposed files
	if doExposed && len(activeSubs) > 0 {
		logf("[*] Exposed file scan for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Exposed files")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			files := exposed.Scan(activeSubs[idx].Subdomain, tout)
			for _, f := range files {
				activeSubs[idx].ExposedFiles = append(activeSubs[idx].ExposedFiles,
					resolver.ExposedFile{Path: f.Path, StatusCode: f.StatusCode, Size: f.Size, URL: f.URL})
			}
		})
	}

	// Cloud bucket check
	if doBuckets && len(activeSubs) > 0 {
		logf("[*] Cloud bucket check for domain %s...", domain)
		if tuiProg != nil {
			tuiProg.SetPhase("Bucket check")
		}
		bkts := buckets.Check(domain, tout)
		if len(bkts) > 0 && len(activeSubs) > 0 {
			for _, b := range bkts {
				activeSubs[0].Buckets = append(activeSubs[0].Buckets, resolver.BucketResult{
					URL: b.URL, Provider: b.Provider, Name: b.Name,
					Public: b.Public, Writable: b.Writable,
				})
			}
		}
	}

	// Open redirect check
	if doOpenRedirect && len(activeSubs) > 0 {
		logf("[*] Open redirect check for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Open redirect")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			results := openredirect.Check(activeSubs[idx].Subdomain, tout)
			for _, r := range results {
				activeSubs[idx].OpenRedirects = append(activeSubs[idx].OpenRedirects,
					resolver.OpenRedirect{URL: r.URL, Param: r.Param})
			}
		})
	}

	// Default credentials (requires admin-detect panels)
	if doDefaultCreds && len(activeSubs) > 0 {
		logf("[*] Default credentials test for admin panels...")
		if tuiProg != nil {
			tuiProg.SetPhase("Default creds")
		}
		parallel(len(activeSubs), 5, func(idx int) {
			for _, panel := range activeSubs[idx].AdminPanels {
				results := defaultcreds.Check(panel.URL, tout)
				for _, r := range results {
					activeSubs[idx].DefaultCreds = append(activeSubs[idx].DefaultCreds,
						resolver.DefaultCred{Username: r.Username, Password: r.Password, Method: r.Method})
				}
			}
		})
	}

	// Banner grabbing
	if doBanner && len(activeSubs) > 0 {
		logf("[*] Banner grabbing for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Banner grab")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			if len(activeSubs[idx].OpenPorts) == 0 {
				return
			}
			banners := banner.GrabAll(activeSubs[idx].Subdomain, activeSubs[idx].OpenPorts, tout)
			for _, b := range banners {
				activeSubs[idx].Banners = append(activeSubs[idx].Banners,
					resolver.BannerInfo{Port: b.Port, Service: b.Service, Raw: b.Raw})
			}
		})
	}

	// API discovery
	if doAPIDiscover && len(activeSubs) > 0 {
		logf("[*] API discovery for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("API discovery")
		}
		parallel(len(activeSubs), 10, func(idx int) {
			res := apidiscover.Discover(activeSubs[idx].Subdomain, tout*2)
			if res == nil {
				return
			}
			apiRes := &resolver.APIResult{
				HasGraphQL:   res.HasGraphQL,
				HasSwagger:   res.HasSwagger,
				HasGRPC:      res.HasGRPC,
				HasWebSocket: res.HasWebSocket,
			}
			for _, ep := range res.Endpoints {
				apiRes.Endpoints = append(apiRes.Endpoints,
					resolver.APIEndpoint{URL: ep.URL, Type: ep.Type, Details: ep.Details})
			}
			activeSubs[idx].APIs = apiRes
		})
	}

	// TLS certificate correlation
	if doCertCorrelate && len(activeSubs) > 0 {
		logf("[*] Certificate correlation for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Cert correlation")
		}
		parallel(len(activeSubs), 5, func(idx int) {
			res := certcorrelate.Find(activeSubs[idx].Subdomain, tout*2)
			if res == nil {
				return
			}
			activeSubs[idx].CertCorrelate = &resolver.CertInfo{
				RelatedDomains: res.RelatedDomains,
				CertCN:         res.CertCN,
				CertIssuer:     res.CertIssuer,
				Fingerprint:    res.Fingerprint,
			}
		})
	}

	// Neighbor /24 scan
	if doNeighbors && len(activeSubs) > 0 {
		logf("[*] Neighbor scan for active IPs...")
		if tuiProg != nil {
			tuiProg.SetPhase("Neighbor scan")
		}
		scannedSubnets := map[string][]neighbors.Host{}
		for i := range activeSubs {
			if len(activeSubs[i].IPs) == 0 {
				continue
			}
			ip := activeSubs[i].IPs[0]
			parts := strings.Split(ip, ".")
			if len(parts) != 4 {
				continue
			}
			subnet := strings.Join(parts[:3], ".")
			if _, already := scannedSubnets[subnet]; !already {
				hosts := neighbors.Scan(ip, tout)
				scannedSubnets[subnet] = hosts
			}
			for _, h := range scannedSubnets[subnet] {
				activeSubs[i].Neighbors = append(activeSubs[i].Neighbors,
					resolver.NeighborHost{IP: h.IP, Hostnames: h.Hostnames})
			}
		}
	}

	// CDN bypass
	if doCDNBypass && len(activeSubs) > 0 {
		logf("[*] CDN bypass for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("CDN bypass")
		}
		parallel(len(activeSubs), 5, func(idx int) {
			results := cdnbypass.Find(activeSubs[idx].Subdomain, tout)
			for _, r := range results {
				if r.Verified {
					activeSubs[idx].RealIP = r.IP
					break
				}
			}
		})
	}

	// Virtual host fuzzing
	if doVHost && wordlist != "" && len(activeSubs) > 0 {
		words := loadWordlist(wordlist)
		if len(words) > 0 {
			logf("[*] Virtual host fuzzing %d subdomains...", len(activeSubs))
			if tuiProg != nil {
				tuiProg.SetPhase("VHost fuzzing")
			}
			parallel(len(activeSubs), 5, func(idx int) {
				if len(activeSubs[idx].IPs) == 0 {
					return
				}
				ip := activeSubs[idx].IPs[0]
				results := vhostfuzz.Fuzz(ip, domain, words, tout, 20)
				for _, r := range results {
					activeSubs[idx].VHosts = append(activeSubs[idx].VHosts, r.VHost)
				}
			})
		}
	}

	// Takeover detection
	if doTakeover && len(activeSubs) > 0 {
		logf("[*] Checking takeover for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Takeover check")
		}
		parallel(len(activeSubs), 20, func(idx int) {
			if activeSubs[idx].CNAME == "" {
				return
			}
			info := takeover.Check(activeSubs[idx])
			if info != nil {
				activeSubs[idx].Takeover = info
				if tuiProg != nil {
					tuiProg.AddTakeover(activeSubs[idx].Subdomain + " [" + info.Service + "]")
				}
			}
		})
	}

	// Screenshots
	if doScreenshot && len(activeSubs) > 0 {
		logf("[*] Taking screenshots for %d subdomains...", len(activeSubs))
		if tuiProg != nil {
			tuiProg.SetPhase("Screenshots")
		}
		subs := make([]string, len(activeSubs))
		for i, r := range activeSubs {
			subs[i] = r.Subdomain
		}
		shots := screenshot.TakeBulk(subs, screenshotDir, tout*6, 3)
		pathMap := map[string]string{}
		for _, s := range shots {
			if s.Path != "" {
				pathMap[s.Subdomain] = s.Path
			}
		}
		for i := range activeSubs {
			if p, ok := pathMap[activeSubs[i].Subdomain]; ok {
				activeSubs[i].ScreenshotPath = p
			}
		}
	}

	// Write all final results
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
			if r.Subdomain == domain {
				continue
			}
			subResults, _ := enumerate(r.Subdomain, srcOpts, writer, db, stats, tuiProg, diffSet, excludePatterns, depth+1)
			activeSubs = append(activeSubs, subResults...)
		}
	}

	if tuiProg == nil {
		fmt.Printf("\n[*] Total enumerated : %d\n", total)
		fmt.Printf("[*] Active subdomains: %d\n", found)
		if outputFile != "" {
			fmt.Printf("[*] Saved to         : %s\n", outputFile)
		}
	}

	if doResume {
		checkpoint.Clear(domain)
	}

	return activeSubs, nil
}

// parallel runs fn(i) for i in [0, n) with at most concurrency goroutines.
func parallel(n, concurrency int, fn func(int)) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(idx)
		}(i)
	}
	wg.Wait()
}

func loadWordlist(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words
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
