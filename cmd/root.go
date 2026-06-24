package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/config"
	"github.com/cyb3r3xpl0it/subhawk/internal/output"
	"github.com/cyb3r3xpl0it/subhawk/internal/permutation"
	"github.com/cyb3r3xpl0it/subhawk/internal/probe"
	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
	"github.com/cyb3r3xpl0it/subhawk/internal/sources"
	"github.com/cyb3r3xpl0it/subhawk/internal/takeover"
	"github.com/cyb3r3xpl0it/subhawk/internal/wildcard"
	"github.com/spf13/cobra"
)

var (
	domain      string
	domainsFile string
	wordlist    string
	outputFile  string
	outputFmt   string
	configFile  string
	threads     int
	timeout     int
	resolvers   []string
	activeOnly  bool
	noColor     bool
	doProbe     bool
	doTakeover  bool
	doPerm      bool
)

var rootCmd = &cobra.Command{
	Use:   "subhawk",
	Short: "SubHawk - Subdomain Enumeration Tool",
	Long:  `SubHawk enumerates subdomains via passive sources and active DNS brute-force.`,
	RunE:  run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain")
	rootCmd.Flags().StringVarP(&domainsFile, "domains-file", "D", "", "File with list of domains (one per line)")
	rootCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Wordlist for brute-force")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	rootCmd.Flags().StringVarP(&outputFmt, "format", "f", "text", "Output format: text, json, csv")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Config file (default ~/.config/subhawk/config.yaml)")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Concurrent DNS resolvers")
	rootCmd.Flags().IntVar(&timeout, "timeout", 5, "DNS timeout in seconds")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", nil, "Custom DNS resolvers (e.g. 8.8.8.8:53)")
	rootCmd.Flags().BoolVarP(&activeOnly, "active", "a", false, "Show only active subdomains")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	rootCmd.Flags().BoolVarP(&doProbe, "probe", "p", false, "HTTP probe active subdomains")
	rootCmd.Flags().BoolVarP(&doTakeover, "takeover", "T", false, "Check for subdomain takeover")
	rootCmd.Flags().BoolVar(&doPerm, "permutation", false, "Generate permutations from found subdomains")

	// init-config subcommand
	rootCmd.AddCommand(&cobra.Command{
		Use:   "init-config",
		Short: "Create default config file at ~/.config/subhawk/config.yaml",
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
		if err := enumerate(d, srcOpts, cfg, writer); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error enumerating %s: %v\n", d, err)
		}
	}

	return nil
}

func enumerate(domain string, srcOpts sources.Options, cfg *config.Config, writer *output.Writer) error {
	tout := time.Duration(timeout) * time.Second
	ns := "8.8.8.8:53"
	if len(resolvers) > 0 {
		ns = resolvers[0]
	}

	fmt.Printf("[*] Target  : %s\n", domain)
	fmt.Printf("[*] Threads : %d\n", threads)

	// Wildcard detection
	if isWild, wIPs := wildcard.Detect(domain, ns, tout); isWild {
		fmt.Printf("[!] Wildcard detected for %s → filtering IPs: %v\n", domain, wIPs)
		res := resolver.New(resolvers, tout)
		res.SetWildcardIPs(wIPs)
	} else {
		fmt.Printf("[*] No wildcard detected\n")
	}

	res := resolver.New(resolvers, tout)
	if isWild, wIPs := wildcard.Detect(domain, ns, tout); isWild {
		res.SetWildcardIPs(wIPs)
	}

	// Source enumeration
	allSubs := map[string]bool{}
	var mu sync.Mutex
	subCh := make(chan string, 5000)

	srcList := sources.All(srcOpts)
	var srcWg sync.WaitGroup

	for _, src := range srcList {
		srcWg.Add(1)
		go func(s sources.Source) {
			defer srcWg.Done()
			fmt.Printf("[~] Source: %s\n", s.Name())
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
			mu.Unlock()
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
		total++
		resolveWg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer resolveWg.Done()
			defer func() { <-sem }()

			result := res.Resolve(s)
			if result.IsWildcard {
				return
			}
			if activeOnly && !result.Active {
				return
			}
			if result.Active {
				mu.Lock()
				found++
				activeSubs = append(activeSubs, result)
				mu.Unlock()
			}
			writer.Write(result)
		}(sub)
	}

	resolveWg.Wait()

	// Permutations
	if doPerm && len(activeSubs) > 0 {
		fmt.Printf("\n[*] Generating permutations from %d found subdomains...\n", len(activeSubs))
		var foundNames []string
		for _, r := range activeSubs {
			foundNames = append(foundNames, r.Subdomain)
		}
		perms := permutation.Generate(foundNames, domain)
		fmt.Printf("[*] Testing %d permutations...\n", len(perms))

		var permWg sync.WaitGroup
		permSem := make(chan struct{}, threads)

		for _, p := range perms {
			mu.Lock()
			alreadyFound := allSubs[p]
			if !alreadyFound {
				allSubs[p] = true
			}
			mu.Unlock()

			if alreadyFound {
				continue
			}

			permWg.Add(1)
			permSem <- struct{}{}
			go func(sub string) {
				defer permWg.Done()
				defer func() { <-permSem }()

				result := res.Resolve(sub)
				if result.IsWildcard || !result.Active {
					return
				}
				mu.Lock()
				found++
				activeSubs = append(activeSubs, result)
				mu.Unlock()
				writer.Write(result)
			}(p)
		}
		permWg.Wait()
	}

	// HTTP probing
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

				info := probe.Probe(activeSubs[idx].Subdomain)
				activeSubs[idx].HTTP = info
				if info != nil {
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

	fmt.Printf("\n[*] Total found  : %d\n", total)
	fmt.Printf("[*] Active subs  : %d\n", found)
	if outputFile != "" {
		fmt.Printf("[*] Saved to     : %s\n", outputFile)
	}

	return nil
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
