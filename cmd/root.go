package cmd

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/output"
	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
	"github.com/cyb3r3xpl0it/subhawk/internal/sources"
	"github.com/spf13/cobra"
)

var (
	domain      string
	wordlist    string
	outputFile  string
	outputFmt   string
	threads     int
	timeout     int
	resolvers   []string
	activeOnly  bool
	noColor     bool
	allSources  bool
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
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	rootCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Wordlist file for brute-force")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	rootCmd.Flags().StringVarP(&outputFmt, "format", "f", "text", "Output format: text, json, csv")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Number of concurrent DNS resolvers")
	rootCmd.Flags().IntVar(&timeout, "timeout", 5, "DNS resolution timeout in seconds")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", nil, "Custom DNS resolvers (e.g. 8.8.8.8:53)")
	rootCmd.Flags().BoolVarP(&activeOnly, "active", "a", false, "Show only active (resolved) subdomains")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	rootCmd.Flags().BoolVar(&allSources, "all", false, "Use all passive sources")

	rootCmd.MarkFlagRequired("domain")
}

func run(cmd *cobra.Command, args []string) error {
	output.Banner()

	fmt.Printf("[*] Target  : %s\n", domain)
	fmt.Printf("[*] Threads : %d\n", threads)
	fmt.Printf("[*] Timeout : %ds\n\n", timeout)

	res := resolver.New(resolvers, time.Duration(timeout)*time.Second)

	writer, err := output.New(output.Format(outputFmt), outputFile, noColor)
	if err != nil {
		return fmt.Errorf("output error: %w", err)
	}
	defer writer.Close()

	writer.WriteHeader()

	// Collect subdomains from all sources
	allSubs := map[string]bool{}
	var mu sync.Mutex

	srcList := sources.All(wordlist)

	var srcWg sync.WaitGroup
	subCh := make(chan string, 1000)

	for _, src := range srcList {
		srcWg.Add(1)
		go func(s sources.Source) {
			defer srcWg.Done()
			fmt.Printf("[~] Source: %s\n", s.Name())
			subs, err := s.Enumerate(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s error: %v\n", s.Name(), err)
				return
			}
			for _, sub := range subs {
				mu.Lock()
				if !allSubs[sub] {
					allSubs[sub] = true
					subCh <- sub
				}
				mu.Unlock()
			}
		}(src)
	}

	// Close channel when all sources are done
	go func() {
		srcWg.Wait()
		close(subCh)
	}()

	// DNS resolution pool
	sem := make(chan struct{}, threads)
	var resolveWg sync.WaitGroup

	found := 0
	total := 0

	for sub := range subCh {
		total++
		resolveWg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer resolveWg.Done()
			defer func() { <-sem }()

			result := res.Resolve(s)
			if activeOnly && !result.Active {
				return
			}
			if result.Active {
				mu.Lock()
				found++
				mu.Unlock()
			}
			writer.Write(result)
		}(sub)
	}

	resolveWg.Wait()

	fmt.Printf("\n[*] Total found  : %d\n", total)
	fmt.Printf("[*] Active subs  : %d\n", found)
	if outputFile != "" {
		fmt.Printf("[*] Saved to     : %s\n", outputFile)
	}

	return nil
}
