package monitor

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ScanFunc returns the current list of found subdomains.
type ScanFunc func() []string

// OnNewFunc is called when new subdomains are discovered.
type OnNewFunc func(newSubs []string)

// Watch runs scanFn every interval, calls onNew with newly discovered subdomains.
// Stops on SIGINT/SIGTERM.
func Watch(interval time.Duration, scanFn ScanFunc, onNew OnNewFunc) {
	seen := map[string]bool{}

	fmt.Printf("[*] Watch mode: initial scan...\n")
	for _, s := range scanFn() {
		seen[s] = true
	}
	fmt.Printf("[*] Watch mode: %d subdomains found. Rescanning every %s\n", len(seen), interval)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Printf("\n[*] Watch mode stopped.\n")
			return
		case <-ticker.C:
			fmt.Printf("[*] Watch mode: rescanning...\n")
			var newOnes []string
			for _, s := range scanFn() {
				if !seen[s] {
					seen[s] = true
					newOnes = append(newOnes, s)
				}
			}
			if len(newOnes) > 0 {
				fmt.Printf("[!] Watch mode: %d NEW subdomains found!\n", len(newOnes))
				onNew(newOnes)
			} else {
				fmt.Printf("[*] Watch mode: no new subdomains. Next scan in %s\n", interval)
			}
		}
	}
}
