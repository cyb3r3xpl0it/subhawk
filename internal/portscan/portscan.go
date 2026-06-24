package portscan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var DefaultPorts = []int{
	80, 443, 8080, 8443, 8888, 3000, 4000, 5000,
	9000, 9090, 7443, 4443, 8000, 8001, 8008,
	8081, 8082, 8083, 8084, 8085, 8086, 8087,
	81, 82, 83, 591, 2082, 2086, 2095, 6443,
}

// Scan checks which ports are open on the given host.
func Scan(host string, ports []int, timeout time.Duration) []int {
	var (
		open []int
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 50)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(open)
	return open
}
