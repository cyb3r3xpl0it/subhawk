package banner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Banner struct {
	Port    int
	Service string
	Raw     string
}

var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
	3306: "mysql", 5432: "postgres", 6379: "redis", 8080: "http-alt",
	8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch",
	11211: "memcached", 2181: "zookeeper", 9092: "kafka",
}

func Grab(host string, port int, timeout time.Duration) *Banner {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, _ = conn.Read(buf)
	}
	if n == 0 {
		return nil
	}

	raw := strings.TrimSpace(string(buf[:n]))
	var clean strings.Builder
	for _, r := range raw {
		if r >= 32 && r < 127 {
			clean.WriteRune(r)
		}
	}
	if clean.Len() == 0 {
		return nil
	}

	svc := commonServices[port]
	if svc == "" {
		svc = guessService(clean.String())
	}
	return &Banner{Port: port, Service: svc, Raw: clean.String()}
}

func GrabAll(host string, ports []int, timeout time.Duration) []Banner {
	var mu sync.Mutex
	var results []Banner
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			if b := Grab(host, p, timeout); b != nil {
				mu.Lock()
				results = append(results, *b)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return results
}

func guessService(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ssh"):
		return "ssh"
	case strings.Contains(b, "ftp"):
		return "ftp"
	case strings.Contains(b, "smtp") || strings.Contains(b, "220 "):
		return "smtp"
	case strings.Contains(b, "http"):
		return "http"
	case strings.Contains(b, "redis"):
		return "redis"
	case strings.Contains(b, "mysql"):
		return "mysql"
	case strings.Contains(b, "postgresql"):
		return "postgres"
	default:
		return "unknown"
	}
}
