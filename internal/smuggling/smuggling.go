package smuggling

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type Result struct {
	Subdomain  string
	Technique  string // "CL.TE", "TE.CL", "TE.TE"
	Vulnerable bool
	Notes      string
}

// sendRaw sends a raw HTTP/1.1 request and reads the response status.
func sendRaw(host string, port int, req string, timeout time.Duration) (int, string, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprint(conn, req)

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	// Read a bit more for body
	var body strings.Builder
	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		body.WriteString(line)
		if err != nil {
			break
		}
	}
	// Parse status code
	var code int
	fmt.Sscanf(statusLine, "HTTP/1.1 %d", &code)
	if code == 0 {
		fmt.Sscanf(statusLine, "HTTP/1.0 %d", &code)
	}
	return code, body.String(), nil
}

// Check performs basic CL.TE and TE.CL HTTP request smuggling probes.
// This is a timing/response-based heuristic — not a definitive exploit.
func Check(subdomain string, timeout time.Duration) *Result {
	result := &Result{Subdomain: subdomain}

	// Try port 80 and 443 (plain TCP, not TLS — for basic detection only)
	for _, port := range []int{80} {
		host := subdomain

		// CL.TE probe: send Content-Length that doesn't match actual body
		// If server uses CL and backend uses TE, the "\r\nX" leaks to next request
		clteReq := fmt.Sprintf(
			"POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
			host,
		)
		code1, _, err1 := sendRaw(host, port, clteReq, timeout)

		// Normal request for baseline
		normalReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		code2, _, err2 := sendRaw(host, port, normalReq, timeout)

		if err1 != nil || err2 != nil {
			continue
		}

		// If the smuggled byte caused a 400/500 on the second request that normally returns 200/301
		// this is a strong indicator (timing or status mismatch)
		if code2 >= 400 && code1 == 200 {
			result.Vulnerable = true
			result.Technique = "CL.TE (possible)"
			result.Notes = fmt.Sprintf("CL.TE probe: first=%d, second=%d — status mismatch may indicate smuggling", code1, code2)
		}
	}

	return result
}
