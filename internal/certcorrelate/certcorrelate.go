package certcorrelate

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	RelatedDomains []string
	CertCN         string
	CertIssuer     string
	Fingerprint    string
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Find fetches the TLS cert from subdomain:443, then queries crt.sh for related domains.
func Find(subdomain string, timeout time.Duration) *Result {
	dialer := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: subdomain}
	conn, err := tls.DialWithDialer(dialer, "tcp", subdomain+":443", conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	fp := sha1.Sum(cert.Raw)
	fpHex := fmt.Sprintf("%X", fp)
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	_ = fpHex

	result := &Result{
		CertCN:      cert.Subject.CommonName,
		CertIssuer:  cert.Issuer.CommonName,
		Fingerprint: strings.Join(parts, ":"),
	}

	targets := []string{cert.Subject.CommonName}
	targets = append(targets, cert.DNSNames...)

	seen := map[string]bool{subdomain: true}
	for _, name := range targets {
		name = strings.TrimPrefix(name, "*.")
		if name == "" {
			continue
		}
		for _, r := range queryCRTsh(name) {
			if !seen[r] {
				seen[r] = true
				result.RelatedDomains = append(result.RelatedDomains, r)
			}
		}
	}
	return result
}

func queryCRTsh(name string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", name)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var results []string
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.TrimSpace(strings.TrimPrefix(n, "*."))
			if n != "" && !seen[n] {
				seen[n] = true
				results = append(results, n)
			}
		}
	}
	return results
}
