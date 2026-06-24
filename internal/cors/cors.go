package cors

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Info struct {
	Vulnerable            bool
	AllowsArbitraryOrigin bool
	AllowsCredentials     bool
	AllowOrigin           string
}

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func Check(subdomain string) *Info {
	for _, scheme := range []string{"https", "http"} {
		info := probe(fmt.Sprintf("%s://%s", scheme, subdomain))
		if info != nil {
			return info
		}
	}
	return nil
}

func probe(url string) *Info {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", "https://evil.subhawk.test")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	if acao == "" {
		return nil
	}

	info := &Info{
		AllowOrigin:       acao,
		AllowsCredentials: acac,
	}

	// Wildcard is only vulnerable without credentials
	if acao == "*" {
		info.AllowsArbitraryOrigin = true
		info.Vulnerable = true
	}

	// Reflected arbitrary origin + credentials = critical
	if strings.Contains(acao, "evil.subhawk.test") {
		info.AllowsArbitraryOrigin = true
		info.Vulnerable = true
	}

	// null origin with credentials
	if acao == "null" && acac {
		info.Vulnerable = true
	}

	return info
}
