package favicon

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spaolacci/murmur3"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Hash fetches /favicon.ico and returns the Shodan-compatible MurmurHash3.
func Hash(subdomain string) string {
	for _, scheme := range []string{"https", "http"} {
		h := fetchHash(fmt.Sprintf("%s://%s/favicon.ico", scheme, subdomain))
		if h != "" {
			return h
		}
	}
	return ""
}

func fetchHash(url string) string {
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || len(data) == 0 {
		return ""
	}

	// Shodan encodes in standard base64 with newlines every 76 chars
	encoded := insertNewlines(base64.StdEncoding.EncodeToString(data), 76)
	hash := int32(murmur3.Sum32([]byte(encoded)))
	return fmt.Sprintf("%d", hash)
}

func insertNewlines(s string, width int) string {
	var sb strings.Builder
	for i, ch := range s {
		if i > 0 && i%width == 0 {
			sb.WriteByte('\n')
		}
		sb.WriteRune(ch)
	}
	sb.WriteByte('\n')
	return sb.String()
}
