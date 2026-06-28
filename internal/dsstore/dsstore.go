package dsstore

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Fetch attempts to download and parse .DS_Store from the given base URL.
// Returns a list of filenames/directories found in the file.
func Fetch(subdomain string, timeout time.Duration) []string {
	bases := []string{"https://" + subdomain, "http://" + subdomain}
	for _, base := range bases {
		resp, err := httpClient.Get(base + "/.DS_Store")
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		if err != nil || len(body) < 32 {
			continue
		}
		entries := parse(body)
		if len(entries) > 0 {
			return entries
		}
	}
	return nil
}

// parse extracts filenames from .DS_Store binary format.
// .DS_Store uses a B-tree structure; we search for UTF-16 strings preceded by length+type markers.
func parse(data []byte) []string {
	seen := map[string]bool{}
	var results []string

	// Magic: 0x00 0x00 0x00 0x01 at offset 0 and "Bud1" at offset 4
	if len(data) < 8 {
		return nil
	}
	if !bytes.Equal(data[4:8], []byte("Bud1")) {
		return nil
	}

	// Walk through data looking for UTF-16BE encoded strings.
	// Each filename record is: 4 bytes length (big-endian) + "ustr" type marker + UTF-16BE string.
	for i := 0; i < len(data)-8; i++ {
		if i+8 > len(data) {
			break
		}
		// Look for "ustr" type marker
		if string(data[i:i+4]) != "ustr" {
			continue
		}
		// Before "ustr" there should be a 4-byte length
		if i < 4 {
			continue
		}
		length := int(binary.BigEndian.Uint32(data[i-4 : i]))
		if length <= 0 || length > 255 || i+4+length*2 > len(data) {
			continue
		}
		// Read length*2 bytes as UTF-16BE
		raw := data[i+4 : i+4+length*2]
		name := decodeUTF16BE(raw)
		name = strings.TrimSpace(name)
		if name != "" && !strings.HasPrefix(name, ".") && !seen[name] {
			seen[name] = true
			results = append(results, name)
		}
	}
	return results
}

func decodeUTF16BE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 2 {
		r := rune(binary.BigEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		if r >= 32 && r < 127 {
			sb.WriteRune(r)
		} else if r > 127 {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
