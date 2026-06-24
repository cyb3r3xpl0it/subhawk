package permutation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var mutationWords = []string{
	"dev", "development", "staging", "stg", "stage",
	"test", "testing", "qa", "uat", "prod", "production",
	"api", "v1", "v2", "v3", "beta", "alpha",
	"old", "new", "internal", "admin", "backend",
	"mobile", "app", "cdn", "static", "sandbox",
	"demo", "pre", "preprod", "corp", "secure",
}

var reNumber = regexp.MustCompile(`(\d+)$`)

// Generate creates permutations from a list of found subdomains.
func Generate(found []string, domain string) []string {
	suffix := "." + domain
	seen := map[string]bool{}
	var results []string

	add := func(sub string) {
		full := sub + suffix
		if !seen[full] {
			seen[full] = true
			results = append(results, full)
		}
	}

	prefixes := map[string]bool{}
	for _, f := range found {
		prefix := strings.TrimSuffix(f, suffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			continue
		}
		prefixes[prefix] = true
	}

	for prefix := range prefixes {
		for _, word := range mutationWords {
			add(fmt.Sprintf("%s-%s", prefix, word))
			add(fmt.Sprintf("%s-%s", word, prefix))
			add(fmt.Sprintf("%s.%s", prefix, word))
			add(fmt.Sprintf("%s.%s", word, prefix))
		}

		// Number mutations: api → api2, api3; api2 → api1, api3
		if m := reNumber.FindStringSubmatch(prefix); m != nil {
			n, _ := strconv.Atoi(m[1])
			base := prefix[:len(prefix)-len(m[1])]
			for _, delta := range []int{-1, 1, 2} {
				next := n + delta
				if next > 0 {
					add(fmt.Sprintf("%s%d", base, next))
				}
			}
		} else {
			add(fmt.Sprintf("%s2", prefix))
		}
	}

	return results
}
