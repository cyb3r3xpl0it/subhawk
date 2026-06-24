package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAll_NoWordlist(t *testing.T) {
	srcs := All(Options{})
	if len(srcs) == 0 {
		t.Fatal("expected at least one source")
	}
	for _, s := range srcs {
		if s.Name() == "wordlist" {
			t.Error("wordlist source should not be included when path is empty")
		}
	}
}

func TestAll_WithWordlist(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "words.txt")
	os.WriteFile(tmp, []byte("www\nmail\napi\n"), 0644)

	srcs := All(Options{WordlistPath: tmp})
	found := false
	for _, s := range srcs {
		if s.Name() == "wordlist" {
			found = true
		}
	}
	if !found {
		t.Error("wordlist source should be included when path is provided")
	}
}

func TestAll_WithAPIKeys(t *testing.T) {
	srcs := All(Options{
		VirusTotalKey:     "test-key",
		SecurityTrailsKey: "test-key",
		ShodanKey:         "test-key",
		CensysID:          "test-id",
		CensysSecret:      "test-secret",
	})
	names := map[string]bool{}
	for _, s := range srcs {
		names[s.Name()] = true
	}
	for _, expected := range []string{"virustotal", "securitytrails", "shodan", "censys"} {
		if !names[expected] {
			t.Errorf("expected source %q when API key is set", expected)
		}
	}
}

func TestWordlist_Enumerate(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "words.txt")
	os.WriteFile(tmp, []byte("www\nmail\n# comment\napi\n"), 0644)

	w := &Wordlist{Path: tmp}
	results, err := w.Enumerate("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d: %v", len(results), results)
	}
	for _, r := range results {
		if !strings.HasSuffix(r, ".example.com") {
			t.Errorf("expected suffix .example.com in %q", r)
		}
	}
}

func TestWordlist_MissingFile(t *testing.T) {
	w := &Wordlist{Path: "/nonexistent/path/words.txt"}
	_, err := w.Enumerate("example.com")
	if err == nil {
		t.Error("expected error for missing wordlist file")
	}
}

func TestSourceNames_NoDuplicates(t *testing.T) {
	names := map[string]bool{}
	for _, s := range All(Options{}) {
		if names[s.Name()] {
			t.Errorf("duplicate source name: %s", s.Name())
		}
		names[s.Name()] = true
	}
}

func TestAll_NoAPIKeys_ExcludesKeyedSources(t *testing.T) {
	srcs := All(Options{})
	for _, s := range srcs {
		switch s.Name() {
		case "virustotal", "securitytrails", "shodan", "censys":
			t.Errorf("source %q should not be included without API key", s.Name())
		}
	}
}
