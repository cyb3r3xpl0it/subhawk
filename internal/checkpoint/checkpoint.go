package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	Domain           string    `json:"domain"`
	StartedAt        time.Time `json:"started_at"`
	CompletedSources []string  `json:"completed_sources"`
	Found            []string  `json:"found"`
}

func path(domain string) string {
	dir, _ := os.UserCacheDir()
	return filepath.Join(dir, "subhawk", domain+".json")
}

func Load(domain string) (*State, error) {
	data, err := os.ReadFile(path(domain))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func Save(s *State) error {
	p := path(s.Domain)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0644)
}

func Clear(domain string) error {
	return os.Remove(path(domain))
}

func New(domain string) *State {
	return &State{
		Domain:    domain,
		StartedAt: time.Now(),
	}
}
