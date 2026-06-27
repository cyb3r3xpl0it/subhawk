package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type APIKeys struct {
	VirusTotal     string `yaml:"virustotal"`
	SecurityTrails string `yaml:"securitytrails"`
	Shodan         string `yaml:"shodan"`
	CensysID       string `yaml:"censys_id"`
	CensysSecret   string `yaml:"censys_secret"`
	Chaos          string `yaml:"chaos"`
	FullHunt       string `yaml:"fullhunt"`
	Bevigil        string `yaml:"bevigil"`
	LeakIX         string `yaml:"leakix"`
	GitHubToken    string `yaml:"github_token"`
}

type Config struct {
	APIKeys APIKeys `yaml:"api_keys"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = defaultPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func defaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		// fallback to home/.config
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "subhawk", "config.yaml")
}

func WriteDefault(path string) error {
	if path == "" {
		path = defaultPath()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	template := `# SubHawk configuration
api_keys:
  virustotal: ""
  securitytrails: ""
  shodan: ""
  censys_id: ""
  censys_secret: ""
  chaos: ""
  fullhunt: ""
  bevigil: ""
  leakix: ""
  github_token: ""
`
	return os.WriteFile(path, []byte(template), 0600)
}
