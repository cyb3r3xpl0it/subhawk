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
}

type Config struct {
	APIKeys APIKeys `yaml:"api_keys"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return &Config{}, nil
		}
		path = filepath.Join(home, ".config", "subhawk", "config.yaml")
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

func WriteDefault(path string) error {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".config", "subhawk", "config.yaml")
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
`
	return os.WriteFile(path, []byte(template), 0600)
}
