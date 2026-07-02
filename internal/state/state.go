// Package state tracks AgentKMS install mode and paths (~/.agentkms/config.yaml).
package state

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Mode is dev (loopback only) or prod (remote hostname).
type Mode string

const (
	ModeDev  Mode = "dev"
	ModeProd Mode = "prod"
)

// Config is persisted after agentkms init.
type Config struct {
	Mode       Mode   `yaml:"mode"`
	Host       string `yaml:"host,omitempty"`
	DataDir    string `yaml:"data_dir"`
	ListenAddr string `yaml:"listen_addr"`
	TrustDomain string `yaml:"trust_domain,omitempty"`
}

// DefaultPath returns ~/.agentkms/config.yaml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentkms", "config.yaml"), nil
}

// Load reads install state. Returns nil, nil if not initialized.
func Load() (*Config, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("state: parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes install state.
func Save(cfg *Config) error {
	path, err := DefaultPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// DevDataDir is the default dev PKI directory.
func DevDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentkms", "dev"), nil
}

// ProdDataDir returns ~/.agentkms/prod/<host>.
func ProdDataDir(host string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentkms", "prod", host), nil
}
