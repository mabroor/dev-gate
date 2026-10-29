// Package config loads dev-gate's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const minAdminTokenLen = 32

// Config is the contents of /etc/dev-gate/config.yaml. Secrets are referenced
// by file path, never inlined.
type Config struct {
	Listen struct {
		Git    string `yaml:"git"`
		Admin  string `yaml:"admin"`
		Egress string `yaml:"egress"`
	} `yaml:"listen"`
	TLS struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
	GitHubApp struct {
		ID      string `yaml:"id"`
		KeyFile string `yaml:"key_file"`
	} `yaml:"github_app"`
	AdminTokenFile  string   `yaml:"admin_token_file"`
	RegistryPath    string   `yaml:"registry_path"`
	EgressBaseAllow []string `yaml:"egress_base_allow"`
}

// Load reads and validates the config at path. Unknown keys are errors.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	var c Config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	for name, v := range map[string]string{
		"listen.git": c.Listen.Git, "listen.admin": c.Listen.Admin, "listen.egress": c.Listen.Egress,
		"tls.cert": c.TLS.Cert, "tls.key": c.TLS.Key,
		"github_app.id": c.GitHubApp.ID, "github_app.key_file": c.GitHubApp.KeyFile,
		"admin_token_file": c.AdminTokenFile, "registry_path": c.RegistryPath,
	} {
		if v == "" {
			return fmt.Errorf("config: %s is required", name)
		}
	}
	return nil
}

// AdminToken reads the admin bearer token from its file.
func (c *Config) AdminToken() (string, error) {
	b, err := os.ReadFile(c.AdminTokenFile)
	if err != nil {
		return "", fmt.Errorf("config: admin token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if len(tok) < minAdminTokenLen {
		return "", errors.New("config: admin token must be at least 32 characters")
	}
	return tok, nil
}
