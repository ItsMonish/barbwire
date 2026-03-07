package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CorrelationWindowSeconds int                 `yaml:"window_duration"`
	SuspiciousFiles          []FilePair          `yaml:"suspicious_files"`
	SuspiciousParents        []LineageModifier   `yaml:"suspicious_parents"`
	LegitParents             []LineageModifier   `yaml:"legit_parents"`
	SeverityThresholds       SeverityThreshold   `yaml:"severity_thresholds"`
	AlertThreshold           int                 `yaml:"alert_threshold"`
	IgnoredDestinations      IgnoredDestinations `yaml:"whitelist"`
}

type FilePair struct {
	Category  string   `yaml:"category"`
	BaseScore int      `yaml:"base_score"`
	Patterns  []string `yaml:"patterns"`
}

type LineageModifier struct {
	Comm     string `yaml:"program"`
	Modifier int    `yaml:"modifier"`
}

type SeverityThreshold struct {
	Medium int `yaml:"medium"`
	High   int `yaml:"high"`
}

type IgnoredDestinations struct {
	Ports []int    `yaml:"ports"`
	IPs   []string `yaml:"ips"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
