package utils

import (
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alperenkeskin/k8scan/internal/core"
)

// SuppressionRule mirrors one entry in .k8scan-ignore.yaml.
type SuppressionRule struct {
	Finding   string `yaml:"finding,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	Resource  string `yaml:"resource,omitempty"`
	Category  string `yaml:"category,omitempty"`
	Severity  string `yaml:"severity,omitempty"`
	Reason    string `yaml:"reason,omitempty"`
}

type ignoreFile struct {
	Suppress []SuppressionRule `yaml:"suppress"`
}

// SuppressionManager reads .k8scan-ignore.yaml and filters findings.
type SuppressionManager struct {
	rules []SuppressionRule
}

// NewSuppressionManager loads rules from path.
// If the file does not exist, an empty (no-op) manager is returned.
func NewSuppressionManager(path string) (*SuppressionManager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &SuppressionManager{}, nil
		}
		return nil, err
	}
	var f ignoreFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &SuppressionManager{rules: f.Suppress}, nil
}

// ActiveRuleCount returns how many rules were loaded.
func (sm *SuppressionManager) ActiveRuleCount() int {
	return len(sm.rules)
}

// IsSuppressed returns true if the finding matches any suppression rule.
func (sm *SuppressionManager) IsSuppressed(f *core.Finding) bool {
	for _, r := range sm.rules {
		if r.Finding != "" && r.Finding != f.Title {
			continue
		}
		if r.Namespace != "" && r.Namespace != f.Namespace {
			continue
		}
		if r.Resource != "" && !strings.Contains(f.ResourceName, r.Resource) {
			continue
		}
		if r.Category != "" && r.Category != f.Category {
			continue
		}
		if r.Severity != "" && r.Severity != string(f.Severity) {
			continue
		}
		return true
	}
	return false
}

// Filter removes suppressed findings and returns the rest.
func (sm *SuppressionManager) Filter(findings []*core.Finding) []*core.Finding {
	if len(sm.rules) == 0 {
		return findings
	}
	out := make([]*core.Finding, 0, len(findings))
	for _, f := range findings {
		if !sm.IsSuppressed(f) {
			out = append(out, f)
		}
	}
	return out
}
