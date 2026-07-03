package utils

import (
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alperenkesk/k8scan/internal/core"
)

// SuppressionRule mirrors one entry in .k8scan-ignore.yaml.
// Both "title" (documented in README) and "finding" (legacy) name the check.
type SuppressionRule struct {
	Finding   string `yaml:"finding,omitempty"`
	Title     string `yaml:"title,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	Resource  string `yaml:"resource,omitempty"`
	Category  string `yaml:"category,omitempty"`
	Severity  string `yaml:"severity,omitempty"`
	Reason    string `yaml:"reason,omitempty"`
}

// titleMatch returns the finding-title criterion, preferring the documented
// "title" key and falling back to the legacy "finding" key.
func (r SuppressionRule) titleMatch() string {
	if r.Title != "" {
		return r.Title
	}
	return r.Finding
}

// isEmpty reports whether the rule has no criteria at all. Such a rule would
// otherwise match — and silently suppress — every finding, so it is ignored.
func (r SuppressionRule) isEmpty() bool {
	return r.titleMatch() == "" && r.Namespace == "" && r.Resource == "" &&
		r.Category == "" && r.Severity == ""
}

// ignoreFile accepts both the documented top-level key "rules" and the legacy
// "suppress" so files written against either the README or older versions work.
type ignoreFile struct {
	Suppress []SuppressionRule `yaml:"suppress"`
	Rules    []SuppressionRule `yaml:"rules"`
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
	// Merge both accepted top-level keys and drop no-criteria rules that would
	// otherwise suppress every finding.
	var rules []SuppressionRule
	for _, r := range append(f.Suppress, f.Rules...) {
		if !r.isEmpty() {
			rules = append(rules, r)
		}
	}
	return &SuppressionManager{rules: rules}, nil
}

// ActiveRuleCount returns how many rules were loaded.
func (sm *SuppressionManager) ActiveRuleCount() int {
	return len(sm.rules)
}

// IsSuppressed returns true if the finding matches any suppression rule.
func (sm *SuppressionManager) IsSuppressed(f *core.Finding) bool {
	for _, r := range sm.rules {
		if t := r.titleMatch(); t != "" && t != f.Title {
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
