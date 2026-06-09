package core

import (
	"sort"
	"strings"
)


// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

var severityOrder = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// Confidence level for a finding
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Finding represents a single security finding detected during a scan.
type Finding struct {
	FindingID      int            `json:"id"`
	Severity       Severity       `json:"severity"`
	Category       string         `json:"category"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	ResourceType   string         `json:"resource_type"`
	ResourceName   string         `json:"resource_name"`
	Namespace      string         `json:"namespace,omitempty"`
	Remediation    string         `json:"remediation,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Exploitation   []string       `json:"exploitation,omitempty"`
	AttackFlow     []string       `json:"attack_flow,omitempty"`
	Impact         string         `json:"impact,omitempty"`
	ProofOfConcept string         `json:"proof_of_concept,omitempty"`
	TargetOS     string         `json:"target_os,omitempty"`  // "linux" | "windows"
	Confidence     Confidence     `json:"confidence,omitempty"` // HIGH / MEDIUM / LOW
	// CIS Benchmark fields — populated by compliance enrichment after scanning
	CISControl string `json:"cis_control,omitempty"` // e.g. "5.2.1"
	CISLevel   int    `json:"cis_level,omitempty"`   // 1 or 2
	CISProfile string `json:"cis_profile,omitempty"` // Master, Worker, Policy, RBAC, etcd, Secrets, Admission
	CISTitle   string `json:"cis_title,omitempty"`   // human-readable CIS control title
	// Static analysis fields — populated when scanning YAML/Helm manifests
	SourceFile string `json:"source_file,omitempty"` // path to the YAML file
	SourceLine int    `json:"source_line,omitempty"` // line number within the file (1-based)
}

// SeverityScore returns a numeric score for sorting (lower = more severe).
func (f *Finding) SeverityScore() int {
	if s, ok := severityOrder[f.Severity]; ok {
		return s
	}
	return 5
}

// SortFindings sorts findings by severity (CRITICAL first), then by title.
func SortFindings(findings []*Finding) {
	sort.Slice(findings, func(i, j int) bool {
		si := findings[i].SeverityScore()
		sj := findings[j].SeverityScore()
		if si != sj {
			return si < sj
		}
		return findings[i].Title < findings[j].Title
	})
}

// FilterBySeverity returns only findings at or above the given severity.
func FilterBySeverity(findings []*Finding, minSeverity Severity) []*Finding {
	if minSeverity == "" {
		return findings
	}
	minScore := severityOrder[minSeverity]
	out := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		if f.SeverityScore() <= minScore {
			out = append(out, f)
		}
	}
	return out
}

// FilterByNamespace returns findings matching the given namespace.
func FilterByNamespace(findings []*Finding, ns string) []*Finding {
	if ns == "" {
		return findings
	}
	out := make([]*Finding, 0)
	for _, f := range findings {
		if f.Namespace == ns {
			out = append(out, f)
		}
	}
	return out
}

// FilterByCategory returns findings whose category contains the given string.
func FilterByCategory(findings []*Finding, category string) []*Finding {
	if category == "" {
		return findings
	}
	out := make([]*Finding, 0)
	for _, f := range findings {
		if containsFold(f.Category, category) {
			out = append(out, f)
		}
	}
	return out
}

// Summary holds aggregated counts per severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// BuildSummary computes severity counts from a slice of findings.
func BuildSummary(findings []*Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// SecurityScore returns a 0-100 score and an A-F grade.
// Deductions are capped per severity band so INFO/LOW noise can't tank a clean cluster.
func (s Summary) SecurityScore() (score int, grade string) {
	score = 100
	score -= min(s.Critical*20, 60)
	score -= min(s.High*8, 25)
	score -= min(s.Medium*2, 10)
	score -= min((s.Low+s.Info)*1, 5)
	if score < 0 {
		score = 0
	}
	switch {
	case score >= 85:
		grade = "A"
	case score >= 70:
		grade = "B"
	case score >= 50:
		grade = "C"
	case score >= 30:
		grade = "D"
	default:
		grade = "F"
	}
	return
}

// GroupedFinding represents multiple findings with the same title collapsed together.
type GroupedFinding struct {
	Title     string
	Severity  Severity
	Category  string
	Count     int
	Examples  []*Finding // up to 3 representative findings
	Remediation string
}

// severityScore returns a numeric score for the group's current severity (lower = more severe).
func (g *GroupedFinding) severityScore() int {
	if s, ok := severityOrder[g.Severity]; ok {
		return s
	}
	return 5
}

// GroupFindings collapses findings with identical titles into GroupedFindings.
// When multiple findings share the same title but differ in severity (e.g.
// because different containers trigger CRITICAL vs HIGH), the group adopts the
// most severe level so the user is never underinformed.
func GroupFindings(findings []*Finding) []GroupedFinding {
	order := make([]string, 0)
	groups := make(map[string]*GroupedFinding)

	for _, f := range findings {
		if g, ok := groups[f.Title]; ok {
			g.Count++
			// Keep the most severe level across grouped findings.
			if f.SeverityScore() < g.severityScore() {
				g.Severity = f.Severity
			}
			if len(g.Examples) < 3 {
				g.Examples = append(g.Examples, f)
			}
		} else {
			order = append(order, f.Title)
			groups[f.Title] = &GroupedFinding{
				Title:       f.Title,
				Severity:    f.Severity,
				Category:    f.Category,
				Count:       1,
				Examples:    []*Finding{f},
				Remediation: f.Remediation,
			}
		}
	}

	result := make([]GroupedFinding, 0, len(order))
	for _, title := range order {
		result = append(result, *groups[title])
	}
	return result
}

// containsFold reports whether s contains substr, case-insensitively.
// Uses strings.Contains on lower-cased copies so that UTF-8 multi-byte
// characters are handled correctly (the previous manual ASCII implementation
// was only safe for single-byte Latin characters).
func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
