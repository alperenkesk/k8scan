package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alperenkesk/k8scan/internal/compliance"
	"github.com/alperenkesk/k8scan/internal/core"
)

// ─── Shared metadata ──────────────────────────────────────────────────────────

// ReportMeta carries cluster and scan metadata into every report format.
type ReportMeta struct {
	ClusterContext string
	ClusterVersion string
	NodeCount      int
	NamespaceCount int
	ScanDurationMS int64
	K8scanVersion  string
}

// ─── JSON output ──────────────────────────────────────────────────────────────

// WriteJSON writes a structured JSON report with score, grade, cluster metadata,
// and full Capability Break / Compound Break analysis results.
func WriteJSON(findings []*core.Finding, cbResult core.CBAnalysisResult, meta ReportMeta, path string) error {
	summary := core.BuildSummary(findings)
	score, grade := summary.SecurityScore()

	type jsonSummary struct {
		Total    int    `json:"total"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Medium   int    `json:"medium"`
		Low      int    `json:"low"`
		Info     int    `json:"info"`
		Score    int    `json:"score"`
		Grade    string `json:"grade"`
	}
	type jsonCluster struct {
		Context        string `json:"context,omitempty"`
		ServerVersion  string `json:"server_version,omitempty"`
		NodeCount      int    `json:"node_count,omitempty"`
		NamespaceCount int    `json:"namespace_count,omitempty"`
	}
	type jsonScan struct {
		K8scanVersion       string  `json:"k8scan_version"`
		GeneratedAt         string  `json:"generated_at"`
		ScanDurationSeconds float64 `json:"scan_duration_seconds,omitempty"`
	}

	// ── Capability Break JSON types ──────────────────────────────
	type jsonProofSignal struct {
		Title        string  `json:"title"`
		Resource     string  `json:"resource"`
		Severity     string  `json:"severity"`
		Significance string  `json:"significance"`
		Weight       float64 `json:"weight"`
	}
	type jsonValidationProof struct {
		Verdict  string            `json:"verdict"`
		Signals  []jsonProofSignal `json:"signals"`
		Combined string            `json:"combined"`
	}
	type jsonBlastRadius struct {
		Mode       string `json:"mode"`
		Level      string `json:"level"`
		Pods       int    `json:"pods,omitempty"`
		Namespaces int    `json:"namespaces,omitempty"`
		Nodes      int    `json:"nodes,omitempty"`
		Secrets    int    `json:"secrets,omitempty"`
	}
	type jsonMITRE struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Tactic string `json:"tactic"`
	}
	type jsonEvidence struct {
		FindingID    int    `json:"finding_id"`
		Title        string `json:"title"`
		ResourceName string `json:"resource_name"`
		Namespace    string `json:"namespace,omitempty"`
		Severity     string `json:"severity"`
	}
	type jsonCB struct {
		ID              string              `json:"id"`
		Name            string              `json:"name"`
		Boundary        string              `json:"boundary"`
		Status          string              `json:"status"`
		Confidence      int                 `json:"confidence"`
		Exploitability  string              `json:"exploitability"`
		FixPriority     string              `json:"fix_priority"`
		BlastRadius     jsonBlastRadius     `json:"blast_radius"`
		MITRE           []jsonMITRE         `json:"mitre,omitempty"`
		Evidence        []jsonEvidence      `json:"evidence"`
		ValidationProof jsonValidationProof `json:"validation_proof"`
		AttackPath      []string            `json:"attack_path,omitempty"`
		Impact          []string            `json:"impact,omitempty"`
		Remediation     string              `json:"remediation"`
		ProofOfConcept  string              `json:"proof_of_concept,omitempty"`
	}
	type jsonCapabilityBreaks struct {
		BlastMode string   `json:"blast_mode"`
		Count     int      `json:"count"`
		Breaks    []jsonCB `json:"breaks"`
	}
	type jsonCompound struct {
		ID             string          `json:"id"`
		Name           string          `json:"name"`
		ConstituentCBs []string        `json:"constituent_cbs"`
		Confidence     int             `json:"confidence"`
		Path           []string        `json:"path,omitempty"`
		Impact         string          `json:"impact,omitempty"`
		Remediation    string          `json:"remediation,omitempty"`
		MITRE          []jsonMITRE     `json:"mitre,omitempty"`
		BlastRadius    jsonBlastRadius `json:"blast_radius"`
	}
	type jsonCompoundBreaks struct {
		Count  int            `json:"count"`
		Breaks []jsonCompound `json:"breaks"`
	}
	type jsonReport struct {
		Scan             jsonScan             `json:"scan"`
		Cluster          jsonCluster          `json:"cluster"`
		Summary          jsonSummary          `json:"summary"`
		Findings         []*core.Finding      `json:"findings"`
		CapabilityBreaks jsonCapabilityBreaks `json:"capability_breaks"`
		CompoundBreaks   jsonCompoundBreaks   `json:"compound_breaks"`
	}

	// ── Build CB slice ───────────────────────────────────────────
	cbSlice := make([]jsonCB, 0, len(cbResult.CapabilityBreaks))
	for _, cb := range cbResult.CapabilityBreaks {
		ev := make([]jsonEvidence, 0, len(cb.Evidence))
		for _, e := range cb.Evidence {
			ev = append(ev, jsonEvidence{
				FindingID: e.FindingID, Title: e.Title,
				ResourceName: e.ResourceName, Namespace: e.Namespace, Severity: e.Severity,
			})
		}
		sigs := make([]jsonProofSignal, 0, len(cb.ValidationProof.Signals))
		for _, s := range cb.ValidationProof.Signals {
			sigs = append(sigs, jsonProofSignal{
				Title: s.Title, Resource: s.Resource,
				Severity: s.Severity, Significance: s.Significance, Weight: s.Weight,
			})
		}
		mitres := make([]jsonMITRE, 0, len(cb.MITRE))
		for _, m := range cb.MITRE {
			mitres = append(mitres, jsonMITRE{ID: m.ID, Name: m.Name, Tactic: m.Tactic})
		}
		cbSlice = append(cbSlice, jsonCB{
			ID: cb.ID, Name: cb.Name, Boundary: cb.Boundary,
			Status: string(cb.Status), Confidence: cb.Confidence,
			Exploitability: string(cb.Exploitability), FixPriority: cb.FixPriority,
			BlastRadius: jsonBlastRadius{
				Mode: string(cb.BlastRadius.Mode), Level: cb.BlastRadius.Level,
				Pods: cb.BlastRadius.Pods, Namespaces: cb.BlastRadius.Namespaces,
				Nodes: cb.BlastRadius.Nodes, Secrets: cb.BlastRadius.Secrets,
			},
			MITRE:    mitres,
			Evidence: ev,
			ValidationProof: jsonValidationProof{
				Verdict: cb.ValidationProof.Verdict, Signals: sigs,
				Combined: cb.ValidationProof.Combined,
			},
			AttackPath:     cb.AttackGraph.Path,
			Impact:         cb.Impact,
			Remediation:    cb.Remediation,
			ProofOfConcept: cb.ProofOfConcept,
		})
	}

	// ── Build Compound slice ─────────────────────────────────────
	compSlice := make([]jsonCompound, 0, len(cbResult.CompoundBreaks))
	for _, c := range cbResult.CompoundBreaks {
		mitres := make([]jsonMITRE, 0, len(c.MITRE))
		for _, m := range c.MITRE {
			mitres = append(mitres, jsonMITRE{ID: m.ID, Name: m.Name, Tactic: m.Tactic})
		}
		compSlice = append(compSlice, jsonCompound{
			ID: c.ID, Name: c.Name, ConstituentCBs: c.CBIDs,
			Confidence: c.Confidence, Path: c.Path,
			Impact: c.Impact, Remediation: c.Remediation,
			MITRE: mitres,
			BlastRadius: jsonBlastRadius{
				Mode: string(c.BlastRadius.Mode), Level: c.BlastRadius.Level,
				Pods: c.BlastRadius.Pods, Namespaces: c.BlastRadius.Namespaces,
				Nodes: c.BlastRadius.Nodes, Secrets: c.BlastRadius.Secrets,
			},
		})
	}

	durSec := float64(0)
	if meta.ScanDurationMS > 0 {
		durSec = float64(meta.ScanDurationMS) / 1000.0
	}

	rep := jsonReport{
		Scan: jsonScan{
			K8scanVersion:       meta.K8scanVersion,
			GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
			ScanDurationSeconds: durSec,
		},
		Cluster: jsonCluster{
			Context:        meta.ClusterContext,
			ServerVersion:  meta.ClusterVersion,
			NodeCount:      meta.NodeCount,
			NamespaceCount: meta.NamespaceCount,
		},
		Summary: jsonSummary{
			Total: summary.Total, Critical: summary.Critical, High: summary.High,
			Medium: summary.Medium, Low: summary.Low, Info: summary.Info,
			Score: score, Grade: grade,
		},
		Findings:         findings,
		CapabilityBreaks: jsonCapabilityBreaks{BlastMode: string(cbResult.BlastMode), Count: len(cbSlice), Breaks: cbSlice},
		CompoundBreaks:   jsonCompoundBreaks{Count: len(compSlice), Breaks: compSlice},
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json report: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ─── HTML output ──────────────────────────────────────────────────────────────

// ReportData is passed into the HTML template.
type ReportData struct {
	GeneratedAt    string
	Meta           ReportMeta
	Summary        core.Summary
	Score          int
	Grade          string
	ScoreColor     string
	SeverityMax    int
	Findings       []*core.Finding
	CISCompliance  compliance.ComplianceSummary
	CISTopControls []cisControlRow
	// Capability Break fields
	CapabilityBreaks   []core.CapabilityBreak
	CompoundBreaks     []core.CompoundBreak
	FindingCBMap       map[string][]string // FindingID (string) → []CB IDs
	FindingCompoundMap map[string][]string // FindingID (string) → []Compound IDs
	BlastMode          string
}

// cisControlRow holds a deduplicated control for the CIS section table.
type cisControlRow struct {
	Control string
	Level   int
	Profile string
	Title   string
	Count   int
}

// WriteHTML writes a dark-theme interactive HTML report.
func WriteHTML(findings []*core.Finding, cbResult core.CBAnalysisResult, meta ReportMeta, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	summary := core.BuildSummary(findings)
	score, grade := summary.SecurityScore()

	severityMax := max(summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info, 1)

	cisCS := compliance.BuildComplianceSummary(findings)
	cisControls := buildCISTopControls(findings)

	data := ReportData{
		GeneratedAt:        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Meta:               meta,
		CISCompliance:      cisCS,
		CISTopControls:     cisControls,
		Summary:            summary,
		Score:              score,
		Grade:              grade,
		ScoreColor:         gradeHex(grade),
		SeverityMax:        severityMax,
		Findings:           findings,
		CapabilityBreaks:   cbResult.CapabilityBreaks,
		CompoundBreaks:     cbResult.CompoundBreaks,
		FindingCBMap:       cbResult.FindingCBMap,
		FindingCompoundMap: cbResult.FindingCompoundMap,
		BlastMode:          string(cbResult.BlastMode),
	}

	tmpl, err := template.New("report").Funcs(templateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func gradeHex(grade string) string {
	switch grade {
	case "A":
		return "#22c55e"
	case "B":
		return "#86efac"
	case "C":
		return "#eab308"
	case "D":
		return "#f97316"
	default:
		return "#ef4444"
	}
}

func buildCISTopControls(findings []*core.Finding) []cisControlRow {
	rows := make(map[string]*cisControlRow)
	for _, f := range findings {
		if f.CISControl == "" {
			continue
		}
		if r, ok := rows[f.CISControl]; ok {
			r.Count++
		} else {
			rows[f.CISControl] = &cisControlRow{
				Control: f.CISControl,
				Level:   f.CISLevel,
				Profile: f.CISProfile,
				Title:   f.CISTitle,
				Count:   1,
			}
		}
	}
	out := make([]cisControlRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Control < out[j].Control
	})
	return out
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"severityClass": func(s core.Severity) string {
			return strings.ToLower(string(s))
		},
		"severityIcon": func(s core.Severity) string {
			switch s {
			case core.SeverityCritical:
				return "🔴"
			case core.SeverityHigh:
				return "🟠"
			case core.SeverityMedium:
				return "🟡"
			case core.SeverityLow:
				return "🔵"
			default:
				return "⚪"
			}
		},
		"pct": func(count, maxCount int) int {
			if maxCount == 0 {
				return 0
			}
			r := count * 100 / maxCount
			if r == 0 && count > 0 {
				return 2
			}
			return r
		},
		"add":   func(a, b int) int { return a + b },
		"lower": strings.ToLower,
		"formatDuration": func(ms int64) string {
			if ms < 1000 {
				return fmt.Sprintf("%dms", ms)
			}
			return fmt.Sprintf("%.1fs", float64(ms)/1000)
		},
		// strID converts a Finding.FindingID int to string for map lookup in templates.
		"strID": func(id int) string { return fmt.Sprintf("%d", id) },
		"cbStatusClass": func(s core.CBStatus) string {
			switch s {
			case core.CBStatusBroken:
				return "status-broken"
			case core.CBStatusDegraded:
				return "status-degraded"
			default:
				return "status-weak"
			}
		},
		"cbExploitClass": func(e core.CBExploitability) string {
			switch e {
			case core.CBExploitImmediate:
				return "exploit-immediate"
			case core.CBExploitHigh:
				return "exploit-high"
			case core.CBExploitMedium:
				return "exploit-medium"
			default:
				return "exploit-low"
			}
		},
		"blastLevelClass": func(l string) string {
			switch l {
			case "CRITICAL":
				return "blast-critical"
			case "HIGH":
				return "blast-high"
			case "MEDIUM":
				return "blast-medium"
			default:
				return "blast-low"
			}
		},
		"fixPriorityClass": func(p string) string {
			switch p {
			case "P0":
				return "priority-p0"
			case "P1":
				return "priority-p1"
			case "P2":
				return "priority-p2"
			default:
				return "priority-p3"
			}
		},
		// safeJS marks a string as safe JavaScript so the template engine
		// does not HTML-escape it inside <script> blocks.
		"safeJS": func(s string) template.JS { return template.JS(s) },
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>k8scan — Security Report{{if .Meta.ClusterContext}} · {{.Meta.ClusterContext}}{{end}}</title>
<style>
:root {
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#3b82f6; --info:#6b7280;
  --bg:#0f172a; --surface:#1e293b; --surface2:#263548; --border:#334155;
  --text:#e2e8f0; --muted:#94a3b8; --green:#22c55e;
  --nav-h:58px; --tabnav-h:44px; --toolbar-h:54px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:15px;line-height:1.5}

/* ── Nav ─────────────────────────────────────────────────── */
nav{
  position:sticky;top:0;z-index:200;height:var(--nav-h);
  background:rgba(15,23,42,.96);backdrop-filter:blur(10px);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:1rem;padding:0 1.5rem;
}
.nav-brand{font-size:1.15rem;font-weight:900;letter-spacing:-.02em;color:#ffffff}
.nav-brand span{color:#10b981}
.nav-cluster{flex:1;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.nav-chip{background:rgba(255,255,255,.07);border:1px solid var(--border);border-radius:20px;padding:.2rem .6rem;font-size:.75rem;color:var(--muted)}
.nav-sep{color:var(--border);font-size:.9rem}
.grade-badge{
  padding:.35rem .9rem;border-radius:8px;font-weight:800;font-size:1rem;
  letter-spacing:.02em;flex-shrink:0;
}
.grade-A{background:rgba(34,197,94,.15);color:#22c55e}
.grade-B{background:rgba(134,239,172,.15);color:#86efac}
.grade-C{background:rgba(234,179,8,.15);color:#eab308}
.grade-D{background:rgba(249,115,22,.15);color:#f97316}
.grade-F{background:rgba(239,68,68,.15);color:#ef4444}

/* ── Toolbar ─────────────────────────────────────────────── */
.toolbar{
  position:sticky;top:calc(var(--nav-h) + var(--tabnav-h));z-index:198;height:var(--toolbar-h);
  background:rgba(15,23,42,.96);backdrop-filter:blur(10px);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:.75rem;padding:0 1.5rem;flex-wrap:wrap;
}
.search-wrap{position:relative;flex-shrink:0}
.search-wrap input{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:.4rem .75rem .4rem 2rem;font-size:.85rem;width:220px;
  outline:none;transition:border-color .2s;
}
.search-wrap input:focus{border-color:var(--medium)}
.search-icon{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);color:var(--muted);font-size:.85rem;pointer-events:none}
.search-hint{position:absolute;right:.6rem;top:50%;transform:translateY(-50%);color:var(--border);font-size:.7rem;pointer-events:none}
.pills{display:flex;gap:.35rem;flex-wrap:wrap;flex:1}
.pill{
  display:inline-flex;align-items:center;gap:.3rem;
  padding:.25rem .65rem;border:1px solid var(--border);border-radius:20px;
  background:transparent;color:var(--muted);font-size:.78rem;cursor:pointer;
  transition:all .15s;white-space:nowrap;
}
.pill:hover{border-color:var(--muted);color:var(--text)}
.pill.active{font-weight:600;background:rgba(255,255,255,.08);color:var(--text);border-color:rgba(255,255,255,.25)}
.pill.p-critical.active{background:rgba(239,68,68,.12);color:var(--critical);border-color:rgba(239,68,68,.4)}
.pill.p-high.active{background:rgba(249,115,22,.12);color:var(--high);border-color:rgba(249,115,22,.4)}
.pill.p-medium.active{background:rgba(234,179,8,.12);color:var(--medium);border-color:rgba(234,179,8,.4)}
.pill.p-low.active{background:rgba(59,130,246,.12);color:var(--low);border-color:rgba(59,130,246,.4)}
.pill.p-info.active{background:rgba(107,114,128,.12);color:var(--info);border-color:rgba(107,114,128,.4)}
.toolbar-actions{display:flex;gap:.35rem;margin-left:auto;flex-shrink:0}
.btn-sm{
  background:transparent;border:1px solid var(--border);border-radius:6px;
  color:var(--muted);padding:.3rem .7rem;font-size:.78rem;cursor:pointer;
  transition:all .15s;white-space:nowrap;
}
.btn-sm:hover{border-color:var(--muted);color:var(--text)}

/* ── Main layout ─────────────────────────────────────────── */
main{max-width:1200px;margin:0 auto;padding:1.5rem}

/* ── Overview ────────────────────────────────────────────── */
.overview{
  display:grid;grid-template-columns:auto 1fr auto;gap:2rem;align-items:center;
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:1.75rem 2rem;margin-bottom:1.5rem;
}
@media(max-width:860px){.overview{grid-template-columns:1fr;gap:1.5rem}}

/* Score ring */
.score-wrap{display:flex;flex-direction:column;align-items:center;gap:.5rem}
.score-ring{
  width:128px;height:128px;border-radius:50%;padding:10px;
  background:conic-gradient(var(--ring) 0% calc(var(--pct) * 1%), var(--surface2) calc(var(--pct) * 1%) 100%);
}
.score-hole{
  width:100%;height:100%;border-radius:50%;
  background:var(--bg);display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:0;
}
.score-grade{font-size:2rem;font-weight:800;line-height:1}
.score-num{font-size:.9rem;color:var(--muted);margin-top:.15rem}
.score-label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}

/* Severity bars */
.sev-bars{display:flex;flex-direction:column;gap:.6rem;min-width:240px}
.sev-row{display:flex;align-items:center;gap:.75rem}
.sev-name{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;width:58px;flex-shrink:0;text-align:right}
.sev-name.critical{color:var(--critical)}
.sev-name.high{color:var(--high)}
.sev-name.medium{color:var(--medium)}
.sev-name.low{color:var(--low)}
.sev-name.info{color:var(--info)}
.bar-track{flex:1;height:8px;background:rgba(255,255,255,.06);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .9s cubic-bezier(.4,0,.2,1)}
.bar-fill.critical{background:linear-gradient(90deg,#dc2626,#ef4444)}
.bar-fill.high{background:linear-gradient(90deg,#c2410c,#f97316)}
.bar-fill.medium{background:linear-gradient(90deg,#a16207,#eab308)}
.bar-fill.low{background:linear-gradient(90deg,#1d4ed8,#3b82f6)}
.bar-fill.info{background:linear-gradient(90deg,#374151,#6b7280)}
.bar-count{font-size:.8rem;font-weight:600;width:28px;text-align:right;flex-shrink:0}

/* Summary chips */
.chips{display:flex;flex-direction:column;gap:.5rem;align-items:flex-end}
@media(max-width:860px){.chips{flex-direction:row;align-items:flex-start;flex-wrap:wrap}}
.chip{
  background:var(--surface2);border:1px solid var(--border);border-radius:8px;
  padding:.5rem .9rem;text-align:center;min-width:80px;
}
.chip-n{font-size:1.6rem;font-weight:700;line-height:1}
.chip-l{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.1rem}
.chip-n.critical{color:var(--critical)}
.chip-n.high{color:var(--high)}
.chip-n.medium{color:var(--medium)}
.chip-n.low{color:var(--low)}
.chip-n.info{color:var(--info)}

/* ── Findings header ─────────────────────────────────────── */
.findings-hdr{
  display:flex;justify-content:space-between;align-items:center;
  padding:.25rem 0 .75rem;color:var(--muted);font-size:.85rem;
}
.findings-hdr strong{color:var(--text)}
.empty-state{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:3rem;text-align:center;color:var(--muted);
}
.empty-state .icon{font-size:2.5rem;margin-bottom:.75rem}
.no-results{display:none;text-align:center;padding:2rem;color:var(--muted)}

/* ── Attack chain cards ───────────────────────────────────── */
.finding[data-cat="attack-chain"]{
  background:rgba(239,68,68,.04);
  border:1px solid rgba(239,68,68,.35);
  border-left:4px solid var(--critical);
  border-radius:0 10px 10px 0;
  margin-bottom:.85rem;overflow:hidden;
  box-shadow:0 0 0 1px rgba(239,68,68,.12),0 2px 16px rgba(239,68,68,.08);
  position:relative;
}
.finding[data-cat="attack-chain"]::before{
  content:"⛓ ATTACK CHAIN";
  position:absolute;top:0;right:0;
  background:rgba(239,68,68,.85);color:#fff;
  font-size:.65rem;font-weight:800;letter-spacing:.08em;
  padding:.2rem .6rem;border-radius:0 8px 0 6px;
}
.finding[data-cat="attack-chain"]:hover{box-shadow:0 0 0 1px rgba(239,68,68,.3),0 4px 20px rgba(239,68,68,.18)}

/* ── Finding cards ───────────────────────────────────────── */
.finding{
  background:var(--surface);border:1px solid var(--border);
  border-left-width:4px;border-radius:0 10px 10px 0;
  margin-bottom:.65rem;overflow:hidden;transition:border-color .15s,box-shadow .15s;
}
.finding:hover{box-shadow:0 2px 12px rgba(0,0,0,.3)}
.finding[data-sev="CRITICAL"]{border-left-color:var(--critical)}
.finding[data-sev="HIGH"]{border-left-color:var(--high)}
.finding[data-sev="MEDIUM"]{border-left-color:var(--medium)}
.finding[data-sev="LOW"]{border-left-color:var(--low)}
.finding[data-sev="INFO"]{border-left-color:var(--info)}

.finding-header{
  display:flex;align-items:center;gap:.75rem;padding:.85rem 1.1rem;
  cursor:pointer;user-select:none;
}
.finding-header:hover{background:rgba(255,255,255,.025)}

.badge{
  display:inline-flex;align-items:center;gap:.25rem;
  padding:.2rem .55rem;border-radius:20px;font-size:.68rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;flex-shrink:0;
}
.badge.critical{background:rgba(239,68,68,.15);color:var(--critical)}
.badge.high{background:rgba(249,115,22,.15);color:var(--high)}
.badge.medium{background:rgba(234,179,8,.15);color:var(--medium)}
.badge.low{background:rgba(59,130,246,.15);color:var(--low)}
.badge.info{background:rgba(107,114,128,.15);color:var(--info)}

.finding-info{flex:1;min-width:0}
.finding-title{font-weight:600;font-size:.95rem;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.finding-meta{font-size:.78rem;color:var(--muted);margin-top:.1rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cat-chip{
  display:inline-block;background:rgba(255,255,255,.07);border-radius:4px;
  padding:.05rem .35rem;font-size:.7rem;color:var(--muted);margin-left:.35rem;
}
.chevron{color:var(--muted);font-size:1.1rem;transition:transform .2s;flex-shrink:0;font-style:normal;line-height:1}
.chevron.open{transform:rotate(90deg)}

/* ── Finding body ────────────────────────────────────────── */
.finding-body{display:none;padding:0 1.25rem 1rem;border-top:1px solid var(--border)}
.finding-body.open{display:block}
.description{padding:.85rem 0;color:var(--text);font-size:.9rem;line-height:1.65}

/* Collapsible sub-sections */
.detail-section{border-top:1px solid rgba(255,255,255,.06)}
.section-toggle{
  display:flex;align-items:center;gap:.5rem;width:100%;
  padding:.55rem 0;cursor:pointer;user-select:none;
  background:none;border:none;color:var(--muted);text-align:left;
}
.section-toggle:hover{color:var(--text)}
.section-toggle .toggle-arrow{
  font-size:.75rem;transition:transform .18s;flex-shrink:0;color:var(--border);
}
.section-toggle.open .toggle-arrow{transform:rotate(90deg);color:var(--muted)}
.section-toggle .toggle-label{
  font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
}
.section-content{display:none;padding-bottom:.85rem}
.section-content.open{display:block}

.impact-text{font-size:.875rem;color:var(--text);line-height:1.6}
.remediation-box{
  background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.18);
  border-radius:8px;padding:.7rem 1rem;font-size:.875rem;color:#86efac;line-height:1.6;
}
.bullet-list,.steps-list{
  padding-left:1.25rem;display:flex;flex-direction:column;gap:.25rem;
}
.bullet-list li,.steps-list li{font-size:.875rem;color:var(--text);padding:.25rem 0;line-height:1.55}
.steps-list{counter-reset:steps;list-style:none;padding-left:0}
.steps-list li{
  display:flex;align-items:flex-start;gap:.65rem;
  border-bottom:1px solid rgba(255,255,255,.04);padding:.35rem 0;
}
.steps-list li::before{
  counter-increment:steps;content:counter(steps);
  flex-shrink:0;width:20px;height:20px;border-radius:50%;
  background:rgba(234,179,8,.15);color:var(--medium);
  font-size:.7rem;font-weight:700;display:grid;place-items:center;margin-top:.15rem;
}

/* ── Code blocks ─────────────────────────────────────────── */
.code-block{position:relative;margin-top:.5rem}
.copy-btn{
  position:absolute;top:.5rem;right:.5rem;z-index:1;
  background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.15);
  color:var(--muted);padding:.22rem .65rem;border-radius:5px;
  font-size:.72rem;cursor:pointer;transition:all .15s;
}
.copy-btn:hover{background:rgba(255,255,255,.12);color:var(--text)}
.copy-btn.copied{background:rgba(34,197,94,.12);color:var(--green);border-color:rgba(34,197,94,.3)}
pre{
  background:#070d1a;border:1px solid var(--border);border-radius:8px;
  padding:1rem 1rem 1rem 1rem;padding-top:2.4rem;
  font-size:.8rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
  color:#a3e635;line-height:1.65;
}

/* ── CIS Compliance section ──────────────────────────────── */
.cis-section{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:1.5rem;margin-bottom:1.5rem;
}
.cis-section-title{
  font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);margin-bottom:1rem;
}
.cis-stats{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.25rem}
.cis-stat{
  background:var(--surface2);border:1px solid var(--border);border-radius:8px;
  padding:.6rem 1rem;text-align:center;min-width:90px;
}
.cis-stat-n{font-size:1.4rem;font-weight:700;color:#10b981}
.cis-stat-l{font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.1rem}
.cis-table{width:100%;border-collapse:collapse;font-size:.82rem}
.cis-table th{text-align:left;color:var(--muted);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;padding:.45rem .75rem;border-bottom:1px solid var(--border)}
.cis-table td{padding:.45rem .75rem;border-bottom:1px solid rgba(255,255,255,.04);color:var(--text)}
.cis-table tr:last-child td{border-bottom:none}
.cis-table tr:hover td{background:rgba(255,255,255,.025)}
.cis-ctrl{font-family:monospace;color:#10b981;font-weight:600}
.cis-lvl{background:rgba(16,185,129,.12);color:#10b981;border-radius:4px;padding:.1rem .35rem;font-size:.7rem;font-weight:700}
.cis-prof{color:var(--muted)}
.cis-title-col{color:var(--muted);font-size:.8rem}
.cis-count{text-align:right;font-weight:600}
.cis-badge{
  display:inline-block;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.25);
  border-radius:4px;padding:.05rem .4rem;font-size:.68rem;color:#10b981;
  font-family:monospace;margin-left:.4rem;white-space:nowrap;
}

/* ── Footer ──────────────────────────────────────────────── */
footer{
  border-top:1px solid var(--border);margin:2rem 0 0;padding:1rem 1.5rem;
  display:flex;gap:1.5rem;flex-wrap:wrap;
  color:var(--muted);font-size:.78rem;max-width:1200px;margin-left:auto;margin-right:auto;
}
footer span{display:flex;align-items:center;gap:.35rem}

/* ── Tab navigation ──────────────────────────────────────── */
.tab-nav{
  position:sticky;top:var(--nav-h);z-index:199;height:var(--tabnav-h);
  background:rgba(15,23,42,.97);backdrop-filter:blur(10px);
  border-bottom:1px solid var(--border);
  display:flex;align-items:stretch;padding:0 1.5rem;gap:0;
}
.tab-btn{
  background:transparent;border:none;color:var(--muted);
  padding:0 1.2rem;cursor:pointer;font-size:.84rem;font-weight:500;
  border-bottom:2px solid transparent;transition:all .15s;
  display:flex;align-items:center;gap:.5rem;white-space:nowrap;
  font-family:inherit;
}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--text);border-bottom-color:#10b981}
.tab-count{
  background:rgba(255,255,255,.1);border-radius:10px;
  padding:.1rem .45rem;font-size:.72rem;font-weight:700;
}
.tab-btn.active .tab-count{background:rgba(16,185,129,.2);color:#34d399}
.tab-count.cb-count{background:rgba(239,68,68,.2);color:#fca5a5}
.tab-count.compound-count{background:rgba(168,85,247,.2);color:#d8b4fe}
.tab-pane{display:none}
.tab-pane.active{display:block}

/* ── Cross-reference badges (Finding → CB → Compound) ────── */
.xref-badges{display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.4rem}
.xref-cb{
  display:inline-flex;align-items:center;gap:.2rem;
  background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);
  color:#fca5a5;border-radius:8px;padding:.15rem .5rem;font-size:.7rem;
  font-weight:600;cursor:pointer;transition:all .15s;
}
.xref-cb:hover{background:rgba(239,68,68,.22);border-color:rgba(239,68,68,.6)}
.xref-compound{
  display:inline-flex;align-items:center;gap:.2rem;
  background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.3);
  color:#d8b4fe;border-radius:8px;padding:.15rem .5rem;font-size:.7rem;
  font-weight:600;cursor:pointer;transition:all .15s;
}
.xref-compound:hover{background:rgba(168,85,247,.22);border-color:rgba(168,85,247,.6)}

/* ── Capability Break cards ──────────────────────────────── */
.cb-section-title{
  font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);margin:1.5rem 0 .75rem;
}
.cb-card{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:1.5rem;margin-bottom:1rem;transition:border-color .2s;
}
.cb-card:hover{border-color:rgba(255,255,255,.12)}
.cb-header{display:flex;align-items:flex-start;gap:1rem;margin-bottom:1rem}
.cb-id-badge{
  background:rgba(255,255,255,.07);border:1px solid var(--border);
  border-radius:8px;padding:.4rem .75rem;font-size:.78rem;font-weight:800;
  color:var(--text);white-space:nowrap;flex-shrink:0;letter-spacing:.04em;
}
.cb-title-area{flex:1;min-width:0}
.cb-name{display:block;font-size:1rem;font-weight:700;color:var(--text);margin-bottom:.2rem}
.cb-boundary{display:block;font-size:.78rem;color:var(--muted)}
.cb-status{
  padding:.35rem .85rem;border-radius:8px;font-size:.75rem;font-weight:700;
  letter-spacing:.04em;flex-shrink:0;
}
.status-broken{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.status-degraded{background:rgba(249,115,22,.15);color:#f97316;border:1px solid rgba(249,115,22,.3)}
.status-weak{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.3)}

.cb-meta-row{
  display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;
  padding:.75rem 1rem;background:var(--surface2);border-radius:8px;
}
.cb-meta-item{display:flex;flex-direction:column;gap:.25rem;min-width:100px}
.cb-meta-label{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.cb-confidence-bar{
  height:6px;background:rgba(255,255,255,.08);border-radius:3px;width:120px;
}
.cb-confidence-fill{height:100%;background:#10b981;border-radius:3px;transition:width .4s}
.cb-meta-val{font-size:.82rem;font-weight:700;color:var(--text)}

.cb-exploit{padding:.2rem .55rem;border-radius:6px;font-size:.72rem;font-weight:700;width:fit-content}
.exploit-immediate{background:rgba(239,68,68,.15);color:#ef4444}
.exploit-high{background:rgba(249,115,22,.15);color:#f97316}
.exploit-medium{background:rgba(234,179,8,.15);color:#eab308}
.exploit-low{background:rgba(59,130,246,.15);color:#60a5fa}

.cb-blast{padding:.2rem .55rem;border-radius:6px;font-size:.72rem;font-weight:700;width:fit-content}
.blast-critical{background:rgba(239,68,68,.15);color:#ef4444}
.blast-high{background:rgba(249,115,22,.15);color:#f97316}
.blast-medium{background:rgba(234,179,8,.15);color:#eab308}
.blast-low{background:rgba(59,130,246,.15);color:#60a5fa}

.cb-priority{padding:.2rem .55rem;border-radius:6px;font-size:.72rem;font-weight:800;width:fit-content}
.priority-p0{background:rgba(239,68,68,.2);color:#ef4444}
.priority-p1{background:rgba(249,115,22,.15);color:#f97316}
.priority-p2{background:rgba(234,179,8,.12);color:#eab308}
.priority-p3{background:rgba(107,114,128,.12);color:var(--muted)}

/* MITRE badges with hover tooltip */
.cb-mitre-row{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:.75rem}
.mitre-badge{
  position:relative;display:inline-flex;align-items:center;
  background:rgba(99,102,241,.12);border:1px solid rgba(99,102,241,.3);
  color:#a5b4fc;border-radius:8px;padding:.2rem .55rem;
  font-size:.7rem;font-weight:700;cursor:default;
}
.mitre-badge:hover .mitre-tooltip{display:block}
.mitre-tooltip{
  display:none;position:absolute;bottom:calc(100% + 6px);left:0;
  background:#1e293b;border:1px solid var(--border);border-radius:8px;
  padding:.5rem .75rem;font-size:.75rem;color:var(--text);
  white-space:nowrap;z-index:300;line-height:1.6;min-width:180px;
  box-shadow:0 8px 24px rgba(0,0,0,.4);
}

/* CB section (collapsible) */
.cb-section{border-top:1px solid rgba(255,255,255,.04);padding-top:.5rem;margin-top:.5rem}
.cb-attack-path{display:flex;flex-direction:column;gap:.35rem;padding:.5rem 0}
.path-step{
  font-size:.82rem;color:var(--text);padding:.3rem .6rem;
  background:rgba(255,255,255,.03);border-radius:5px;border-left:2px solid #10b981;
}
.path-step:first-child{border-left-color:#ef4444}
.path-step:last-child{border-left-color:#a78bfa}

.cb-evidence-list{list-style:none;display:flex;flex-direction:column;gap:.35rem}
.cb-evidence-item{
  display:flex;align-items:center;gap:.5rem;font-size:.8rem;
  padding:.3rem .5rem;background:rgba(255,255,255,.03);border-radius:5px;
}
.ev-sev{
  padding:.1rem .4rem;border-radius:4px;font-size:.65rem;font-weight:700;flex-shrink:0;
}
.ev-critical{background:rgba(239,68,68,.15);color:#ef4444}
.ev-high{background:rgba(249,115,22,.15);color:#f97316}
.ev-medium{background:rgba(234,179,8,.12);color:#eab308}
.ev-low{background:rgba(59,130,246,.12);color:#60a5fa}
.ev-info{background:rgba(107,114,128,.12);color:var(--muted)}
.ev-title{flex:1;color:var(--text)}
.ev-resource{font-size:.72rem;color:var(--muted);white-space:nowrap}

.blast-grid{
  display:flex;gap:.75rem;flex-wrap:wrap;padding:.5rem 0;
}
.blast-item{
  background:var(--surface2);border-radius:8px;padding:.6rem 1rem;
  text-align:center;min-width:70px;
}
.blast-n{font-size:1.2rem;font-weight:800;color:var(--text)}
.blast-l{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}

/* ── Compound Break cards ─────────────────────────────────── */
.compound-card{
  background:var(--surface);border:1px solid rgba(168,85,247,.2);border-radius:12px;
  padding:1.5rem;margin-bottom:1rem;
}
.compound-card:hover{border-color:rgba(168,85,247,.4)}
.compound-header{display:flex;align-items:flex-start;gap:1rem;margin-bottom:1rem}
.compound-id{
  background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.3);
  color:#d8b4fe;border-radius:8px;padding:.4rem .75rem;
  font-size:.78rem;font-weight:800;white-space:nowrap;flex-shrink:0;
}
.compound-name{font-size:1rem;font-weight:700;color:var(--text);flex:1}
.compound-confidence{
  font-size:.78rem;font-weight:700;color:#a78bfa;white-space:nowrap;flex-shrink:0;
}
.compound-chain{display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.75rem}
.compound-cb-ref{
  background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);
  color:#fca5a5;border-radius:6px;padding:.2rem .55rem;
  font-size:.72rem;font-weight:700;cursor:pointer;transition:all .15s;
}
.compound-cb-ref:hover{background:rgba(239,68,68,.2);border-color:rgba(239,68,68,.5)}
.chain-arrow{color:var(--muted);font-size:.85rem}
.compound-narrative{display:flex;flex-direction:column;gap:.3rem;margin-bottom:.75rem}
.narrative-step{
  font-size:.82rem;color:var(--text);padding:.3rem .6rem;
  background:rgba(168,85,247,.04);border-radius:5px;border-left:2px solid rgba(168,85,247,.4);
}
.narrative-step:first-child{border-left-color:#ef4444}
.narrative-step:last-child{border-left-color:#a78bfa;font-weight:600;color:#d8b4fe}
.compound-impact{
  font-size:.85rem;color:#fde68a;background:rgba(251,191,36,.07);
  border:1px solid rgba(251,191,36,.15);border-radius:6px;padding:.6rem .85rem;
  margin-bottom:.75rem;
}
.compound-remediation{
  font-size:.82rem;color:var(--muted);background:var(--surface2);
  border-radius:6px;padding:.6rem .85rem;margin-top:.75rem;line-height:1.6;
}
.compound-cb-section{border-top:1px solid rgba(255,255,255,.04);padding-top:.75rem;margin-top:.75rem}
.compound-cb-title{font-size:.8rem;font-weight:700;color:#d8b4fe;margin-bottom:.5rem}

/* ── Empty CB / Compound states ──────────────────────────── */
.cb-empty{
  text-align:center;padding:4rem 2rem;color:var(--muted);
}
.cb-empty .icon{font-size:2.5rem;margin-bottom:.75rem}
.cb-empty p{font-size:.95rem}

/* ── Validation Proof ────────────────────────────────────── */
.proof-verdict{
  font-size:.82rem;font-weight:700;padding:.6rem .9rem;border-radius:7px;margin-bottom:.75rem;
  background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#fca5a5;
}
.proof-signals-table{
  width:100%;border-collapse:collapse;font-size:.78rem;margin-bottom:.65rem;
}
.proof-signals-table th{
  text-align:left;color:var(--muted);font-size:.66rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;padding:.35rem .5rem;
  border-bottom:1px solid var(--border);
}
.proof-signals-table td{
  padding:.35rem .5rem;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top;
}
.proof-signals-table tr:last-child td{border-bottom:none}
.proof-signals-table tr:hover td{background:rgba(255,255,255,.02)}
.proof-significance{color:var(--muted);font-size:.76rem;line-height:1.5}
.proof-combined{
  font-size:.82rem;color:var(--text);line-height:1.65;padding:.65rem .9rem;
  background:rgba(255,255,255,.03);border-left:3px solid rgba(99,102,241,.4);
  border-radius:0 6px 6px 0;
}

/* ── Attack graph (DOM/SVG) ──────────────────────────────── */
.graph-flow-wrap{
  margin-top:.65rem;border-radius:8px;
  border:1px solid rgba(255,255,255,.06);
  background:#070d1a;overflow:visible;
}
.attack-graph-flow{
  position:relative;width:100%;min-height:72px;
}
</style>
</head>
<body>

<!-- Sticky nav -->
<nav>
  <div class="nav-brand">k8<span>scan</span></div>
  <div class="nav-cluster">
    {{if .Meta.ClusterContext}}<span class="nav-chip">{{.Meta.ClusterContext}}</span>{{end}}
    {{if .Meta.ClusterVersion}}<span class="nav-chip">{{.Meta.ClusterVersion}}</span>{{end}}
    {{if .Meta.NodeCount}}<span class="nav-chip">{{.Meta.NodeCount}} nodes</span>{{end}}
    {{if .Meta.NamespaceCount}}<span class="nav-chip">{{.Meta.NamespaceCount}} namespaces</span>{{end}}
  </div>
  <div class="grade-badge grade-{{.Grade}}">{{.Grade}} &nbsp;{{.Score}}/100</div>
</nav>

<!-- Tab navigation -->
<div class="tab-nav">
  <button class="tab-btn active" onclick="switchTab(this,'findings')">
    🔍 Findings <span class="tab-count">{{.Summary.Total}}</span>
  </button>
  <button class="tab-btn" onclick="switchTab(this,'capbreaks')">
    💣 Capability Breaks {{if .CapabilityBreaks}}<span class="tab-count cb-count">{{len .CapabilityBreaks}}</span>{{end}}
  </button>
  <button class="tab-btn" onclick="switchTab(this,'compounds')">
    ⛓ Compound Breaks {{if .CompoundBreaks}}<span class="tab-count compound-count">{{len .CompoundBreaks}}</span>{{end}}
  </button>
</div>

<div id="tab-findings" class="tab-pane active">

<!-- Sticky toolbar -->
<div class="toolbar">
  <div class="search-wrap">
    <span class="search-icon">⌕</span>
    <input type="search" id="search-input" placeholder="Search findings..." oninput="applyFilters()">
    <span class="search-hint">/</span>
  </div>
  <div class="pills">
    <button class="pill active" onclick="setFilter('all',this)">All <strong>{{.Summary.Total}}</strong></button>
    <button class="pill p-critical" onclick="setFilter('CRITICAL',this)">🔴 {{.Summary.Critical}}</button>
    <button class="pill p-high" onclick="setFilter('HIGH',this)">🟠 {{.Summary.High}}</button>
    <button class="pill p-medium" onclick="setFilter('MEDIUM',this)">🟡 {{.Summary.Medium}}</button>
    <button class="pill p-low" onclick="setFilter('LOW',this)">🔵 {{.Summary.Low}}</button>
    <button class="pill p-info" onclick="setFilter('INFO',this)">⚪ {{.Summary.Info}}</button>
  </div>
  <div class="toolbar-actions">
    <button class="btn-sm" onclick="expandAll()">Expand All</button>
    <button class="btn-sm" onclick="collapseAll()">Collapse All</button>
  </div>
</div>

<main>

<!-- Overview -->
<div class="overview">

  <!-- Score ring -->
  <div class="score-wrap">
    <div class="score-ring" style="--pct:{{.Score}};--ring:{{.ScoreColor}}">
      <div class="score-hole">
        <span class="score-grade grade-{{.Grade}}">{{.Grade}}</span>
        <span class="score-num">{{.Score}}/100</span>
      </div>
    </div>
    <div class="score-label">Security Score</div>
  </div>

  <!-- Severity bars -->
  <div class="sev-bars">
    <div class="sev-row">
      <span class="sev-name critical">Critical</span>
      <div class="bar-track"><div class="bar-fill critical" style="width:{{pct .Summary.Critical .SeverityMax}}%"></div></div>
      <span class="bar-count">{{.Summary.Critical}}</span>
    </div>
    <div class="sev-row">
      <span class="sev-name high">High</span>
      <div class="bar-track"><div class="bar-fill high" style="width:{{pct .Summary.High .SeverityMax}}%"></div></div>
      <span class="bar-count">{{.Summary.High}}</span>
    </div>
    <div class="sev-row">
      <span class="sev-name medium">Medium</span>
      <div class="bar-track"><div class="bar-fill medium" style="width:{{pct .Summary.Medium .SeverityMax}}%"></div></div>
      <span class="bar-count">{{.Summary.Medium}}</span>
    </div>
    <div class="sev-row">
      <span class="sev-name low">Low</span>
      <div class="bar-track"><div class="bar-fill low" style="width:{{pct .Summary.Low .SeverityMax}}%"></div></div>
      <span class="bar-count">{{.Summary.Low}}</span>
    </div>
    <div class="sev-row">
      <span class="sev-name info">Info</span>
      <div class="bar-track"><div class="bar-fill info" style="width:{{pct .Summary.Info .SeverityMax}}%"></div></div>
      <span class="bar-count">{{.Summary.Info}}</span>
    </div>
  </div>

  <!-- Summary chips -->
  <div class="chips">
    <div class="chip"><div class="chip-n">{{.Summary.Total}}</div><div class="chip-l">Total</div></div>
    <div class="chip"><div class="chip-n critical">{{.Summary.Critical}}</div><div class="chip-l">Critical</div></div>
    <div class="chip"><div class="chip-n high">{{.Summary.High}}</div><div class="chip-l">High</div></div>
    <div class="chip"><div class="chip-n medium">{{.Summary.Medium}}</div><div class="chip-l">Medium</div></div>
  </div>

</div>

<!-- CIS Compliance -->
{{if .CISCompliance.MappedFindings}}
<div class="cis-section">
  <div class="cis-section-title">CIS Kubernetes Benchmark v1.8 — Compliance Overview</div>
  <div class="cis-stats">
    <div class="cis-stat"><div class="cis-stat-n">{{.CISCompliance.MappedFindings}}</div><div class="cis-stat-l">CIS Findings</div></div>
    <div class="cis-stat"><div class="cis-stat-n">{{.CISCompliance.UniqueControlsViolated}}</div><div class="cis-stat-l">Controls Violated</div></div>
    <div class="cis-stat"><div class="cis-stat-n">{{.CISCompliance.Level1Findings}}</div><div class="cis-stat-l">Level 1</div></div>
    <div class="cis-stat"><div class="cis-stat-n">{{.CISCompliance.Level2Findings}}</div><div class="cis-stat-l">Level 2</div></div>
  </div>
  {{if .CISTopControls}}
  <table class="cis-table">
    <thead><tr><th>Control</th><th>Level</th><th>Profile</th><th>Title</th><th style="text-align:right">Findings</th></tr></thead>
    <tbody>
    {{range .CISTopControls}}
    <tr>
      <td class="cis-ctrl">{{.Control}}</td>
      <td><span class="cis-lvl">L{{.Level}}</span></td>
      <td class="cis-prof">{{.Profile}}</td>
      <td class="cis-title-col">{{.Title}}</td>
      <td class="cis-count">{{.Count}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</div>
{{end}}

<!-- Findings -->
{{if eq .Summary.Total 0}}
<div class="empty-state">
  <div class="icon">✅</div>
  <div style="font-size:1.1rem;font-weight:600;margin-bottom:.5rem">No security issues found</div>
  <div style="color:var(--muted);font-size:.9rem">Your cluster passed all checks.</div>
</div>
{{else}}

<div class="findings-hdr">
  <span><strong id="findings-count">{{.Summary.Total}}</strong> findings</span>
  <span>Generated {{.GeneratedAt}}{{if .Meta.ScanDurationMS}} · took {{formatDuration .Meta.ScanDurationMS}}{{end}}</span>
</div>

<div id="no-results" class="no-results">No findings match the current filter.</div>

{{range .Findings}}
<article class="finding" data-sev="{{.Severity}}" data-cat="{{.Category}}">
  <div class="finding-header" onclick="toggleCard(this)">
    <span class="badge {{severityClass .Severity}}">{{severityIcon .Severity}} {{.Severity}}</span>
    <div class="finding-info">
      <span class="finding-title">{{.Title}}{{if .CISControl}}<span class="cis-badge">CIS {{.CISControl}} · L{{.CISLevel}}</span>{{end}}</span>
      <span class="finding-meta">
        {{.ResourceType}}/{{.ResourceName}}{{if .Namespace}} · {{.Namespace}}{{end}}
        {{if .Category}}<span class="cat-chip">{{.Category}}</span>{{end}}
      </span>
      {{$fid := strID .FindingID}}
      {{$cbids := index $.FindingCBMap $fid}}
      {{$compids := index $.FindingCompoundMap $fid}}
      {{if or $cbids $compids}}
      <div class="xref-badges">
        {{range $cbids}}<span class="xref-cb" onclick="navToCB('{{.}}')">⚡ {{.}}</span>{{end}}
        {{range $compids}}<span class="xref-compound" onclick="navToCompound('{{.}}')">⛓ {{.}}</span>{{end}}
      </div>
      {{end}}
    </div>
    <i class="chevron">›</i>
  </div>
  <div class="finding-body">
    {{if .Description}}<p class="description">{{.Description}}</p>{{end}}

    {{if .Impact}}
    <div class="detail-section">
      <button class="section-toggle" onclick="toggleSection(this)">
        <span class="toggle-arrow">›</span>
        <span class="toggle-label">Impact</span>
      </button>
      <div class="section-content">
        <p class="impact-text">{{.Impact}}</p>
      </div>
    </div>
    {{end}}

    {{if .Remediation}}
    <div class="detail-section">
      <button class="section-toggle" onclick="toggleSection(this)">
        <span class="toggle-arrow">›</span>
        <span class="toggle-label">Remediation</span>
      </button>
      <div class="section-content">
        <div class="remediation-box">{{.Remediation}}</div>
      </div>
    </div>
    {{end}}

    {{if .Exploitation}}
    <div class="detail-section">
      <button class="section-toggle" onclick="toggleSection(this)">
        <span class="toggle-arrow">›</span>
        <span class="toggle-label">Exploitation Vectors</span>
      </button>
      <div class="section-content">
        <ul class="bullet-list">{{range .Exploitation}}<li>{{.}}</li>{{end}}</ul>
      </div>
    </div>
    {{end}}

    {{if .AttackFlow}}
    <div class="detail-section">
      <button class="section-toggle" onclick="toggleSection(this)">
        <span class="toggle-arrow">›</span>
        <span class="toggle-label">Attack Flow</span>
      </button>
      <div class="section-content">
        <ol class="steps-list">{{range .AttackFlow}}<li>{{.}}</li>{{end}}</ol>
      </div>
    </div>
    {{end}}

    {{if .ProofOfConcept}}
    <div class="detail-section">
      <button class="section-toggle" onclick="toggleSection(this)">
        <span class="toggle-arrow">›</span>
        <span class="toggle-label">Proof of Concept</span>
      </button>
      <div class="section-content">
        <div class="code-block">
          <button class="copy-btn" onclick="copyCode(this)">Copy</button>
          <pre><code>{{.ProofOfConcept}}</code></pre>
        </div>
      </div>
    </div>
    {{end}}
  </div>
</article>
{{end}}
{{end}}

</main>
</div><!-- /tab-findings -->

<!-- ── Capability Breaks tab ──────────────────────────────── -->
<div id="tab-capbreaks" class="tab-pane">
<main>
{{if .CapabilityBreaks}}
<div class="cb-section-title" style="margin-top:0">{{len .CapabilityBreaks}} Capability Break(s) Detected · Blast Radius Mode: {{.BlastMode}}</div>
{{range .CapabilityBreaks}}
<div class="cb-card" id="cb-{{.ID}}">
  <div class="cb-header">
    <div class="cb-id-badge">{{.ID}}</div>
    <div class="cb-title-area">
      <span class="cb-name">{{.Name}}</span>
      <span class="cb-boundary">{{.Boundary}}</span>
    </div>
    <div class="cb-status {{cbStatusClass .Status}}">{{.Status}}</div>
  </div>

  <div class="cb-meta-row">
    <div class="cb-meta-item">
      <div class="cb-meta-label">Confidence</div>
      <div class="cb-confidence-bar"><div class="cb-confidence-fill" style="width:{{.Confidence}}%"></div></div>
      <div class="cb-meta-val">{{.Confidence}}%</div>
    </div>
    <div class="cb-meta-item">
      <div class="cb-meta-label">Exploitability</div>
      <div class="cb-exploit {{cbExploitClass .Exploitability}}">{{.Exploitability}}</div>
    </div>
    <div class="cb-meta-item">
      <div class="cb-meta-label">Blast Radius</div>
      <div class="cb-blast {{blastLevelClass .BlastRadius.Level}}">{{.BlastRadius.Level}}</div>
    </div>
    <div class="cb-meta-item">
      <div class="cb-meta-label">Fix Priority</div>
      <div class="cb-priority {{fixPriorityClass .FixPriority}}">{{.FixPriority}}</div>
    </div>
  </div>

  {{if .MITRE}}
  <div class="cb-mitre-row">
    {{range .MITRE}}<span class="mitre-badge">{{.ID}}<span class="mitre-tooltip">{{.Tactic}}<br><strong>{{.Name}}</strong></span></span>{{end}}
  </div>
  {{end}}

  {{if .Evidence}}
  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Evidence ({{len .Evidence}} findings)</span>
    </button>
    <div class="section-content">
      <ul class="cb-evidence-list">
        {{range .Evidence}}
        <li class="cb-evidence-item">
          <span class="ev-sev ev-{{lower .Severity}}">{{.Severity}}</span>
          <span class="ev-title">{{.Title}}</span>
          {{if .ResourceName}}<span class="ev-resource">{{.ResourceName}}{{if .Namespace}}/{{.Namespace}}{{end}}</span>{{end}}
        </li>
        {{end}}
      </ul>
    </div>
  </div>
  {{end}}

  {{if .ValidationProof.Verdict}}
  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Validation Proof</span>
    </button>
    <div class="section-content">
      <div class="proof-verdict">{{.ValidationProof.Verdict}}</div>
      {{if .ValidationProof.Signals}}
      <table class="proof-signals-table">
        <thead><tr><th>Finding</th><th>Resource</th><th>Sev</th><th>Why This Proves Boundary Failure</th></tr></thead>
        <tbody>
        {{range .ValidationProof.Signals}}
        <tr>
          <td>{{.Title}}</td>
          <td class="ev-resource">{{.Resource}}</td>
          <td><span class="ev-sev ev-{{lower .Severity}}">{{.Severity}}</span></td>
          <td class="proof-significance">{{.Significance}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{end}}
      {{if .ValidationProof.Combined}}
      <div class="proof-combined">{{.ValidationProof.Combined}}</div>
      {{end}}
    </div>
  </div>
  {{end}}

  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Attack Graph</span>
    </button>
    <div class="section-content">
      <div class="cb-attack-path">
        {{range .AttackGraph.Path}}<div class="path-step">{{.}}</div>{{end}}
      </div>
      {{if .GraphJSON}}
      <script>window._cbGraphs=window._cbGraphs||{};window._cbGraphs['{{.ID}}']={{safeJS .GraphJSON}};</script>
      <div class="graph-flow-wrap">
        <div id="graph-{{.ID}}" class="attack-graph-flow"></div>
      </div>
      {{end}}
    </div>
  </div>

  {{if .Impact}}
  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Impact</span>
    </button>
    <div class="section-content">
      <ul class="bullet-list">{{range .Impact}}<li>{{.}}</li>{{end}}</ul>
    </div>
  </div>
  {{end}}

  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Blast Radius ({{.BlastRadius.Mode}})</span>
    </button>
    <div class="section-content">
      <div class="blast-grid">
        <div class="blast-item"><div class="blast-n">{{.BlastRadius.Pods}}</div><div class="blast-l">Pods</div></div>
        <div class="blast-item"><div class="blast-n">{{.BlastRadius.Namespaces}}</div><div class="blast-l">Namespaces</div></div>
        <div class="blast-item"><div class="blast-n">{{.BlastRadius.Nodes}}</div><div class="blast-l">Nodes</div></div>
        <div class="blast-item"><div class="blast-n">{{.BlastRadius.Secrets}}</div><div class="blast-l">Secrets</div></div>
      </div>
    </div>
  </div>

  {{if .ProofOfConcept}}
  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Proof of Concept (Reproducible Attack Path)</span>
    </button>
    <div class="section-content">
      <div class="code-block">
        <button class="copy-btn" onclick="copyCode(this)">Copy</button>
        <pre><code>{{.ProofOfConcept}}</code></pre>
      </div>
    </div>
  </div>
  {{end}}

  {{if .Remediation}}
  <div class="cb-section">
    <button class="section-toggle" onclick="toggleSection(this)">
      <span class="toggle-arrow">›</span>
      <span class="toggle-label">Remediation</span>
    </button>
    <div class="section-content">
      <div class="remediation-box">{{.Remediation}}</div>
    </div>
  </div>
  {{end}}
</div>
{{end}}
{{else}}
<div class="cb-empty"><div class="icon">🛡</div><p>No capability breaks detected. All boundary checks passed.</p></div>
{{end}}
</main>
</div><!-- /tab-capbreaks -->

<!-- ── Compound Breaks tab ─────────────────────────────────── -->
<div id="tab-compounds" class="tab-pane">
<main>
{{if .CompoundBreaks}}
<div class="cb-section-title" style="margin-top:0">{{len .CompoundBreaks}} Compound Break(s) — Multi-Stage Attack Paths</div>
{{range .CompoundBreaks}}
<div class="compound-card" id="compound-{{.ID}}">
  <div class="compound-header">
    <div class="compound-id">{{.ID}}</div>
    <div class="compound-name">{{.Name}}</div>
    <div class="compound-confidence">{{.Confidence}}% confidence</div>
  </div>

  <div class="compound-chain">
    {{range $i, $cbid := .CBIDs}}
    {{if $i}}<span class="chain-arrow">→</span>{{end}}
    <span class="compound-cb-ref" onclick="navToCB('{{$cbid}}')">{{$cbid}}</span>
    {{end}}
  </div>

  {{if .MITRE}}
  <div class="cb-mitre-row">
    {{range .MITRE}}<span class="mitre-badge">{{.ID}}<span class="mitre-tooltip">{{.Tactic}}<br><strong>{{.Name}}</strong></span></span>{{end}}
  </div>
  {{end}}

  <div class="compound-narrative">
    {{range .Path}}<div class="narrative-step">{{.}}</div>{{end}}
  </div>

  {{if .GraphJSON}}
  <script>window._cbGraphs=window._cbGraphs||{};window._cbGraphs['{{.ID}}']={{safeJS .GraphJSON}};</script>
  <div class="graph-flow-wrap" style="margin-bottom:.75rem">
    <div id="graph-{{.ID}}" class="attack-graph-flow" data-autorender="1"></div>
  </div>
  {{end}}

  <div class="compound-impact">{{.Impact}}</div>

  <div class="blast-grid" style="margin-bottom:.75rem">
    <div class="blast-item"><div class="blast-n">{{.BlastRadius.Pods}}</div><div class="blast-l">Pods</div></div>
    <div class="blast-item"><div class="blast-n">{{.BlastRadius.Namespaces}}</div><div class="blast-l">Namespaces</div></div>
    <div class="blast-item"><div class="blast-n">{{.BlastRadius.Nodes}}</div><div class="blast-l">Nodes</div></div>
    <div class="blast-item"><div class="blast-n">{{.BlastRadius.Secrets}}</div><div class="blast-l">Secrets</div></div>
  </div>

  {{range .CBs}}
  <div class="compound-cb-section">
    <div class="compound-cb-title">{{.ID}} — {{.Name}}</div>
    <ul class="cb-evidence-list">
      {{range .Evidence}}
      <li class="cb-evidence-item">
        <span class="ev-sev ev-{{lower .Severity}}">{{.Severity}}</span>
        <span class="ev-title">{{.Title}}</span>
        {{if .ResourceName}}<span class="ev-resource">{{.ResourceName}}{{if .Namespace}}/{{.Namespace}}{{end}}</span>{{end}}
      </li>
      {{end}}
    </ul>
  </div>
  {{end}}

  {{if .Remediation}}
  <div class="compound-remediation">{{.Remediation}}</div>
  {{end}}
</div>
{{end}}
{{else}}
<div class="cb-empty"><div class="icon">🔗</div><p>No compound breaks detected. No multi-stage attack paths found.</p></div>
{{end}}
</main>
</div><!-- /tab-compounds -->

<footer>
  <span>🔍 k8scan {{.Meta.K8scanVersion}}</span>
  {{if .Meta.ClusterContext}}<span>☸ {{.Meta.ClusterContext}}</span>{{end}}
  {{if .Meta.ClusterVersion}}<span>{{.Meta.ClusterVersion}}</span>{{end}}
  <span>📅 {{.GeneratedAt}}</span>
  {{if .Meta.ScanDurationMS}}<span>⏱ {{formatDuration .Meta.ScanDurationMS}}</span>{{end}}
</footer>

<script>
var activeFilter = 'all';

function applyFilters() {
  var query = document.getElementById('search-input').value.toLowerCase();
  var items = document.querySelectorAll('.finding');
  var count = 0;
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    var sevMatch = (activeFilter === 'all' || item.dataset.sev === activeFilter);
    var text = item.querySelector('.finding-header').textContent.toLowerCase();
    var textMatch = (query === '' || text.indexOf(query) !== -1);
    if (sevMatch && textMatch) { item.style.display = ''; count++; }
    else { item.style.display = 'none'; }
  }
  var cntEl = document.getElementById('findings-count');
  if (cntEl) cntEl.textContent = count;
  var noRes = document.getElementById('no-results');
  if (noRes) noRes.style.display = (count === 0 ? '' : 'none');
}

function setFilter(sev, btn) {
  activeFilter = sev;
  document.querySelectorAll('.pill').forEach(function(p) { p.classList.remove('active'); });
  btn.classList.add('active');
  applyFilters();
}

function toggleCard(header) {
  var body = header.nextElementSibling;
  var ch = header.querySelector('.chevron');
  body.classList.toggle('open');
  if (ch) ch.classList.toggle('open');
}

function toggleSection(btn) {
  btn.classList.toggle('open');
  var content = btn.nextElementSibling;
  content.classList.toggle('open');
  // Lazy-render attack graph when section first opens
  if (content.classList.contains('open')) {
    var flow = content.querySelector('.attack-graph-flow');
    if (flow && !flow.dataset.rendered) {
      flow.dataset.rendered = '1';
      var id = flow.id.replace(/^graph-/, '');
      var g = window._cbGraphs && window._cbGraphs[id];
      if (g) renderAttackGraph(flow, g);
    }
  }
}

function expandAll() {
  document.querySelectorAll('.finding-body').forEach(function(b) { b.classList.add('open'); });
  document.querySelectorAll('.chevron').forEach(function(c) { c.classList.add('open'); });
  document.querySelectorAll('.section-toggle').forEach(function(t) { t.classList.add('open'); });
  document.querySelectorAll('.section-content').forEach(function(c) { c.classList.add('open'); });
}

function collapseAll() {
  document.querySelectorAll('.finding-body').forEach(function(b) { b.classList.remove('open'); });
  document.querySelectorAll('.chevron').forEach(function(c) { c.classList.remove('open'); });
  document.querySelectorAll('.section-toggle').forEach(function(t) { t.classList.remove('open'); });
  document.querySelectorAll('.section-content').forEach(function(c) { c.classList.remove('open'); });
}

function copyCode(btn) {
  var code = btn.parentElement.querySelector('code');
  if (!code) return;
  var text = code.textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function() {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function() { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
    });
  }
}

document.addEventListener('keydown', function(e) {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
    e.preventDefault();
    var si = document.getElementById('search-input');
    if (si) { si.focus(); }
  }
  if (e.key === 'Escape') {
    var si = document.getElementById('search-input');
    if (si) { si.value = ''; applyFilters(); }
  }
});

function switchTab(btn, tabId) {
  document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
  document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
  btn.classList.add('active');
  var pane = document.getElementById('tab-' + tabId);
  if (pane) {
    pane.classList.add('active');
    // Auto-render compound graphs (always visible, not inside collapsible sections)
    pane.querySelectorAll('.attack-graph-flow[data-autorender="1"]').forEach(function(c) {
      if (!c.dataset.rendered) {
        c.dataset.rendered = '1';
        var id = c.id.replace(/^graph-/, '');
        var g = window._cbGraphs && window._cbGraphs[id];
        if (g) renderAttackGraph(c, g);
      }
    });
  }
}

function navToCB(cbId) {
  var btn = document.querySelector('.tab-btn[onclick*="capbreaks"]');
  if (btn) switchTab(btn, 'capbreaks');
  setTimeout(function() {
    var el = document.getElementById('cb-' + cbId);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 50);
}

function navToCompound(compoundId) {
  var btn = document.querySelector('.tab-btn[onclick*="compounds"]');
  if (btn) switchTab(btn, 'compounds');
  setTimeout(function() {
    var el = document.getElementById('compound-' + compoundId);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 50);
}

// ── DOM/SVG attack graph renderer ─────────────────────────────
var _GRAPH_COLORS = {
  workload:'#60a5fa', identity:'#fbbf24', node:'#f97316',
  cp:'#a78bfa', secret:'#34d399', cloud:'#38bdf8', target:'#ef4444'
};

function renderAttackGraph(container, g) {
  // ── 1. BFS column assignment ──────────────────────────────
  var inDeg = {}, outMap = {};
  g.nodes.forEach(function(n) { inDeg[n.id] = 0; outMap[n.id] = []; });
  g.edges.forEach(function(e) {
    inDeg[e.to] = (inDeg[e.to]||0) + 1;
    (outMap[e.from] = outMap[e.from]||[]).push(e.to);
  });
  var colIdx = {};
  var q = g.nodes.filter(function(n) { return !inDeg[n.id]; });
  q.forEach(function(n) { colIdx[n.id] = 0; });
  for (var qi = 0; qi < q.length; qi++) {
    var cur = q[qi];
    (outMap[cur.id]||[]).forEach(function(tid) {
      var nc = (colIdx[cur.id]||0) + 1;
      if (colIdx[tid] === undefined || colIdx[tid] < nc) {
        colIdx[tid] = nc;
        var tn = g.nodes.find(function(n) { return n.id === tid; });
        if (tn) q.push(tn);
      }
    });
  }
  g.nodes.forEach(function(n) { if (colIdx[n.id] === undefined) colIdx[n.id] = 0; });

  // ── 2. Group by column ────────────────────────────────────
  var maxCol = 0;
  g.nodes.forEach(function(n) { if (colIdx[n.id] > maxCol) maxCol = colIdx[n.id]; });
  var numCols = maxCol + 1;
  var colNodes = [];
  for (var c = 0; c < numCols; c++) colNodes[c] = [];
  g.nodes.forEach(function(n) { colNodes[colIdx[n.id]].push(n); });
  var maxPerCol = colNodes.reduce(function(m, col) { return Math.max(m, col.length); }, 1);

  // ── 3. Compute layout ─────────────────────────────────────
  var PAD_X = 16, PAD_Y = 16, GAP_X = 18, GAP_Y = 12, BH = 56, BR = 7;
  var W = container.offsetWidth || 680;
  var BW = Math.min(152, Math.floor((W - PAD_X*2 - GAP_X*(numCols-1)) / numCols));
  BW = Math.max(BW, 80);
  var totalW = numCols*BW + (numCols-1)*GAP_X;
  var ox = Math.max(PAD_X, (W - totalW) / 2);
  var totalH = maxPerCol*BH + (maxPerCol-1)*GAP_Y + PAD_Y*2;

  container.style.cssText += 'position:relative;min-height:'+totalH+'px;';
  container.innerHTML = '';

  var pos = {};
  for (var c = 0; c < numCols; c++) {
    var cn = colNodes[c];
    var colH = cn.length*BH + (cn.length-1)*GAP_Y;
    var oy = (totalH - colH) / 2;
    cn.forEach(function(n, i) {
      pos[n.id] = { x: ox + c*(BW+GAP_X), y: oy + i*(BH+GAP_Y) };
    });
  }

  // ── 4. SVG layer for edges ────────────────────────────────
  var NS = 'http://www.w3.org/2000/svg';
  var svgEl = document.createElementNS(NS, 'svg');
  svgEl.setAttribute('width', W);
  svgEl.setAttribute('height', totalH);
  svgEl.style.cssText = 'position:absolute;top:0;left:0;pointer-events:none;overflow:visible;';

  // Unique arrow marker per graph
  var markerId = 'agm-' + container.id.replace(/[^a-z0-9]/gi,'');
  var defs = document.createElementNS(NS, 'defs');
  var marker = document.createElementNS(NS, 'marker');
  marker.setAttribute('id', markerId);
  marker.setAttribute('markerWidth', '7'); marker.setAttribute('markerHeight', '7');
  marker.setAttribute('refX', '6'); marker.setAttribute('refY', '3.5');
  marker.setAttribute('orient', 'auto');
  var arrowPoly = document.createElementNS(NS, 'polygon');
  arrowPoly.setAttribute('points', '0,0 7,3.5 0,7');
  arrowPoly.setAttribute('fill', 'rgba(148,163,184,.5)');
  marker.appendChild(arrowPoly); defs.appendChild(marker); svgEl.appendChild(defs);

  g.edges.forEach(function(e) {
    var a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    var x1 = a.x + BW, y1 = a.y + BH/2;
    var x2 = b.x - 1, y2 = b.y + BH/2;
    var mx = (x1 + x2) / 2;

    var path = document.createElementNS(NS, 'path');
    path.setAttribute('d', 'M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2);
    path.setAttribute('stroke', 'rgba(148,163,184,.28)');
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('fill', 'none');
    path.setAttribute('marker-end', 'url(#'+markerId+')');
    svgEl.appendChild(path);

    if (e.label) {
      var lx = mx, ly = Math.min(a.y, b.y) - 5;
      if (ly < 6) ly = 6;
      var txt = document.createElementNS(NS, 'text');
      txt.setAttribute('x', lx); txt.setAttribute('y', ly);
      txt.setAttribute('fill', 'rgba(148,163,184,.72)');
      txt.setAttribute('font-size', '9');
      txt.setAttribute('font-family', 'ui-monospace,SFMono-Regular,monospace');
      txt.setAttribute('text-anchor', 'middle');
      txt.textContent = e.label;
      svgEl.appendChild(txt);
    }
  });
  container.appendChild(svgEl);

  // ── 5. Node divs ──────────────────────────────────────────
  g.nodes.forEach(function(n) {
    var p = pos[n.id];
    if (!p) return;
    var tc = _GRAPH_COLORS[n.type] || '#94a3b8';

    var div = document.createElement('div');
    div.style.cssText =
      'position:absolute;box-sizing:border-box;'
      +'left:'+p.x+'px;top:'+p.y+'px;width:'+BW+'px;min-height:'+BH+'px;'
      +'border:1.5px solid '+tc+';border-radius:'+BR+'px;'
      +'background:rgba(8,14,28,.97);'
      +'display:flex;align-items:center;justify-content:center;'
      +'flex-direction:column;padding:3px 8px 3px 12px;'
      +'box-shadow:0 0 10px 0 '+tc+'28;';

    var stripe = document.createElement('div');
    stripe.style.cssText =
      'position:absolute;left:0;top:'+BR+'px;bottom:'+BR+'px;'
      +'width:3px;background:'+tc+';border-radius:1px 0 0 1px;opacity:.9;';
    div.appendChild(stripe);

    var lines = n.label.split('\n');
    var l1 = document.createElement('div');
    l1.style.cssText =
      'font:600 10px/1.3 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
      +'color:#e2e8f0;text-align:center;'
      +'word-break:break-word;overflow-wrap:break-word;width:100%;';
    l1.textContent = lines[0];
    div.appendChild(l1);

    if (lines[1]) {
      var l2 = document.createElement('div');
      l2.style.cssText =
        'font:9.5px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
        +'color:rgba(148,163,184,.8);text-align:center;'
        +'word-break:break-word;width:100%;margin-top:2px;';
      l2.textContent = lines[1];
      div.appendChild(l2);
    }
    container.appendChild(div);
  });
}
</script>
</body>
</html>`

// ─── SARIF output ─────────────────────────────────────────────────────────────

// WriteSARIF writes a SARIF 2.1.0 report compatible with GitHub Advanced Security.
func WriteSARIF(findings []*core.Finding, meta ReportMeta, path string) error {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMessage      `json:"shortDescription"`
		FullDescription  sarifMessage      `json:"fullDescription"`
		Properties       map[string]string `json:"properties,omitempty"`
	}
	type sarifLogicalLoc struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
		Kind               string `json:"kind"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhysLoc struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysLoc      `json:"physicalLocation"`
		LogicalLocations []sarifLogicalLoc `json:"logicalLocations"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifRoot struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	rulesSeen := make(map[string]bool)
	// Initialize as empty (non-nil) slices so a zero-finding report serializes to
	// "rules": [] / "results": [] rather than null — strict SARIF consumers
	// (GitHub Advanced Security) reject a null where an array is expected.
	rules := []sarifRule{}
	for _, f := range findings {
		if !rulesSeen[f.Title] {
			rulesSeen[f.Title] = true
			rules = append(rules, sarifRule{
				ID:               sarifRuleID(f.Title),
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				Properties:       map[string]string{"category": f.Category, "severity": string(f.Severity)},
			})
		}
	}

	results := []sarifResult{}
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID: sarifRuleID(f.Title),
			Level:  sarifSeverityLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Description + " Remediation: " + f.Remediation,
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifact{
						URI: func() string {
							if f.SourceFile != "" {
								return f.SourceFile
							}
							return fmt.Sprintf("k8s://%s/%s/%s", f.Namespace, strings.ToLower(f.ResourceType), f.ResourceName)
						}(),
					},
					Region: func() *sarifRegion {
						if f.SourceLine > 0 {
							return &sarifRegion{StartLine: f.SourceLine}
						}
						return nil
					}(),
				},
				LogicalLocations: []sarifLogicalLoc{{
					Name:               f.ResourceName,
					FullyQualifiedName: fmt.Sprintf("%s/%s/%s", f.Namespace, f.ResourceType, f.ResourceName),
					Kind:               strings.ToLower(f.ResourceType),
				}},
			}},
		})
	}

	ver := meta.K8scanVersion
	if ver == "" {
		ver = "1.0.0"
	}
	root := sarifRoot{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "k8scan",
					Version:        ver,
					InformationURI: "https://github.com/alperenkesk/k8scan",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func sarifRuleID(title string) string {
	return "K8S-" + strings.ToUpper(strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(title))
}

func sarifSeverityLevel(sev core.Severity) string {
	switch sev {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// ─── Markdown output ──────────────────────────────────────────────────────────

// WriteMarkdown writes a Markdown report suitable for GitHub issues and PR comments.
func WriteMarkdown(findings []*core.Finding, meta ReportMeta, path string) error {
	summary := core.BuildSummary(findings)
	score, grade := summary.SecurityScore()

	var sb strings.Builder

	sb.WriteString("# k8scan Security Report\n\n")
	if meta.ClusterContext != "" {
		parts := []string{meta.ClusterContext}
		if meta.ClusterVersion != "" {
			parts = append(parts, meta.ClusterVersion)
		}
		sb.WriteString(fmt.Sprintf("**Cluster:** %s\n\n", strings.Join(parts, " · ")))
	}
	sb.WriteString(fmt.Sprintf("**Generated:** %s", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	if meta.ScanDurationMS > 0 {
		if meta.ScanDurationMS < 1000 {
			sb.WriteString(fmt.Sprintf(" · scan took %dms", meta.ScanDurationMS))
		} else {
			sb.WriteString(fmt.Sprintf(" · scan took %.1fs", float64(meta.ScanDurationMS)/1000))
		}
	}
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("## Security Score: %d/100 — Grade **%s**\n\n", score, grade))

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n|:---------|------:|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 **CRITICAL** | %d |\n", summary.Critical))
	sb.WriteString(fmt.Sprintf("| 🟠 **HIGH** | %d |\n", summary.High))
	sb.WriteString(fmt.Sprintf("| 🟡 **MEDIUM** | %d |\n", summary.Medium))
	sb.WriteString(fmt.Sprintf("| 🔵 **LOW** | %d |\n", summary.Low))
	sb.WriteString(fmt.Sprintf("| ⚪ **INFO** | %d |\n", summary.Info))
	sb.WriteString(fmt.Sprintf("| — | **%d** |\n\n", summary.Total))

	if summary.Total == 0 {
		sb.WriteString("✅ No security issues found.\n")
	} else {
		sb.WriteString("## Findings\n\n")
		grouped := core.GroupFindings(findings)
		for _, g := range grouped {
			icon := markdownIcon(g.Severity)
			if g.Count == 1 {
				f := g.Examples[0]
				sb.WriteString(fmt.Sprintf("### %s %s\n\n", icon, g.Title))
				sb.WriteString(fmt.Sprintf("**Resource:** `%s/%s`", f.ResourceType, f.ResourceName))
				if f.Namespace != "" {
					sb.WriteString(fmt.Sprintf(" · namespace `%s`", f.Namespace))
				}
				sb.WriteString("\n\n")
				if f.Description != "" {
					sb.WriteString(fmt.Sprintf("%s\n\n", f.Description))
				}
				if g.Remediation != "" {
					sb.WriteString(fmt.Sprintf("> **Remediation:** %s\n\n", g.Remediation))
				}
			} else {
				sb.WriteString(fmt.Sprintf("### %s %s ×%d\n\n", icon, g.Title, g.Count))
				for _, ex := range g.Examples {
					ns := ""
					if ex.Namespace != "" {
						ns = " (`" + ex.Namespace + "`)"
					}
					sb.WriteString(fmt.Sprintf("- `%s/%s`%s\n", ex.ResourceType, ex.ResourceName, ns))
				}
				if g.Count > len(g.Examples) {
					sb.WriteString(fmt.Sprintf("- … and %d more\n", g.Count-len(g.Examples)))
				}
				if g.Remediation != "" {
					sb.WriteString(fmt.Sprintf("\n> **Remediation:** %s\n", g.Remediation))
				}
				sb.WriteString("\n")
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func markdownIcon(sev core.Severity) string {
	switch sev {
	case core.SeverityCritical:
		return "🔴"
	case core.SeverityHigh:
		return "🟠"
	case core.SeverityMedium:
		return "🟡"
	case core.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}
