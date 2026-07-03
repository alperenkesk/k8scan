package core

// ── Enums ─────────────────────────────────────────────────────

type CBStatus string

const (
	CBStatusBroken   CBStatus = "BROKEN"
	CBStatusDegraded CBStatus = "DEGRADED"
	CBStatusWeak     CBStatus = "WEAK"
)

type CBExploitability string

const (
	CBExploitImmediate CBExploitability = "IMMEDIATE"
	CBExploitHigh      CBExploitability = "HIGH"
	CBExploitMedium    CBExploitability = "MEDIUM"
	CBExploitLow       CBExploitability = "LOW"
)

type CBBlastMode string

const (
	BlastModeInfer     CBBlastMode = "INFER"
	BlastModeProjected CBBlastMode = "PROJECTED"
	BlastModeActual    CBBlastMode = "ACTUAL"
)

// ── Sub-types ─────────────────────────────────────────────────

// CBEvidence links a raw Finding to a CapabilityBreak.
type CBEvidence struct {
	FindingID    int
	Title        string
	ResourceType string // e.g. "Pod", "Deployment" — lets PoCs build correct kubectl refs
	ResourceName string
	Namespace    string
	Severity     string
}

// ── Validation Proof ──────────────────────────────────────────

// ValidationProof explains WHY a boundary is considered broken — deterministic,
// reproducible, and explainable per finding.
type ValidationProof struct {
	Verdict  string        // e.g. "BOUNDARY BROKEN: 2 escape vectors confirmed"
	Signals  []ProofSignal // one entry per matched finding
	Combined string        // how signals together prove the failure
}

// ProofSignal is one matched finding with its boundary-failure significance.
type ProofSignal struct {
	Title        string
	Resource     string // "namespace/pod-name"
	Severity     string
	Significance string  // why this signal proves a boundary failure
	Weight       float64 // signal weight used in confidence calculation
}

// ── Graph types ───────────────────────────────────────────────

// CBGraphNode is a node in the attack graph visualization.
type CBGraphNode struct {
	ID    string // unique within the graph
	Label string // may contain \n for multi-line (rendered as two lines)
	Type  string // workload | identity | node | cp | secret | cloud | target
}

// CBGraphEdge is a directed edge in the attack graph.
type CBGraphEdge struct {
	From  string
	To    string
	Label string
	Style string // escape | steal | escalate | access | compromise
}

// CBBlastRadius describes the potential blast radius of a boundary failure.
type CBBlastRadius struct {
	Mode       CBBlastMode
	Pods       int
	Namespaces int
	Nodes      int
	Secrets    int
	Level      string // LOW | MEDIUM | HIGH | CRITICAL
}

// CBAttackGraph describes the attack path enabled by a boundary failure.
type CBAttackGraph struct {
	// Path is an ordered list of steps, e.g. ["Container", "→ Node", "→ cluster-admin"]
	Path        []string
	Description string
}

// MITRETechnique is a single MITRE ATT&CK for Containers technique.
type MITRETechnique struct {
	ID     string // e.g. "T1611"
	Name   string // e.g. "Escape to Host"
	Tactic string // e.g. "Privilege Escalation"
}

// ── CapabilityBreak ───────────────────────────────────────────

// CapabilityBreak is a validated security boundary failure detected by
// correlating one or more raw Findings against a boundary-failure rule.
type CapabilityBreak struct {
	ID             string
	Name           string
	Boundary       string           // e.g. "L1 — Workload Boundary"
	Layer          string           // "L1" | "L2" | "L3" | "L4"
	Status         CBStatus         // BROKEN | DEGRADED | WEAK
	Confidence     int              // 75–100
	Exploitability CBExploitability // IMMEDIATE | HIGH | MEDIUM | LOW
	Evidence       []CBEvidence
	AttackGraph    CBAttackGraph
	Impact         []string
	BlastRadius    CBBlastRadius
	Remediation    string
	FixPriority    string // P0 | P1 | P2 | P3
	MITRE          []MITRETechnique
	// ProofOfConcept contains step-by-step commands using real resource names
	// from the evidence findings — reproducible attack path simulation.
	ProofOfConcept string
	// ValidationProof explains why this boundary is considered broken.
	ValidationProof ValidationProof
	// GraphNodes and GraphEdges drive the Obsidian-style attack graph canvas.
	GraphNodes []CBGraphNode
	GraphEdges []CBGraphEdge
	// GraphJSON is the pre-serialized JSON for the canvas renderer (avoids
	// template-level serialization).
	GraphJSON string
}

// ── CompoundBreak ─────────────────────────────────────────────

// CompoundBreak is detected when two or more CapabilityBreaks combine into
// a realistic multi-stage attack path (the exploitation story).
type CompoundBreak struct {
	ID          string
	Name        string
	CBIDs       []string          // constituent CB IDs, e.g. ["CB-001","CB-003"]
	CBs         []CapabilityBreak // full constituent CB structs for rendering
	Confidence  int               // weighted from constituent CBs
	Path        []string          // narrative attack steps
	Impact      string
	BlastRadius CBBlastRadius
	Remediation string
	MITRE       []MITRETechnique
	// GraphJSON is the pre-serialized JSON for the canvas renderer.
	GraphJSON string
}

// ── CBAnalysisResult ──────────────────────────────────────────

// CBAnalysisResult is returned by capbreaks.Analyze() and consumed by the
// HTML reporter. FindingCBMap and FindingCompoundMap drive cross-reference
// badges on individual Finding cards (finding → CB → Compound).
type CBAnalysisResult struct {
	CapabilityBreaks []CapabilityBreak
	CompoundBreaks   []CompoundBreak
	// FindingCBMap maps Finding.FindingID (as string) → CB IDs it contributes to.
	FindingCBMap map[string][]string
	// FindingCompoundMap maps Finding.FindingID (as string) → Compound IDs it contributes to.
	FindingCompoundMap map[string][]string
	BlastMode          CBBlastMode
}
