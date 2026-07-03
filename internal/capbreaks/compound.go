package capbreaks

import (
	"math"

	"github.com/alperenkesk/k8scan/internal/core"
)

// compoundRule defines a known multi-stage attack path composed of 2+ CBs.
type compoundRule struct {
	id          string
	name        string
	requires    []string // CB IDs that must all be present (AND)
	path        []string // narrative attack steps
	impact      string
	remediation string
	mitre       []core.MITRETechnique
	// pathPositions assigns each required CB ID a position multiplier:
	// chain start (1.2) → bridge (1.1) → leaf (0.9)
	pathPositions map[string]float64
}

var compoundRules = []compoundRule{
	{
		id:       "COMPOUND-1",
		name:     "Container Escape to Cluster Admin",
		requires: []string{"CB-001", "CB-003"},
		path: []string{
			"Container escape via privileged context / hostPID",
			"→ Access node filesystem, steal kubeconfig or SA token",
			"→ RBAC escalation using stolen identity",
			"→ cluster-admin — full cluster control",
		},
		impact:      "Complete cluster compromise from any vulnerable pod.",
		remediation: "Enforce non-privileged workloads via admission control (CB-001) AND restrict RBAC escalation paths (CB-003). Both boundaries must hold simultaneously.",
		mitre: []core.MITRETechnique{
			{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
		},
		pathPositions: map[string]float64{"CB-001": 1.2, "CB-003": 1.1},
	},
	{
		id:       "COMPOUND-2",
		name:     "ServiceAccount Token to Full Cluster Control",
		requires: []string{"CB-004", "CB-003"},
		path: []string{
			"Auto-mounted SA token exfiltrated from compromised pod",
			"→ Token carries excessive RBAC permissions",
			"→ Create RoleBinding / escalate to cluster-admin",
			"→ Unrestricted cluster API access",
		},
		impact:      "Identity abuse path requiring zero container escape — API-only attack.",
		remediation: "Disable SA auto-mount where not needed (CB-004) and eliminate RBAC escalation paths (CB-003).",
		mitre: []core.MITRETechnique{
			{ID: "T1528", Name: "Steal Application Access Token", Tactic: "Credential Access"},
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
		},
		pathPositions: map[string]float64{"CB-004": 1.2, "CB-003": 1.1},
	},
	{
		id:       "COMPOUND-3",
		name:     "Container Escape to Cloud Account Takeover",
		requires: []string{"CB-001", "CB-010"},
		path: []string{
			"Container escape to node level via privileged context",
			"→ Node can reach cloud metadata API (169.254.169.254)",
			"→ Retrieve IAM credentials / IRSA token from metadata service",
			"→ AWS / GCP / Azure account full access",
		},
		impact:      "Kubernetes cluster breach pivots directly to cloud infrastructure compromise.",
		remediation: "Enforce non-privileged containers (CB-001) AND block metadata API egress via NetworkPolicy (CB-010).",
		mitre: []core.MITRETechnique{
			{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
			{ID: "T1552.005", Name: "Cloud Instance Metadata API", Tactic: "Credential Access"},
		},
		pathPositions: map[string]float64{"CB-001": 1.2, "CB-010": 1.1},
	},
	{
		id:       "COMPOUND-4",
		name:     "Policy Bypass to Persistent Node Compromise",
		requires: []string{"CB-005", "CB-001"},
		path: []string{
			"Attacker submits privileged container manifest",
			"→ No admission webhook rejects it (policy bypass)",
			"→ Privileged pod scheduled and running",
			"→ Container escape to node root",
		},
		impact:      "Admission control failure removes the last prevention layer before container escape.",
		remediation: "Deploy Kyverno/OPA with a deny-privileged policy (CB-005) so CB-001 risks cannot manifest.",
		mitre: []core.MITRETechnique{
			{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"},
			{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
		},
		pathPositions: map[string]float64{"CB-005": 1.2, "CB-001": 0.9},
	},
	{
		id:       "COMPOUND-5",
		name:     "Full Cluster Compromise via Triple Boundary Failure",
		requires: []string{"CB-001", "CB-003", "CB-007"},
		path: []string{
			"Container escape to node (CB-001)",
			"→ Steal SA token / kubeconfig from node",
			"→ RBAC escalation to cluster-admin (CB-003)",
			"→ List and exfiltrate all cluster secrets (CB-007)",
			"→ Complete cluster takeover + credential exfiltration",
		},
		impact:      "Highest-severity scenario: node compromise + RBAC escalation + full secret exfiltration in one chain.",
		remediation: "All three boundaries must be hardened simultaneously. Prioritize CB-001 (container hardening) as the chain entry point.",
		mitre: []core.MITRETechnique{
			{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
			{ID: "T1552", Name: "Unsecured Credentials", Tactic: "Credential Access"},
		},
		pathPositions: map[string]float64{"CB-001": 1.2, "CB-003": 1.1, "CB-007": 0.9},
	},
	{
		id:       "COMPOUND-6",
		name:     "Namespace Escape via RBAC Wildcard",
		requires: []string{"CB-002", "CB-003"},
		path: []string{
			"Workload in Namespace A exploits ClusterRoleBinding",
			"→ Wildcard RBAC verbs allow access to Namespace B..N",
			"→ RBAC escalation creates new bindings in target namespace",
			"→ Tenant escape — full cross-namespace control",
		},
		impact:      "Namespace boundary is completely meaningless when combined with wildcard RBAC.",
		remediation: "Replace ClusterRoleBindings with namespace-scoped RoleBindings (CB-002) and eliminate wildcard RBAC (CB-003).",
		mitre: []core.MITRETechnique{
			{ID: "T1484", Name: "Domain Policy Modification", Tactic: "Privilege Escalation"},
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
		},
		pathPositions: map[string]float64{"CB-002": 1.2, "CB-003": 1.1},
	},
	{
		id:       "COMPOUND-7",
		name:     "CI/CD Pipeline to Cluster Takeover",
		requires: []string{"CB-008", "CB-004"},
		path: []string{
			"Attacker compromises CI/CD pipeline (ArgoCD / Flux / GitHub Actions)",
			"→ Pipeline holds SA token with deploy permissions",
			"→ Deploy malicious workload with SA's identity",
			"→ Escalate via SA's RBAC permissions → cluster control",
		},
		impact:      "Supply chain entry point combined with identity abuse — no direct cluster access required.",
		remediation: "Restrict CI/CD SA permissions (CB-008) and enforce SA least-privilege (CB-004).",
		mitre: []core.MITRETechnique{
			{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"},
			{ID: "T1528", Name: "Steal Application Access Token", Tactic: "Credential Access"},
		},
		pathPositions: map[string]float64{"CB-008": 1.2, "CB-004": 1.1},
	},
	{
		id:       "COMPOUND-8",
		name:     "Multi-Tenant Escape via Shared Identity",
		requires: []string{"CB-009", "CB-002"},
		path: []string{
			"Tenant A abuses shared ServiceAccount or shared controller",
			"→ Cross-namespace resource access via ClusterRoleBinding",
			"→ Read Tenant B secrets / modify Tenant B workloads",
			"→ Full tenant isolation breakdown",
		},
		impact:      "Shared identity layer bridges two separate tenant boundaries.",
		remediation: "Enforce per-tenant SA isolation (CB-009) and namespace-scoped RBAC (CB-002).",
		mitre: []core.MITRETechnique{
			{ID: "T1484", Name: "Domain Policy Modification", Tactic: "Privilege Escalation"},
			{ID: "T1078", Name: "Valid Accounts", Tactic: "Persistence"},
		},
		pathPositions: map[string]float64{"CB-009": 1.2, "CB-002": 1.1},
	},
	{
		id:       "COMPOUND-9",
		name:     "Cloud Identity Bridge with RBAC Escalation",
		requires: []string{"CB-010", "CB-003"},
		path: []string{
			"Pod reaches cloud metadata API, obtains IAM credentials",
			"→ IAM role has K8s API server access or RBAC bind permissions",
			"→ Escalate to cluster-admin via RBAC",
			"→ AWS / GCP / Azure account + full cluster control simultaneously",
		},
		impact:      "Bidirectional compromise: cloud account AND Kubernetes cluster both fall in one chain.",
		remediation: "Block metadata API access (CB-010) and eliminate RBAC escalation paths (CB-003).",
		mitre: []core.MITRETechnique{
			{ID: "T1552.005", Name: "Cloud Instance Metadata API", Tactic: "Credential Access"},
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
		},
		pathPositions: map[string]float64{"CB-010": 1.2, "CB-003": 1.1},
	},
	{
		id:       "COMPOUND-10",
		name:     "Container Runtime Socket to Node Takeover",
		requires: []string{"CB-006", "CB-001"},
		path: []string{
			"Container accesses docker.sock or containerd.sock",
			"→ Spawn new container with privileged flag via runtime API",
			"→ New container escapes to host filesystem",
			"→ Node root — full node compromise",
		},
		impact:      "Container runtime socket access is an unconditional node takeover when combined with privileged container capability.",
		remediation: "Never mount runtime sockets in workloads (CB-006) and enforce non-privileged containers (CB-001).",
		mitre: []core.MITRETechnique{
			{ID: "T1610", Name: "Deploy Container", Tactic: "Execution"},
			{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
		},
		pathPositions: map[string]float64{"CB-006": 1.2, "CB-001": 0.9},
	},
}

// exploitWeight maps CBExploitability to a numeric weight for confidence calculation.
var exploitWeight = map[core.CBExploitability]float64{
	core.CBExploitImmediate: 1.0,
	core.CBExploitHigh:      0.8,
	core.CBExploitMedium:    0.5,
	core.CBExploitLow:       0.2,
}

// weightedConfidence computes compound confidence using the formula:
// Σ(CB.confidence × exploitWeight × pathPosition) / Σ(exploitWeight × pathPosition)
func weightedConfidence(cbMap map[string]core.CapabilityBreak, positions map[string]float64) int {
	totalWeighted := 0.0
	totalWeight := 0.0
	for id, cb := range cbMap {
		pos := positions[id]
		if pos == 0 {
			pos = 1.0
		}
		w := exploitWeight[cb.Exploitability] * pos
		totalWeighted += float64(cb.Confidence) * w
		totalWeight += w
	}
	if totalWeight == 0 {
		return 0
	}
	return int(math.Min(totalWeighted/totalWeight, 100))
}

// detectCompounds returns all compound breaks whose required CBs are all present.
func detectCompounds(activeCBs []core.CapabilityBreak, _ core.CBBlastMode, _ interface{}) []core.CompoundBreak {
	cbByID := make(map[string]core.CapabilityBreak, len(activeCBs))
	for _, cb := range activeCBs {
		cbByID[cb.ID] = cb
	}

	var compounds []core.CompoundBreak
	for _, rule := range compoundRules {
		if c := evalCompoundRule(rule, cbByID); c != nil {
			compounds = append(compounds, *c)
		}
	}
	return compounds
}

func evalCompoundRule(rule compoundRule, cbByID map[string]core.CapabilityBreak) *core.CompoundBreak {
	present := make(map[string]core.CapabilityBreak, len(rule.requires))
	for _, req := range rule.requires {
		cb, ok := cbByID[req]
		if !ok {
			return nil
		}
		present[req] = cb
	}

	conf := weightedConfidence(present, rule.pathPositions)
	if conf < 75 {
		return nil
	}

	cbs := make([]core.CapabilityBreak, 0, len(rule.requires))
	for _, req := range rule.requires {
		cbs = append(cbs, present[req])
	}

	blast := worstBlast(cbs)
	return &core.CompoundBreak{
		ID:          rule.id,
		Name:        rule.name,
		CBIDs:       rule.requires,
		CBs:         cbs,
		Confidence:  conf,
		Path:        rule.path,
		Impact:      rule.impact,
		BlastRadius: blast,
		Remediation: rule.remediation,
		MITRE:       rule.mitre,
	}
}

// worstBlast returns the highest-severity blast radius among constituent CBs.
func worstBlast(cbs []core.CapabilityBreak) core.CBBlastRadius {
	levelOrder := map[string]int{"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
	best := core.CBBlastRadius{Level: "LOW"}
	for _, cb := range cbs {
		if levelOrder[cb.BlastRadius.Level] > levelOrder[best.Level] {
			best = cb.BlastRadius
		}
		if cb.BlastRadius.Pods > best.Pods {
			best.Pods = cb.BlastRadius.Pods
		}
		if cb.BlastRadius.Namespaces > best.Namespaces {
			best.Namespaces = cb.BlastRadius.Namespaces
		}
		if cb.BlastRadius.Nodes > best.Nodes {
			best.Nodes = cb.BlastRadius.Nodes
		}
		if cb.BlastRadius.Secrets > best.Secrets {
			best.Secrets = cb.BlastRadius.Secrets
		}
	}
	return best
}
