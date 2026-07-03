package capbreaks

import (
	"math"
	"strings"

	"github.com/alperenkesk/k8scan/internal/core"
)

// ── Signal matching primitives ────────────────────────────────

type signalDef struct {
	keyword      string
	weight       float64
	significance string // why this signal proves a boundary failure
}

type matchedSignal struct {
	def     signalDef
	finding *core.Finding
}

// matchSignals scans all findings for keyword hits in title+category.
// Each finding is matched at most once per keyword to avoid double-counting.
func matchSignals(findings []*core.Finding, signals []signalDef) []matchedSignal {
	var matched []matchedSignal
	for _, f := range findings {
		combined := strings.ToLower(f.Title + " " + f.Category)
		for _, sig := range signals {
			if containsKeyword(combined, sig.keyword) {
				matched = append(matched, matchedSignal{def: sig, finding: f})
				break // one match per finding
			}
		}
	}
	return matched
}

// containsKeyword reports whether keyword occurs in haystack bounded by
// non-word characters on both sides. This is a word/phrase match, not a raw
// substring match: it prevents short keywords from matching inside larger words
// (e.g. "exec" must not match "execution", "opa" must not match "propagation").
// haystack is expected to be lower-cased already.
func containsKeyword(haystack, keyword string) bool {
	if keyword == "" {
		return false
	}
	from := 0
	for {
		i := strings.Index(haystack[from:], keyword)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(keyword)
		beforeOK := start == 0 || !isWordByte(haystack[start-1])
		afterOK := end == len(haystack) || !isWordByte(haystack[end])
		if beforeOK && afterOK {
			return true
		}
		from = start + 1
	}
}

// isWordByte reports whether b is an alphanumeric ASCII character. Underscores
// and punctuation count as boundaries so keywords like "sys_admin" or
// "docker.sock" still match at their natural edges.
func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// confidenceFromSignals converts total signal weight to a 0–100 confidence score.
// One strong signal (weight 1.0) → 80; two signals → ~95; three+ → 100.
func confidenceFromSignals(matched []matchedSignal) int {
	if len(matched) == 0 {
		return 0
	}
	total := 0.0
	for _, m := range matched {
		total += m.def.weight
	}
	raw := 65.0 + total*15.0
	return int(math.Min(raw, 100))
}

func toEvidence(matched []matchedSignal) []core.CBEvidence {
	seen := make(map[int]bool)
	var ev []core.CBEvidence
	for _, m := range matched {
		if seen[m.finding.FindingID] {
			continue
		}
		seen[m.finding.FindingID] = true
		ev = append(ev, core.CBEvidence{
			FindingID:    m.finding.FindingID,
			Title:        m.finding.Title,
			ResourceType: m.finding.ResourceType,
			ResourceName: m.finding.ResourceName,
			Namespace:    m.finding.Namespace,
			Severity:     string(m.finding.Severity),
		})
	}
	return ev
}

func statusFromConfidence(conf int) core.CBStatus {
	switch {
	case conf >= 88:
		return core.CBStatusBroken
	case conf >= 78:
		return core.CBStatusDegraded
	default:
		return core.CBStatusWeak
	}
}

func exploitFromMatched(matched []matchedSignal) core.CBExploitability {
	for _, m := range matched {
		if m.finding.Severity == core.SeverityCritical {
			return core.CBExploitImmediate
		}
	}
	for _, m := range matched {
		if m.finding.Severity == core.SeverityHigh {
			return core.CBExploitHigh
		}
	}
	for _, m := range matched {
		if m.finding.Severity == core.SeverityMedium {
			return core.CBExploitMedium
		}
	}
	return core.CBExploitLow
}

func fixPriority(status core.CBStatus, exploit core.CBExploitability) string {
	switch {
	case exploit == core.CBExploitImmediate:
		return "P0"
	case status == core.CBStatusBroken && exploit == core.CBExploitHigh:
		return "P0"
	case status == core.CBStatusBroken || exploit == core.CBExploitHigh:
		return "P1"
	case status == core.CBStatusDegraded:
		return "P2"
	default:
		return "P3"
	}
}

// ── CB-001: Container Isolation Failure ──────────────────────

var cb001Signals = []signalDef{
	{keyword: "privileged container", weight: 1.0, significance: "Grants container direct host kernel namespace access — equivalent to root on the node"},
	{keyword: "privileged mode", weight: 1.0, significance: "Container runs with unrestricted host privileges — no isolation boundary"},
	{keyword: "sys_admin", weight: 1.0, significance: "Unrestricted Linux capability — kernel module load, mount, namespace manipulation"},
	{keyword: "dangerous capability", weight: 0.85, significance: "Dangerous Linux capability grants kernel-level access beyond container namespace boundaries"},
	{keyword: "bpf", weight: 0.9, significance: "eBPF programs can read/write arbitrary kernel memory and trace all processes"},
	{keyword: "net_admin", weight: 0.7, significance: "Full network stack manipulation — can intercept and modify node traffic"},
	{keyword: "sys_ptrace", weight: 0.85, significance: "Can attach to any process on the host — credential extraction from other containers"},
	{keyword: "hostpid", weight: 0.85, significance: "All node processes visible — /proc/*/root exposes host filesystem to container"},
	{keyword: "hostnetwork", weight: 0.65, significance: "Container shares node network namespace — can sniff cluster-internal traffic"},
	{keyword: "host path", weight: 0.7, significance: "Direct mount of node filesystem — bypasses container storage isolation"},
	{keyword: "hostpath", weight: 0.7, significance: "Direct mount of node filesystem — bypasses container storage isolation"},
	{keyword: "shared process namespace", weight: 0.7, significance: "Shared process namespace exposes all pod processes — credentials in co-located container memory are readable"},
	{keyword: "unmasked proc", weight: 0.8, significance: "Unmasked /proc exposes host kernel internals — container escape via /proc/sysrq-trigger or sysctl"},
	{keyword: "bidirectional volume", weight: 0.65, significance: "Bidirectional mount propagation exposes host filesystem write path from within the container"},
	{keyword: "escalation allowed", weight: 0.7, significance: "AllowPrivilegeEscalation enabled — setuid binaries can elevate child process privileges beyond parent"},
	{keyword: "allows privilege escalation", weight: 0.7, significance: "Container explicitly permits privilege escalation — setuid/setgid escalation path confirmed"},
	{keyword: "allowprivilegeescalation", weight: 0.65, significance: "AllowPrivilegeEscalation flag set — child process privilege elevation is not blocked"},
	{keyword: "allow privilege escalation", weight: 0.65, significance: "AllowPrivilegeEscalation configuration — setuid binaries can acquire additional privileges"},
}

func evalCB001(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb001Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-001", Name: "Container Isolation Failure",
		Boundary: "L1 — Workload Boundary", Layer: "L1",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Compromised Container", "→ Privileged / hostPID / hostPath access", "→ Node filesystem or kubelet socket", "→ Steal kubeconfig / SA token", "→ cluster-admin"},
			Description: "Attacker escapes container sandbox via privileged execution context or host namespace access.",
		},
		Impact:      []string{"node root access", "kubelet compromise", "credential theft from node filesystem"},
		Remediation: "Remove privileged:true. Drop ALL capabilities and add only required ones. Avoid hostPID/hostNetwork/hostPath. Set runAsNonRoot:true and allowPrivilegeEscalation:false.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB001,
	}
}

// ── CB-002: Namespace Isolation Failure ──────────────────────

var cb002Signals = []signalDef{
	{keyword: "clusterrolebinding", weight: 0.9, significance: "ClusterRoleBinding grants cluster-wide permissions — namespace provides no isolation"},
	{keyword: "cluster role binding", weight: 0.9, significance: "ClusterRoleBinding grants cluster-wide permissions — namespace provides no isolation"},
	{keyword: "wildcard", weight: 0.85, significance: "Wildcard resource/verb expands permissions to all current and future resource types"},
	{keyword: "impersonate", weight: 1.0, significance: "Identity can act as any user/group/SA — authentication boundary fully bypassed"},
	{keyword: "cross-namespace", weight: 0.8, significance: "Explicit cross-namespace access proves isolation boundary is broken"},
	{keyword: "all namespaces", weight: 0.75, significance: "Access to all namespaces defeats the purpose of namespace segmentation"},
	{keyword: "cluster-wide", weight: 0.7, significance: "Cluster-scoped permissions override any namespace-level isolation"},
}

func evalCB002(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb002Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-002", Name: "Namespace Isolation Failure",
		Boundary: "L2 — Identity Boundary", Layer: "L2",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Workload in Namespace A", "→ ClusterRoleBinding / wildcard RBAC", "→ Access resources in Namespace B..N", "→ Tenant escape"},
			Description: "Namespace boundary provides no real isolation due to cluster-scoped RBAC or wildcard permissions.",
		},
		Impact:      []string{"tenant escape", "cross-namespace lateral movement", "multi-tenant isolation broken"},
		Remediation: "Replace ClusterRoleBindings with namespace-scoped RoleBindings where possible. Eliminate wildcard verbs/resources. Audit impersonation permissions.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB002,
	}
}

// ── CB-003: RBAC Boundary Failure ────────────────────────────

var cb003Signals = []signalDef{
	{keyword: "system:masters", weight: 1.0, significance: "system:masters group binding grants unconditional cluster-admin — cannot be restricted by RBAC admission"},
	{keyword: "create rolebinding", weight: 1.0, significance: "Can self-grant any permission to any identity — RBAC boundary completely bypassable"},
	{keyword: "create clusterrolebinding", weight: 1.0, significance: "Can grant cluster-admin to self — single API call achieves full escalation"},
	{keyword: "impersonate", weight: 1.0, significance: "Can act as cluster-admin or any privileged identity directly"},
	{keyword: "wildcard permissions", weight: 0.9, significance: "Wildcard permissions on resources — all current and future K8s API resources accessible with all verbs"},
	{keyword: "wildcard verb", weight: 0.9, significance: "No restriction on API operations — all current and future verbs permitted"},
	{keyword: "wildcard resource", weight: 0.9, significance: "Access to all resource types including secrets, nodes, pods, configmaps"},
	{keyword: "dangerous permission", weight: 0.85, significance: "Dangerous permission combination provides an escalation path via indirect privilege abuse"},
	{keyword: "* verb", weight: 0.85, significance: "All verbs permitted — read, write, delete, exec, escalate with no restriction"},
	{keyword: "* resource", weight: 0.85, significance: "All API resources accessible — equivalent to cluster-admin scope"},
	{keyword: "token create", weight: 0.9, significance: "Can mint ServiceAccount tokens for any SA — impersonation without API server"},
	{keyword: "escalate", weight: 0.85, significance: "Can grant permissions it does not have — privilege escalation without existing access"},
	{keyword: "bind verb", weight: 0.9, significance: "Can bind any ClusterRole — including cluster-admin — to own identity"},
	{keyword: "overly permissive", weight: 0.7, significance: "Permission set exceeds operational needs — unnecessary attack surface"},
	{keyword: "excessive rbac", weight: 0.75, significance: "RBAC grants exceed operational requirements — lateral movement risk"},
}

func evalCB003(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb003Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-003", Name: "RBAC Boundary Failure",
		Boundary: "L2 — Identity Boundary", Layer: "L2",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Compromised Identity", "→ Create RoleBinding / impersonate / token create", "→ Escalate to cluster-admin", "→ Full cluster control"},
			Description: "RBAC permissions allow an identity to escalate privileges beyond their intended scope.",
		},
		Impact:      []string{"cluster-admin escalation", "unrestricted API access", "full cluster takeover"},
		Remediation: "Apply principle of least privilege. Audit roles with wildcard verbs/resources. Remove escalate/bind/impersonate from non-admin roles. Use TokenRequest API instead of long-lived tokens.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB003,
	}
}

// ── CB-004: ServiceAccount Trust Failure ─────────────────────

var cb004Signals = []signalDef{
	{keyword: "automount", weight: 0.75, significance: "Token available in every container — exposed to any code running inside the pod"},
	{keyword: "default service account", weight: 0.5, significance: "Default SA used — requires corroboration with permission evidence to confirm exploitation path"},
	{keyword: "mounted service account", weight: 0.85, significance: "SA token mounted in pod that does not require API access — unnecessary credential exposure"},
	{keyword: "service account token", weight: 0.7, significance: "SA token present and readable from pod filesystem — exfiltrable if SA has permissions"},
	{keyword: "excessive sa", weight: 0.85, significance: "SA permissions beyond pod's operational needs — enables API abuse if pod is compromised"},
	{keyword: "secret read", weight: 0.7, significance: "SA can read secrets — credential theft possible via API without container exec"},
	{keyword: "service account permissions", weight: 0.75, significance: "SA has permissions inconsistent with workload function — attack surface expansion"},
	{keyword: "workload identity", weight: 0.65, significance: "Cloud workload identity misconfiguration may bridge cluster and cloud IAM"},
}

func evalCB004(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb004Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	// Require at least one strong signal (weight >= 0.85) to prevent firing on
	// "uses default SA + automount" alone, which doesn't prove a permissions exploit path.
	hasStrongSignal := false
	for _, m := range matched {
		if m.def.weight >= 0.85 {
			hasStrongSignal = true
			break
		}
	}
	if !hasStrongSignal {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-004", Name: "ServiceAccount Trust Failure",
		Boundary: "L2 — Identity Boundary", Layer: "L2",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Compromised Pod", "→ Auto-mounted SA token", "→ Kubernetes API with excessive permissions", "→ List/read secrets", "→ Lateral movement"},
			Description: "Workload identity (ServiceAccount) carries excessive API permissions or is auto-mounted in pods that do not need it.",
		},
		Impact:      []string{"API abuse via stolen SA token", "secret exfiltration", "privilege escalation via SA permissions"},
		Remediation: "Set automountServiceAccountToken:false on pods that don't need API access. Create dedicated minimal-permission SAs per workload. Avoid using default SA.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB004,
	}
}

// ── CB-005: Admission Control Failure ────────────────────────

var cb005Signals = []signalDef{
	// NOTE: "admission" must come before more specific keywords to avoid substring double-match.
	// "policy" is intentionally excluded — it causes false positives on network/image policy findings.
	{keyword: "no admission", weight: 1.0, significance: "No admission webhook found — any user with pod/create can deploy privileged containers"},
	{keyword: "missing admission", weight: 1.0, significance: "Admission control absent — the last prevention layer before container escape is missing"},
	{keyword: "privileged workload allowed", weight: 1.0, significance: "Admission control explicitly permits privileged workloads — CB-001 risk is unblocked"},
	{keyword: "admission policy engine", weight: 1.0, significance: "No policy engine (Kyverno/OPA/Gatekeeper) configured — privileged workload deployment is unrestricted"},
	{keyword: "pod security admission", weight: 0.85, significance: "Pod Security Admission configuration issue — enforcement level may permit privileged workloads"},
	{keyword: "admission webhook", weight: 0.8, significance: "Admission webhook misconfiguration — failurePolicy:Ignore or short timeout can cause policy bypass"},
	{keyword: "kyverno", weight: 0.8, significance: "Kyverno policy gap — verify deny-privileged policies cover all namespaces with no exclusion bypass"},
	{keyword: "gatekeeper", weight: 0.8, significance: "OPA Gatekeeper gap — verify ConstraintTemplates enforce privileged workload denial across all namespaces"},
	{keyword: "opa", weight: 0.75, significance: "OPA policy engine gap — audit for namespace exclusions and bypass paths"},
}

func evalCB005(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb005Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-005", Name: "Admission Control Failure",
		Boundary: "L3 — Control Plane Boundary", Layer: "L3",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Attacker submits privileged workload manifest", "→ No admission webhook rejects it", "→ Privileged pod scheduled", "→ Container escape path open"},
			Description: "Policy enforcement layer (Kyverno/OPA/PSA) is absent, misconfigured, or bypassable, allowing unauthorized privileged workloads.",
		},
		Impact:      []string{"policy bypass", "unauthorized privileged workload deployment", "undetected privilege escalation"},
		Remediation: "Deploy Kyverno or OPA Gatekeeper with a deny-privileged baseline policy. Enable Pod Security Admission at restricted or baseline level. Audit namespace exclusions.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB005,
	}
}

// ── CB-006: Node Trust Failure ────────────────────────────────

var cb006Signals = []signalDef{
	{keyword: "docker.sock", weight: 1.0, significance: "Docker socket access = unconditional node root — spawn privileged container, mount host, escape"},
	{keyword: "docker socket", weight: 1.0, significance: "Docker socket access = unconditional node root — spawn privileged container, mount host, escape"},
	{keyword: "containerd.sock", weight: 1.0, significance: "Containerd socket allows creating privileged containers via CRI API — node takeover"},
	{keyword: "container socket", weight: 0.95, significance: "Container runtime socket grants control over all containers and images on the node"},
	{keyword: "cri socket", weight: 0.9, significance: "CRI socket access bypasses Kubernetes API server authorization — direct node runtime control"},
	{keyword: "hostpath", weight: 0.65, significance: "Host path mount exposes node filesystem — sensitive files readable without socket access"},
	{keyword: "host path", weight: 0.65, significance: "Host path mount exposes node filesystem — sensitive files readable without socket access"},
	{keyword: "hostpid", weight: 0.75, significance: "Host PID namespace exposes all node processes — attach to kubelet or containerd directly"},
	{keyword: "node filesystem", weight: 0.7, significance: "Node filesystem access enables reading kubeconfig, certificates, or container layers"},
}

func evalCB006(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb006Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-006", Name: "Node Trust Failure",
		Boundary: "L4 — Infrastructure Boundary", Layer: "L4",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Compromised Container", "→ Access docker.sock / containerd.sock", "→ Spawn new privileged container", "→ Mount host filesystem", "→ Node root"},
			Description: "Workload has access to node-level execution interfaces (container runtime sockets, host PID namespace) enabling full node compromise.",
		},
		Impact:      []string{"node root access", "kernel-level code execution", "all pods on node compromised"},
		Remediation: "Never mount /var/run/docker.sock or /run/containerd/containerd.sock in workloads. Disable hostPID. Use read-only rootfs. Apply seccomp/AppArmor profiles.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB006,
	}
}

// ── CB-007: Secret Exposure Chain Failure ────────────────────

var cb007Signals = []signalDef{
	{keyword: "plaintext secret", weight: 1.0, significance: "Credential stored unencrypted — any reader of the resource has immediate access"},
	{keyword: "hardcoded secret", weight: 1.0, significance: "Credential embedded in manifest — version control, audit logs, and etcd snapshots expose it"},
	{keyword: "secret in environment", weight: 0.85, significance: "Secret value exposed as env var — readable from process list, container inspect, or crash dumps"},
	{keyword: "sensitive environment", weight: 0.85, significance: "Sensitive data in environment variables is visible to all processes in the container"},
	{keyword: "secret exposed", weight: 0.9, significance: "Secret value directly accessible without additional exploitation steps"},
	{keyword: "secrets read", weight: 0.85, significance: "RBAC grants read access to secret values — credentials exfiltrable via API without pod exec (matches 'Secrets Read Access Granted')"},
	{keyword: "secrets list", weight: 0.85, significance: "RBAC allows listing secrets — attacker can enumerate all credential names in namespace or cluster"},
	{keyword: "list secrets", weight: 0.85, significance: "RBAC allows listing secrets — attacker can enumerate all credentials in namespace or cluster"},
	{keyword: "list/watch access", weight: 0.8, significance: "List/Watch RBAC on secrets enables continuous credential monitoring by a compromised workload"},
	{keyword: "read secrets", weight: 0.85, significance: "RBAC allows reading secret values — credentials exfiltrable via API without pod exec"},
	{keyword: "secret access", weight: 0.75, significance: "Unrestricted secret access enables credential theft affecting downstream systems"},
	{keyword: "exec", weight: 0.75, significance: "Pod exec permission grants interactive shell access — mounted secrets and env vars directly readable"},
}

func evalCB007(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb007Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-007", Name: "Secret Exposure Chain Failure",
		Boundary: "L2 — Identity Boundary", Layer: "L2",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"RBAC traversal or exec access", "→ List / read secrets", "→ Extract database credentials / API keys", "→ Lateral movement to external systems"},
			Description: "Secrets can be indirectly accessed through RBAC traversal, exec into privileged pods, or SA overreach.",
		},
		Impact:      []string{"credential theft", "lateral movement to databases/APIs", "persistent access via stolen keys"},
		Remediation: "Use external secret stores (Vault, AWS Secrets Manager). Restrict RBAC to minimum required secrets. Enable secret encryption at rest. Rotate all exposed credentials.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB007,
	}
}

// ── CB-008: CI/CD Trust Failure ───────────────────────────────

var cb008Signals = []signalDef{
	// Live signal — pulling from an unknown registry is a concrete supply-chain
	// injection vector and is rare enough to be a meaningful boundary signal.
	// NOTE: digest-pinning ("Image Not Pinned to Digest") is deliberately NOT a
	// signal here — it fires on almost every tagged image, so accumulating it
	// across workloads would falsely trip this break on healthy clusters.
	{keyword: "untrusted registry", weight: 0.75, significance: "Image pulled from an unknown registry — a poisoned image at that registry executes with the workload's identity (supply-chain injection)"},
	// Aspirational signals — match if a scanner emits CI/CD pipeline findings.
	{keyword: "argocd", weight: 0.9, significance: "ArgoCD SA typically has cluster-wide deploy permissions — compromise enables arbitrary workload injection"},
	{keyword: "argo cd", weight: 0.9, significance: "ArgoCD SA typically has cluster-wide deploy permissions — compromise enables arbitrary workload injection"},
	{keyword: "flux", weight: 0.85, significance: "Flux controller SA has write access to all managed namespaces — supply chain entry point"},
	{keyword: "github action", weight: 0.85, significance: "GitHub Actions secrets may contain cluster credentials — external trust boundary into cluster"},
	{keyword: "ci/cd", weight: 0.75, significance: "CI/CD pipeline credentials bridge external SCM trust into cluster deployment authority"},
	{keyword: "deployment token", weight: 0.8, significance: "Long-lived deployment token in pipeline — theft enables cluster access without cluster knowledge"},
	{keyword: "pipeline", weight: 0.65, significance: "Pipeline infrastructure carries cluster credentials — external compromise = cluster breach"},
	{keyword: "gitops", weight: 0.75, significance: "GitOps controller SA has cluster-write permissions — repository compromise = cluster compromise"},
	{keyword: "registry credential", weight: 0.7, significance: "Registry pull secret in cluster enables image substitution — malicious image injection vector"},
}

func evalCB008(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb008Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-008", Name: "Supply Chain & CI/CD Trust Failure",
		Boundary: "L3 — Control Plane Boundary", Layer: "L3",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Untrusted / poisoned image (or compromised CI/CD pipeline)", "→ Workload runs unverified code", "→ Code abuses the workload's mounted SA token / pipeline credentials", "→ Cluster takeover"},
			Description: "Workloads run images from untrusted registries — or are deployed by pipelines carrying cluster credentials — giving a supply-chain foothold that executes with the workload's identity.",
		},
		Impact:      []string{"supply chain compromise", "malicious image injection", "cluster takeover via workload identity"},
		Remediation: "Pull images only from trusted registries and pin to digests; sign and verify images (Cosign/Sigstore) via an admission policy. Restrict ArgoCD/Flux RBAC to minimum namespaces and use short-lived OIDC workload identity instead of long-lived tokens.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB008,
	}
}

// ── CB-009: Multi-Tenant Isolation Failure ────────────────────

var cb009Signals = []signalDef{
	// Live signals — match real scanner finding titles that prove tenant bleed-through.
	{keyword: "cross-namespace", weight: 0.8, significance: "Cross-namespace ServiceAccount binding or ingress bridges tenant boundaries — a workload in Tenant A can act on or reach Tenant B"},
	{keyword: "cross-namespace network", weight: 0.8, significance: "Missing cross-namespace network isolation lets any namespace reach this one — no tenant segmentation at the network layer"},
	// Aspirational signals (match if a future scanner emits these phrasings).
	{keyword: "shared service account", weight: 0.85, significance: "Shared SA identity bridges tenant boundaries — Tenant A can act as Tenant B"},
	{keyword: "shared controller", weight: 0.8, significance: "Shared operator/controller with cross-namespace access collapses tenant isolation"},
	{keyword: "cluster-scoped", weight: 0.75, significance: "Cluster-scoped permission granted to tenant workload — breaks intended tenant boundary"},
	{keyword: "multi-tenant", weight: 0.75, significance: "Multi-tenant configuration gap — trust model assumption violated across tenant boundaries"},
	{keyword: "namespace isolation", weight: 0.75, significance: "Namespace isolation explicitly noted as broken or missing"},
	{keyword: "shared namespace", weight: 0.8, significance: "Shared namespace between tenants creates implicit trust — data and secrets co-mingled"},
}

func evalCB009(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb009Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-009", Name: "Multi-Tenant Isolation Failure",
		Boundary: "L2 — Identity Boundary", Layer: "L2",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Tenant A workload", "→ Shared SA / shared controller", "→ Cross-tenant namespace access", "→ Tenant B data / credentials"},
			Description: "Tenants are not truly isolated due to shared service accounts, cluster-scoped controllers, or permissive cross-namespace RBAC.",
		},
		Impact:      []string{"tenant escape", "cross-tenant data access", "shared infrastructure compromise"},
		Remediation: "Enforce namespace-per-tenant isolation. Create dedicated SAs per tenant. Avoid cluster-scoped operators with cross-namespace access. Use NetworkPolicies to block cross-tenant traffic.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB009,
	}
}

// ── CB-010: Cloud Identity Bridge Failure ─────────────────────

var cb010Signals = []signalDef{
	{keyword: "metadata api", weight: 1.0, significance: "Cloud metadata API reachable at 169.254.169.254 — IAM credentials retrievable via HTTP from any pod"},
	{keyword: "imds", weight: 0.95, significance: "Instance Metadata Service accessible — temporary IAM tokens obtainable without authentication"},
	{keyword: "instance metadata", weight: 1.0, significance: "Instance metadata endpoint reachable — exposes IAM role, user-data, and instance identity"},
	{keyword: "irsa", weight: 0.9, significance: "IRSA role overly permissive — SA token can assume cloud IAM role with excessive permissions"},
	{keyword: "workload identity", weight: 0.85, significance: "GCP/Azure Workload Identity misconfigured — pod can obtain cloud IAM token beyond intended scope"},
	{keyword: "iam role", weight: 0.8, significance: "IAM role attached to node/pod with excessive permissions — cloud resource access via cluster breach"},
	{keyword: "cloud credential", weight: 0.85, significance: "Cloud credentials accessible from cluster workload — Kubernetes breach enables cloud takeover"},
	{keyword: "aws credential", weight: 0.85, significance: "AWS credentials accessible — S3, IAM, EC2, and other AWS resources exposed"},
	{keyword: "gcp credential", weight: 0.85, significance: "GCP credentials accessible — GCS, GKE, IAM and other GCP resources exposed"},
	{keyword: "azure credential", weight: 0.85, significance: "Azure credentials accessible — Storage, AKS, Key Vault and Azure resources exposed"},
}

func evalCB010(findings []*core.Finding) ([]matchedSignal, *core.CapabilityBreak) {
	matched := matchSignals(findings, cb010Signals)
	conf := confidenceFromSignals(matched)
	if conf < 75 {
		return nil, nil
	}
	ev := toEvidence(matched)
	status := statusFromConfidence(conf)
	// If all matched findings are LOW severity, cap at DEGRADED — the metadata API may be
	// restricted by IMDSv2 hop-limit-1 or equivalent cloud-provider protection.
	if status == core.CBStatusBroken {
		allLow := true
		for _, m := range matched {
			if m.finding.Severity != core.SeverityLow {
				allLow = false
				break
			}
		}
		if allLow {
			status = core.CBStatusDegraded
		}
	}
	exploit := exploitFromMatched(matched)
	return matched, &core.CapabilityBreak{
		ID: "CB-010", Name: "Cloud Identity Bridge Failure",
		Boundary: "L4 — Infrastructure Boundary", Layer: "L4",
		Status: status, Confidence: conf, Exploitability: exploit,
		Evidence: ev,
		AttackGraph: core.CBAttackGraph{
			Path:        []string{"Compromised Pod", "→ Access cloud metadata API (169.254.169.254)", "→ Retrieve IAM credentials / IRSA token", "→ AWS / GCP / Azure account access", "→ Cloud infrastructure takeover"},
			Description: "Kubernetes workloads can reach cloud provider metadata APIs, bridging a cluster compromise into a full cloud account takeover.",
		},
		Impact:      []string{"AWS / GCP / Azure account takeover", "cloud data exfiltration", "infrastructure-level persistence"},
		Remediation: "Block metadata API access via NetworkPolicy (deny egress to 169.254.169.254). Use IMDSv2 on AWS with hop limit 1. Scope IRSA / Workload Identity roles to minimum required permissions.",
		FixPriority: fixPriority(status, exploit),
		MITRE:       mitreCB010,
	}
}

// allRules returns the evaluation functions for all 10 CB rules.
// Returns (matched signals, CapabilityBreak or nil if below threshold).
type ruleFunc func([]*core.Finding) ([]matchedSignal, *core.CapabilityBreak)

func allRules() []ruleFunc {
	return []ruleFunc{
		evalCB001, evalCB002, evalCB003, evalCB004, evalCB005,
		evalCB006, evalCB007, evalCB008, evalCB009, evalCB010,
	}
}
