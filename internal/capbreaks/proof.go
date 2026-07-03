package capbreaks

import (
	"fmt"

	"github.com/alperenkesk/k8scan/internal/core"
)

// buildValidationProof constructs a deterministic, explainable proof of why
// a security boundary is considered broken. Each matched signal is annotated
// with its significance, and a combined verdict explains how they together
// prove the boundary failure.
func buildValidationProof(cbID string, matched []matchedSignal) core.ValidationProof {
	signals := make([]core.ProofSignal, 0, len(matched))
	seenFindings := make(map[int]bool)

	for _, m := range matched {
		if seenFindings[m.finding.FindingID] {
			continue
		}
		seenFindings[m.finding.FindingID] = true

		resource := m.finding.ResourceName
		if m.finding.Namespace != "" {
			resource = m.finding.Namespace + "/" + m.finding.ResourceName
		}

		sig := m.def.significance
		if sig == "" {
			sig = "Security signal contributing to boundary failure"
		}

		signals = append(signals, core.ProofSignal{
			Title:        m.finding.Title,
			Resource:     resource,
			Severity:     string(m.finding.Severity),
			Significance: sig,
			Weight:       m.def.weight,
		})
	}

	verdict, combined := buildVerdict(cbID, signals)
	return core.ValidationProof{
		Verdict:  verdict,
		Signals:  signals,
		Combined: combined,
	}
}

func buildVerdict(cbID string, signals []core.ProofSignal) (verdict, combined string) {
	count := len(signals)
	if count == 0 {
		return "INSUFFICIENT EVIDENCE", "No matching signals found."
	}

	critCount := 0
	for _, s := range signals {
		if s.Severity == "CRITICAL" {
			critCount++
		}
	}

	switch cbID {
	case "CB-001":
		if critCount > 0 {
			verdict = fmt.Sprintf("BOUNDARY BROKEN — %d independent container escape vector(s) confirmed", count)
			combined = fmt.Sprintf(
				"%d finding(s) independently allow container-to-node escape. "+
					"An attacker in ANY of these containers can reach node-level access "+
					"without additional exploitation steps. Each signal is individually sufficient "+
					"— together they represent multiple parallel escape paths.",
				count)
		} else {
			verdict = fmt.Sprintf("BOUNDARY DEGRADED — %d elevated privilege signal(s) weaken isolation", count)
			combined = "Configuration weakens container isolation. Exploitation may require " +
				"a specific kernel version or additional misconfiguration, but the attack " +
				"surface is materially larger than a hardened baseline."
		}
	case "CB-002":
		// Even a single cluster-scoped binding logically breaks namespace isolation.
		// The proof verdict reflects the logical claim; status badge reflects signal confidence.
		if count >= 2 {
			verdict = fmt.Sprintf("BOUNDARY BROKEN — namespace isolation bypassed via %d cluster-scoped signal(s)", count)
		} else {
			verdict = "BOUNDARY PERMEABLE — cluster-scoped permission found (namespace isolation not enforced)"
		}
		combined = "ClusterRoleBinding(s) or wildcard RBAC permissions allow cross-namespace " +
			"resource access. The namespace boundary provides no security guarantee in this cluster — " +
			"it is an organizational label, not a security boundary."
	case "CB-003":
		verdict = fmt.Sprintf("BOUNDARY BROKEN — %d RBAC privilege escalation path(s) confirmed", count)
		combined = "The identity model allows self-escalation to cluster-admin without " +
			"external action. An attacker who compromises any workload with these permissions " +
			"can obtain unrestricted cluster control in a single API call."
	case "CB-004":
		verdict = fmt.Sprintf("BOUNDARY DEGRADED — %d ServiceAccount trust violation(s)", count)
		combined = "Workload identities carry permissions beyond their operational needs. " +
			"Any code running inside the affected pods — including injected libraries or " +
			"compromised dependencies — can abuse these permissions via the mounted SA token."
	case "CB-005":
		// Admission control absence is a structural failure — use BROKEN when evidence is strong.
		if count >= 2 {
			verdict = fmt.Sprintf("BOUNDARY BROKEN — admission enforcement absent, %d gaps confirmed", count)
		} else {
			verdict = fmt.Sprintf("BOUNDARY DEGRADED — admission enforcement absent or bypassable (%d signal(s))", count)
		}
		combined = "The admission control layer cannot prevent deployment of privileged workloads. " +
			"CB-001 (Container Isolation Failure) risks are structurally unblocked — " +
			"any user with pod/create can deploy a container escape vector."
	case "CB-006":
		verdict = fmt.Sprintf("BOUNDARY BROKEN — node runtime interface directly exposed (%d signal(s))", count)
		combined = "Container runtime socket access enables spawning new privileged containers " +
			"via the node's CRI API, completely bypassing Kubernetes RBAC. " +
			"This is an unconditional path to node root — no kernel exploit required."
	case "CB-007":
		verdict = fmt.Sprintf("BOUNDARY BROKEN — %d secret exfiltration path(s) confirmed", count)
		combined = "Secrets are reachable via RBAC traversal, exec access, or environment " +
			"variable exposure. Credential theft is possible without container escape — " +
			"these are pure API-level or configuration-level attacks."
	case "CB-008":
		verdict = fmt.Sprintf("BOUNDARY DEGRADED — CI/CD pipeline carries cluster trust (%d signal(s))", count)
		combined = "Deployment pipeline credentials have cluster-level write access. " +
			"A supply chain attack targeting the repository, pipeline config, or registry " +
			"would gain cluster control without any direct cluster access."
	case "CB-009":
		verdict = fmt.Sprintf("BOUNDARY DEGRADED — %d tenant isolation failure(s)", count)
		combined = "Shared identities or cluster-scoped controllers bridge tenant trust boundaries. " +
			"The multi-tenant isolation model is violated — Tenant A workloads can interact " +
			"with Tenant B resources through shared infrastructure."
	case "CB-010":
		// Mirror evalCB010's all-LOW cap: if no signal is above LOW severity the
		// metadata path may be restricted (IMDSv2 hop-limit-1), so the boundary is
		// degraded, not proven broken.
		aboveLow := false
		for _, s := range signals {
			if s.Severity != "LOW" && s.Severity != "INFO" {
				aboveLow = true
				break
			}
		}
		if aboveLow {
			verdict = fmt.Sprintf("BOUNDARY BROKEN — cloud metadata API reachable from %d workload(s)", count)
		} else {
			verdict = fmt.Sprintf("BOUNDARY DEGRADED — cloud metadata exposure likely, but may be restricted by IMDSv2 (%d signal(s))", count)
		}
		combined = "Cloud provider IAM credentials are retrievable via plain HTTP from any pod " +
			"in the affected namespaces. A cluster breach immediately extends to cloud " +
			"infrastructure — no cloud-level exploit is required."
	default:
		verdict = fmt.Sprintf("BOUNDARY FAILURE — %d evidence signal(s) detected", count)
		combined = "Multiple security signals confirm this boundary failure."
	}
	return
}
