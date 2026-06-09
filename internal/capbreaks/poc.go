package capbreaks

import (
	"fmt"
	"strings"

	"github.com/alperenkeskin/k8scan/internal/core"
)

// buildPoC generates validation commands that confirm the vulnerability exists.
// The goal is to prove the misconfiguration is real and exploitable — not to
// weaponize it. All resource names are sourced from the actual evidence findings.
func buildPoC(cbID string, evidence []core.CBEvidence) string {
	switch cbID {
	case "CB-001":
		return pocCB001(evidence)
	case "CB-002":
		return pocCB002(evidence)
	case "CB-003":
		return pocCB003(evidence)
	case "CB-004":
		return pocCB004(evidence)
	case "CB-005":
		return pocCB005(evidence)
	case "CB-006":
		return pocCB006(evidence)
	case "CB-007":
		return pocCB007(evidence)
	case "CB-008":
		return pocCB008(evidence)
	case "CB-009":
		return pocCB009(evidence)
	case "CB-010":
		return pocCB010(evidence)
	default:
		return ""
	}
}

// ── helpers ───────────────────────────────────────────────────

func firstPod(evidence []core.CBEvidence) (pod, ns string) {
	for _, e := range evidence {
		if e.ResourceName != "" {
			return e.ResourceName, e.Namespace
		}
	}
	return "<pod-name>", "<namespace>"
}

func allAffected(evidence []core.CBEvidence) string {
	nsSet := make(map[string]bool)
	var pods []string
	for _, e := range evidence {
		if e.ResourceName != "" {
			label := e.ResourceName
			if e.Namespace != "" {
				label = e.Namespace + "/" + e.ResourceName
				nsSet[e.Namespace] = true
			}
			pods = append(pods, label)
		}
	}
	if len(pods) == 0 {
		return "  Affected resources: <none detected>"
	}
	lines := []string{fmt.Sprintf("  Affected namespaces: %s", strings.Join(keys(nsSet), ", "))}
	for _, p := range pods {
		lines = append(lines, "    - "+p)
	}
	return strings.Join(lines, "\n")
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ── CB-001: Container Isolation Failure ──────────────────────

func pocCB001(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	nsFlag := ""
	if ns != "" && ns != "<namespace>" {
		nsFlag = " -n " + ns
	}
	return fmt.Sprintf(`# CB-001 — Container Isolation Failure
# Vulnerability Validation — Confirm isolation boundary is breakable
# Purpose: Verify misconfiguration exists. Does NOT exploit.

# Check 1: Confirm privileged flag or dangerous capabilities
kubectl get pod %s%s -o jsonpath='{.spec.containers[*].securityContext}' | jq .

# Check 2: Verify host namespace sharing
kubectl get pod %s%s -o jsonpath='{.spec.hostPID} {.spec.hostNetwork} {.spec.hostIPC}'
# BOUNDARY BREAKABLE if any field = "true"

# Check 3: Non-destructive isolation boundary test
kubectl exec %s%s -- ls /proc/1/root/ 2>/dev/null \
  && echo "RESULT: HOST_ACCESSIBLE — container sees node filesystem" \
  || echo "RESULT: ISOLATED — /proc/1/root not reachable"

# Check 4: Enumerate dangerous volume mounts
kubectl get pod %s%s -o jsonpath='{.spec.volumes[*]}' | jq .

%s

# CONFIRMED if: privileged=true OR hostPID/hostNetwork=true OR /proc/1/root accessible
# IMPACT: Any code in this container can reach node-level resources without kernel exploit`, pod, nsFlag, pod, nsFlag, pod, nsFlag, pod, nsFlag, allAffected(evidence))
}

// ── CB-002: Namespace Isolation Failure ──────────────────────

func pocCB002(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	return fmt.Sprintf(`# CB-002 — Namespace Isolation Failure
# Vulnerability Validation — Confirm namespace boundary provides no security
# Purpose: Verify cross-namespace RBAC access. Does NOT modify resources.

# Check 1: List cluster-wide bindings for this service account
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]? | .name == "%s") | .metadata.name'

# Check 2: Verify permission to read secrets in other namespaces
kubectl auth can-i get secrets --namespace kube-system \
  --as=system:serviceaccount:%s:%s
# BOUNDARY BROKEN if output = "yes"

# Check 3: Cross-namespace pod list capability
kubectl auth can-i list pods --all-namespaces \
  --as=system:serviceaccount:%s:%s
# BOUNDARY BROKEN if output = "yes"

# Check 4: Full RBAC permission dump for this identity
kubectl auth can-i --list --as=system:serviceaccount:%s:%s | head -20

%s

# CONFIRMED if: any cross-namespace "can-i" check returns "yes"
# IMPACT: Namespace provides organizational grouping only — not a security boundary`, pod, ns, pod, ns, pod, ns, pod, allAffected(evidence))
}

// ── CB-003: RBAC Boundary Failure ────────────────────────────

func pocCB003(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	return fmt.Sprintf(`# CB-003 — RBAC Boundary Failure
# Vulnerability Validation — Confirm privilege escalation path exists
# Purpose: Verify escalation verbs are present. Does NOT escalate.

# Check 1: Test for "escalate" verb on ClusterRoles
kubectl auth can-i escalate clusterroles \
  --as=system:serviceaccount:%s:%s
# BOUNDARY BROKEN if output = "yes"

# Check 2: Test for "bind" verb (create bindings to any role)
kubectl auth can-i bind clusterroles \
  --as=system:serviceaccount:%s:%s
# BOUNDARY BROKEN if output = "yes"

# Check 3: Test for impersonation capability
kubectl auth can-i impersonate users \
  --as=system:serviceaccount:%s:%s

# Check 4: List ClusterRoles with dangerous verbs
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]?.verbs[]? | test("^(escalate|bind|impersonate)$")) |
      {name: .metadata.name, rules: .rules}'

# Check 5: Full permission listing for this identity
kubectl auth can-i --list --as=system:serviceaccount:%s:%s

%s

# CONFIRMED if: escalate OR bind returns "yes" for this identity
# IMPACT: Single API call is sufficient to reach cluster-admin from this identity`, ns, pod, ns, pod, ns, pod, ns, pod, allAffected(evidence))
}

// ── CB-004: ServiceAccount Trust Failure ─────────────────────

func pocCB004(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	nsFlag := ""
	if ns != "" {
		nsFlag = " -n " + ns
	}
	return fmt.Sprintf(`# CB-004 — ServiceAccount Trust Failure
# Vulnerability Validation — Confirm SA token abuse is possible
# Purpose: Verify token exists and has excessive permissions. Read-only checks.

# Check 1: Confirm SA token is auto-mounted in the pod
kubectl exec %s%s -- ls /var/run/secrets/kubernetes.io/serviceaccount/
# VULNERABLE if token file is present

# Check 2: Verify token allows API server queries
kubectl exec %s%s -- sh -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  APISERVER=https://kubernetes.default.svc
  CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces" -o /dev/null -w "HTTP %%{http_code}\n"
'
# VULNERABLE if HTTP 200 is returned

# Check 3: Enumerate API permissions held by this SA token
kubectl auth can-i --list \
  --as=system:serviceaccount:%s:%s | grep -v "^no\b" | head -20

# Check 4: Test secret access capability
kubectl auth can-i list secrets%s \
  --as=system:serviceaccount:%s:%s
# VULNERABLE if output = "yes"

%s

# CONFIRMED if: token auto-mounted AND API access succeeds AND permissions exceed operational needs
# IMPACT: Any code in affected pods — including injected libraries — inherits these permissions`, pod, nsFlag, pod, nsFlag, ns, pod, nsFlag, ns, pod, allAffected(evidence))
}

// ── CB-005: Admission Control Failure ────────────────────────

func pocCB005(evidence []core.CBEvidence) string {
	_, ns := firstPod(evidence)
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf(`# CB-005 — Admission Control Failure
# Vulnerability Validation — Confirm policy engine cannot block privileged pods
# Purpose: Verify policy gap exists. Dry-run only — no actual deployment.

# Check 1: List active admission webhooks
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations
# VULNERABLE if no Kyverno/OPA/Gatekeeper webhook is listed

# Check 2: Check PodSecurity admission on namespace
kubectl get namespace %s -o json | \
  jq '.metadata.labels | with_entries(select(.key | startswith("pod-security")))'
# VULNERABLE if no pod-security labels are set (empty result)

# Check 3: Dry-run a privileged pod manifest — does policy block it?
kubectl apply --dry-run=server -n %s -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: validation-check-dryrun
spec:
  containers:
  - name: check
    image: alpine
    securityContext:
      privileged: true
EOF
# BOUNDARY BROKEN if dry-run succeeds (no admission webhook rejects it)

# Check 4: Verify if any PSA enforcing mode is active cluster-wide
kubectl get namespaces -o json | \
  jq '[.items[] | {name:.metadata.name, psa:.metadata.labels} |
      select(.psa | keys[] | startswith("pod-security")) ] | length'
# VULNERABLE if count is 0 (no namespaces have PSA enforcement)

%s

# CONFIRMED if: no webhook present AND dry-run admits privileged pod
# IMPACT: CB-001 risks are structurally unblocked — any user with pod/create can escape`, ns, ns, allAffected(evidence))
}

// ── CB-006: Node Trust Failure ────────────────────────────────

func pocCB006(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	nsFlag := ""
	if ns != "" {
		nsFlag = " -n " + ns
	}
	return fmt.Sprintf(`# CB-006 — Node Trust Failure
# Vulnerability Validation — Confirm container runtime socket is accessible
# Purpose: Verify socket mount exists. Does NOT spawn containers.

# Check 1: Verify docker/containerd socket mount in pod spec
kubectl get pod %s%s -o jsonpath='{.spec.volumes}' | \
  jq '.[] | select(.hostPath.path | test("docker.sock|containerd.sock|cri.sock"))'
# VULNERABLE if any matching volume is found

# Check 2: Confirm socket is accessible from inside the container
kubectl exec %s%s -- ls -la \
  /var/run/docker.sock \
  /run/containerd/containerd.sock \
  /run/cri-dockerd.sock 2>/dev/null
# VULNERABLE if socket file is visible

# Check 3: Verify socket is usable (read-only API query, no modification)
kubectl exec %s%s -- sh -c \
  'docker -H unix:///var/run/docker.sock version 2>/dev/null | head -3 || echo "docker unavailable"'

# Check 4: Confirm containerd socket access
kubectl exec %s%s -- sh -c \
  'ctr -a /run/containerd/containerd.sock version 2>/dev/null | head -3 || echo "ctr unavailable"'

%s

# CONFIRMED if: socket file accessible AND API query succeeds
# IMPACT: Socket access enables spawning privileged containers via CRI, bypassing Kubernetes RBAC entirely`, pod, nsFlag, pod, nsFlag, pod, nsFlag, pod, nsFlag, allAffected(evidence))
}

// ── CB-007: Secret Exposure Chain Failure ────────────────────

func pocCB007(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	nsFlag := ""
	if ns != "" {
		nsFlag = " -n " + ns
	}
	return fmt.Sprintf(`# CB-007 — Secret Exposure Chain Failure
# Vulnerability Validation — Confirm secrets are reachable via RBAC or exec
# Purpose: Verify access path exists. Lists secret names only — no value disclosure.

# Check 1: Verify RBAC grants secret list/get to this identity
kubectl auth can-i list secrets%s \
  --as=system:serviceaccount:%s:%s
# VULNERABLE if output = "yes"

kubectl auth can-i get secrets%s \
  --as=system:serviceaccount:%s:%s

# Check 2: Count accessible secrets (names only, no values)
kubectl get secrets%s \
  --as=system:serviceaccount:%s:%s \
  -o name 2>/dev/null | wc -l
# VULNERABLE if count > 0

# Check 3: Check for credential material in environment variables (read-only)
kubectl exec %s%s -- env | grep -ciE 'password|secret|token|key|api|db|cred'
# VULNERABLE if count > 0

# Check 4: Check for mounted secret volumes
kubectl exec %s%s -- find /var/run/secrets /etc/secrets -maxdepth 2 -type f 2>/dev/null | head -10
# Lists mounted secret file paths — does NOT read their contents

%s

# CONFIRMED if: secret list/get RBAC returns "yes" OR env leak detected OR secret volume mounted
# IMPACT: Credential theft is possible without container escape — pure API or config-level access`, nsFlag, ns, pod, nsFlag, ns, pod, nsFlag, ns, pod, pod, nsFlag, pod, nsFlag, allAffected(evidence))
}

// ── CB-008: CI/CD Trust Failure ───────────────────────────────

func pocCB008(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	return fmt.Sprintf(`# CB-008 — CI/CD Trust Failure
# Vulnerability Validation — Confirm pipeline has excessive cluster write access
# Purpose: Check permission scope. Does NOT deploy or modify workloads.

# Check 1: Identify CI/CD service accounts and their cluster permissions
kubectl get serviceaccounts -A | grep -iE 'argocd|flux|gitops|deploy|cd|ci'

# Check 2: Check ArgoCD/Flux SA cluster-write permissions
kubectl auth can-i create pods \
  --as=system:serviceaccount:%s:%s
kubectl auth can-i create deployments \
  --as=system:serviceaccount:%s:%s
# VULNERABLE if either returns "yes"

# Check 3: Check for cluster-admin or edit ClusterRoleBinding
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]? | .namespace == "%s") |
      {name:.metadata.name, role:.roleRef.name}'

# Check 4: Check ArgoCD sync scope (cluster-wide vs namespaced)
kubectl get applications -n argocd -o json 2>/dev/null | \
  jq '.items[] | {name:.metadata.name, dest:.spec.destination}' | head -20

%s

# CONFIRMED if: pipeline SA has pod/deployment create OR cluster-admin binding
# IMPACT: Supply chain attack on repository/pipeline → direct cluster write access`, ns, pod, ns, pod, ns, allAffected(evidence))
}

// ── CB-009: Multi-Tenant Isolation Failure ────────────────────

func pocCB009(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	return fmt.Sprintf(`# CB-009 — Multi-Tenant Isolation Failure
# Vulnerability Validation — Confirm tenant isolation model is broken
# Purpose: Verify shared identity bridges tenant boundaries. Read-only.

# Check 1: List ClusterRoleBindings that span multiple tenant namespaces
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects | length > 0) |
      {name:.metadata.name, ns:[.subjects[].namespace] | unique, role:.roleRef.name}'

# Check 2: Confirm this SA can access resources in non-owner namespaces
kubectl auth can-i get pods --namespace default \
  --as=system:serviceaccount:%s:%s
kubectl auth can-i get secrets --all-namespaces \
  --as=system:serviceaccount:%s:%s
# BOUNDARY BROKEN if either returns "yes"

# Check 3: Identify shared controllers with cluster-scoped permissions
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]?.resources[]? == "*") |
      {name:.metadata.name, verbs:[.rules[].verbs] | flatten | unique}'

# Check 4: Check if multiple tenant namespaces share this SA
kubectl get rolebindings -A -o json | \
  jq '.items[] | select(.subjects[]?.name == "%s") |
      {namespace:.metadata.namespace, role:.roleRef.name}'

%s

# CONFIRMED if: SA has cross-namespace access OR ClusterRoleBinding spans multiple tenants
# IMPACT: Tenant A workload can interact with Tenant B resources through shared infrastructure`, ns, pod, ns, pod, pod, allAffected(evidence))
}

// ── CB-010: Cloud Identity Bridge Failure ─────────────────────

func pocCB010(evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	nsFlag := ""
	if ns != "" {
		nsFlag = " -n " + ns
	}
	return fmt.Sprintf(`# CB-010 — Cloud Identity Bridge Failure
# Vulnerability Validation — Confirm cloud metadata API is reachable
# Purpose: Verify IMDS reachability. Confirms IAM role name only — no credential retrieval.

# Check 1: Test metadata API reachability (connection only, no data)
kubectl exec %s%s -- sh -c \
  'curl -s -m 3 -o /dev/null -w "HTTP %%{http_code}" http://169.254.169.254/latest/meta-data/'
# BOUNDARY BROKEN if HTTP 200 is returned

# Check 2: AWS — read IAM role name (no secret values, just role identity)
kubectl exec %s%s -- sh -c \
  'curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || echo "NOT_AWS"'
# VULNERABLE if a role name is returned

# Check 3: GCP — check metadata endpoint reachability
kubectl exec %s%s -- sh -c \
  'curl -s -m 3 -o /dev/null -w "HTTP %%{http_code}" \
    -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/ 2>/dev/null || echo "NOT_GCP"'
# VULNERABLE if HTTP 200 is returned

# Check 4: Verify NetworkPolicy is absent (no egress restriction to 169.254.169.254)
kubectl get networkpolicies%s -o json | \
  jq '.items[] | select(.spec.egress != null) |
      {name:.metadata.name, egress:.spec.egress}' 2>/dev/null | head -20
# SAFER if a NetworkPolicy explicitly denies 169.254.169.254 egress

%s

# CONFIRMED if: HTTP 200 from metadata endpoint
# IMPACT: Cluster breach extends to cloud infrastructure — IAM credentials retrievable via plain HTTP`, pod, nsFlag, pod, nsFlag, pod, nsFlag, nsFlag, allAffected(evidence))
}
