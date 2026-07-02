package scanners

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/alperenkeskin/k8scan/internal/core"
	"github.com/alperenkeskin/k8scan/internal/utils"
)

// RBACScanner checks Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings.
type RBACScanner struct{}

func (RBACScanner) Name() string { return "RBAC Security" }

func (RBACScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	pods, err := client.GetAllPods(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := client.GetAllRoles(ctx)
	if err != nil {
		return nil, err
	}
	clusterRoles, err := client.GetAllClusterRoles(ctx)
	if err != nil {
		return nil, err
	}
	roleBindings, err := client.GetAllRoleBindings(ctx)
	if err != nil {
		return nil, err
	}
	clusterRoleBindings, err := client.GetAllClusterRoleBindings(ctx)
	if err != nil {
		return nil, err
	}

	var findings []*core.Finding

	for _, role := range roles {
		findings = append(findings, checkRole(role.Rules, role.Name, role.Namespace, "Role")...)
	}
	for _, cr := range clusterRoles {
		findings = append(findings, checkRole(cr.Rules, cr.Name, "", "ClusterRole")...)
	}

	for _, rb := range roleBindings {
		findings = append(findings, checkRoleBinding(rb.Subjects, rb.RoleRef, rb.Name, rb.Namespace)...)
	}
	for _, crb := range clusterRoleBindings {
		findings = append(findings, checkClusterRoleBinding(crb.Subjects, crb.RoleRef, crb.Name)...)
	}

	serviceAccounts, err := client.GetAllServiceAccounts(ctx)
	if err != nil {
		return nil, err
	}

	findings = append(findings, checkDefaultSADangerousPerms(roleBindings, clusterRoleBindings, roles, clusterRoles)...)
	findings = append(findings, checkDefaultSAUsedByPods(pods)...)
	findings = append(findings, checkUnusedServiceAccounts(serviceAccounts, pods)...)
	findings = append(findings, checkLegacySATokenMount(pods)...)
	findings = append(findings, checkPrivilegedSABoundToWorkload(pods, roleBindings, clusterRoleBindings, roles, clusterRoles)...)

	return findings, nil
}

// ─── Role checks ──────────────────────────────────────────────────────────────

type permCombo struct {
	verbs     []string
	resources []string
	title     string
}

var dangerousCombos = []permCombo{
	{[]string{"create", "update", "patch"}, []string{"pods"}, "create/update pods"},
	{[]string{"create"}, []string{"deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"}, "create workloads"},
	{[]string{"bind", "escalate"}, []string{"roles", "clusterroles"}, "bind/escalate roles"},
	{[]string{"impersonate"}, []string{"users", "groups", "serviceaccounts"}, "impersonate identities"},
	{[]string{"create"}, []string{"persistentvolumeclaims"}, "create PVCs"},
	{[]string{"delete"}, []string{"nodes"}, "delete nodes"},
	{[]string{"delete"}, []string{"persistentvolumes"}, "delete persistent volumes"},
	{[]string{"create"}, []string{"serviceaccounts/token"}, "create SA tokens"},
	{[]string{"patch", "update"}, []string{"nodes"}, "patch nodes"},
	{[]string{"create", "patch", "update"}, []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}, "modify admission webhooks"},
}

func checkRole(rules []rbacv1.PolicyRule, roleName, namespace, resourceType string) []*core.Finding {
	var findings []*core.Finding

	if isSystemRole(roleName) {
		return nil
	}

	// Per-role deduplication: each check fires at most once per role regardless
	// of how many policy rules match. Roles like 'edit' have dozens of rules
	// and would otherwise produce duplicate findings for the same issue.
	wildcardReported := false
	execReported := false
	secretsReported := false
	allCombos := utils.NewStringSet()

	for _, rule := range rules {
		verbSet := utils.NewStringSet(rule.Verbs...)
		resourceSet := utils.NewStringSet(rule.Resources...)

		// Wildcard permissions — report once per role
		// Distinguish: wildcard verbs (full control) vs wildcard resources with limited verbs (read-only access to all types)
		if !wildcardReported && (verbSet.Has("*") || resourceSet.Has("*")) {
			wildcardReported = true
			ns := namespace
			if ns == "" {
				ns = "cluster-wide"
			}
			if verbSet.Has("*") {
				// Full wildcard: both verbs and resources — CRITICAL
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityCritical,
					Category:     "rbac",
					Title:        "Wildcard Permissions Granted",
					Description:  fmt.Sprintf("%s '%s' grants wildcard (*) verbs on all resources. This allows full create/read/update/delete control over every resource type.", resourceType, roleName),
					ResourceType: resourceType,
					ResourceName: roleName,
					Namespace:    ns,
					Remediation:  "Replace wildcards with specific verbs and resources following the principle of least privilege.",
				})
			} else {
				// Wildcard resources but limited verbs — HIGH (read all resource types)
				verbs := strings.Join(rule.Verbs, ", ")
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "rbac",
					Title:        "Wildcard Resource Access Granted",
					Description:  fmt.Sprintf("%s '%s' grants access to all resource types (*) with verbs [%s]. Any new resource type added to the cluster is automatically accessible.", resourceType, roleName, verbs),
					ResourceType: resourceType,
					ResourceName: roleName,
					Namespace:    ns,
					Remediation:  "Replace the wildcard resource (*) with an explicit list of resource types the role actually needs.",
				})
			}
		}

		// Pod exec — report once per role
		if !execReported && (verbSet.Has("create") || verbSet.Has("*")) && (resourceSet.Has("pods/exec") || resourceSet.Has("*")) {
			execReported = true
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "rbac",
				Title:        "Pod Exec Permission Granted",
				Description:  fmt.Sprintf("%s '%s' allows 'create pods/exec' — enables direct command execution inside any pod.", resourceType, roleName),
				ResourceType: resourceType,
				ResourceName: roleName,
				Namespace:    namespace,
				Remediation:  "Remove pods/exec permission unless strictly required. Restrict to specific namespaces/pods if needed.",
			})
		}

		if !secretsReported && hasVerbForResource(rule, []string{"get"}, "secrets") {
			secretsReported = true
			title := "Secrets Read Access Granted"
			desc := fmt.Sprintf("%s '%s' can read Kubernetes secrets — exposes all credentials stored as secrets.", resourceType, roleName)
			remediation := "Restrict secrets access to only the specific secrets the workload needs via resourceNames."
			// No resourceNames scoping → access to ALL secrets in namespace
			if len(rule.ResourceNames) == 0 {
				desc += " No resourceNames restriction — all secrets in scope are accessible."
				remediation = "Add resourceNames to restrict to specific secret names. Grant access only to the secrets the workload actually needs."
			}
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "rbac",
				Title:        title,
				Description:  desc,
				ResourceType: resourceType,
				ResourceName: roleName,
				Namespace:    namespace,
				Remediation:  remediation,
			})
		}

		// list/watch without get still leaks all secret names and metadata
		if !secretsReported && hasVerbForResource(rule, []string{"list", "watch"}, "secrets") {
			secretsReported = true
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "rbac",
				Title:        "Secrets List/Watch Access Granted",
				Description:  fmt.Sprintf("%s '%s' can list/watch secrets — even without 'get', an attacker can enumerate all secret names, namespaces, and metadata.", resourceType, roleName),
				ResourceType: resourceType,
				ResourceName: roleName,
				Namespace:    namespace,
				Remediation:  "Remove list/watch on secrets. If needed, restrict to specific secret names using resourceNames.",
			})
		}

		if hasVerbForResource(rule, []string{"update", "patch"}, "nodes/status") {
			allCombos.Add("update nodes/status")
		}
		if verbSet.Has("proxy") || verbSet.Has("*") {
			allCombos.Add("proxy verb (service tunnel)")
		}
		if verbSet.Has("escalate") {
			allCombos.Add("escalate roles (privilege escalation)")
		}

		// Dangerous combinations — accumulate across all rules, emit once at end
		for _, combo := range dangerousCombos {
			if allCombos.Has(combo.title) {
				continue
			}
			verbsMatch := false
			resourcesMatch := false
			for _, v := range combo.verbs {
				if verbSet.Has(v) || verbSet.Has("*") {
					verbsMatch = true
					break
				}
			}
			for _, r := range combo.resources {
				if resourceSet.Has(r) || resourceSet.Has("*") {
					resourcesMatch = true
					break
				}
			}
			if verbsMatch && resourcesMatch {
				allCombos.Add(combo.title)
			}
		}
	}

	// Emit dangerous combos as a single finding per role
	if allCombos.Len() > 0 {
		comboList := allCombos.Sorted()
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "rbac",
			Title:        "Dangerous Permission Combination",
			Description:  fmt.Sprintf("%s '%s' has dangerous permission combinations: %s", resourceType, roleName, strings.Join(comboList, ", ")),
			ResourceType: resourceType,
			ResourceName: roleName,
			Namespace:    namespace,
			Remediation:  "Remove dangerous permission combinations. Apply least privilege — grant only what is explicitly required.",
			Metadata: map[string]any{
				"dangerous_combos": comboList,
			},
		})
	}

	return findings
}

func hasVerbForResource(rule rbacv1.PolicyRule, verbs []string, resource string) bool {
	resourceSet := utils.NewStringSet(rule.Resources...)
	verbSet := utils.NewStringSet(rule.Verbs...)
	if !resourceSet.Has(resource) && !resourceSet.Has("*") {
		return false
	}
	for _, v := range verbs {
		if verbSet.Has(v) || verbSet.Has("*") {
			return true
		}
	}
	return false
}

// ─── Binding checks ───────────────────────────────────────────────────────────

func checkRoleBinding(subjects []rbacv1.Subject, roleRef rbacv1.RoleRef, bindingName, namespace string) []*core.Finding {
	var findings []*core.Finding

	if roleRef.Kind == "ClusterRole" && !isSystemRole(roleRef.Name) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "rbac",
			Title:        "ClusterRole Used in Namespace-Scoped Binding",
			Description:  fmt.Sprintf("RoleBinding '%s' (namespace: %s) references ClusterRole '%s'. Using a ClusterRole in a namespace binding is confusing — the role may grant permissions on cluster-scoped resources that don't apply, obscuring the actual effective permissions.", bindingName, namespace, roleRef.Name),
			ResourceType: "RoleBinding",
			ResourceName: bindingName,
			Namespace:    namespace,
			Remediation:  "Create a namespace-scoped Role with only the permissions needed in this namespace instead of referencing a ClusterRole.",
		})
	}

	// adminReported prevents N identical "Overly Permissive" findings when a
	// single binding has multiple subjects — report once per binding, not per subject.
	adminReported := false
	var adminSubjectNames []string

	for _, subj := range subjects {
		if subj.Kind == "ServiceAccount" && subj.Namespace != "" && subj.Namespace != namespace &&
			!knownSafeRBACBindings[bindingName] && !strings.HasPrefix(subj.Name, "system:controller:") {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "rbac",
				Title:        "Cross-Namespace ServiceAccount Binding",
				Description:  fmt.Sprintf("RoleBinding '%s' (namespace: %s) grants permissions to ServiceAccount '%s' from namespace '%s' — a workload in another namespace can act with these permissions.", bindingName, namespace, subj.Name, subj.Namespace),
				ResourceType: "RoleBinding",
				ResourceName: bindingName,
				Namespace:    namespace,
				Remediation:  "Avoid cross-namespace SA bindings. Create a dedicated SA in the same namespace with only the permissions it needs.",
				Metadata:     map[string]any{"sa_namespace": subj.Namespace, "sa_name": subj.Name},
			})
		}

		if (subj.Name == "system:anonymous" || subj.Name == "system:unauthenticated") && !knownSafeRBACBindings[bindingName] {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityCritical,
				Category:     "rbac",
				Title:        "Anonymous User Granted Permissions",
				Description:  fmt.Sprintf("RoleBinding '%s' grants permissions to '%s' — unauthenticated users can exercise these permissions.", bindingName, subj.Name),
				ResourceType: "RoleBinding",
				ResourceName: bindingName,
				Namespace:    namespace,
				Remediation:  "Remove bindings to system:anonymous and system:unauthenticated immediately.",
			})
		}

		if subj.Name == "system:authenticated" && !knownSafeRBACBindings[bindingName] {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "rbac",
				Title:        "Overly Permissive Role Binding",
				Description:  fmt.Sprintf("RoleBinding '%s' grants permissions to 'system:authenticated' — every authenticated user in the cluster gets these permissions.", bindingName),
				ResourceType: "RoleBinding",
				ResourceName: bindingName,
				Namespace:    namespace,
				Remediation:  "Remove binding to system:authenticated. Bind only specific users/groups/service accounts.",
			})
		}

		if roleRef.Name == "cluster-admin" || roleRef.Name == "admin" {
			adminSubjectNames = append(adminSubjectNames, subj.Name)
		}
	}

	// Emit a single finding for admin role bindings, listing all subjects together.
	if !adminReported && len(adminSubjectNames) > 0 {
		adminReported = true
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "rbac",
			Title:        "Overly Permissive Role Binding",
			Description:  fmt.Sprintf("RoleBinding '%s' binds %v to '%s' — this grants very broad permissions.", bindingName, adminSubjectNames, roleRef.Name),
			ResourceType: "RoleBinding",
			ResourceName: bindingName,
			Namespace:    namespace,
			Remediation:  "Create a minimal Role with only required permissions instead of using cluster-admin or admin.",
			Metadata:     map[string]any{"subjects": adminSubjectNames, "role": roleRef.Name},
		})
	}

	return findings
}


func checkClusterRoleBinding(subjects []rbacv1.Subject, roleRef rbacv1.RoleRef, bindingName string) []*core.Finding {
	var findings []*core.Finding

	for _, subj := range subjects {
		if (subj.Name == "system:anonymous" || subj.Name == "system:unauthenticated") && !knownSafeRBACBindings[bindingName] {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityCritical,
				Category:     "rbac",
				Title:        "Anonymous User Granted Permissions",
				Description:  fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-level permissions to '%s'.", bindingName, subj.Name),
				ResourceType: "ClusterRoleBinding",
				ResourceName: bindingName,
				Namespace:    "cluster-wide",
				Remediation:  "Remove ClusterRoleBindings to system:anonymous and system:unauthenticated immediately.",
			})
		}

		if subj.Name == "system:authenticated" && !knownSafeRBACBindings[bindingName] {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "rbac",
				Title:        "Overly Permissive Role Binding",
				Description:  fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-level permissions to 'system:authenticated' — every authenticated user in the cluster.", bindingName),
				ResourceType: "ClusterRoleBinding",
				ResourceName: bindingName,
				Namespace:    "cluster-wide",
				Remediation:  "Remove binding to system:authenticated. Bind only specific users, groups, or service accounts.",
			})
		}

		if roleRef.Name == "cluster-admin" && !isSystemSubject(subj.Name) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityCritical,
				Category:     "rbac",
				Title:        "Overly Permissive Role Binding",
				Description:  fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin to '%s' — full cluster control.", bindingName, subj.Name),
				ResourceType: "ClusterRoleBinding",
				ResourceName: bindingName,
				Namespace:    "cluster-wide",
				Remediation:  "Remove cluster-admin ClusterRoleBinding. Create a minimal ClusterRole with only the required permissions.",
			})
		}

		if subj.Kind == "Group" && subj.Name == "system:masters" && !knownSafeRBACBindings[bindingName] {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityCritical,
				Category:     "rbac",
				Title:        "system:masters Group Binding Detected",
				Description:  fmt.Sprintf("ClusterRoleBinding '%s' grants permissions to the 'system:masters' group. Members of this group bypass all RBAC checks and have unconditional cluster-admin access — even if cluster-admin ClusterRole is removed.", bindingName),
				ResourceType: "ClusterRoleBinding",
				ResourceName: bindingName,
				Namespace:    "cluster-wide",
				Remediation:  "Never bind user-facing accounts to system:masters. Use a custom ClusterRole with the specific permissions required.",
			})
		}
	}
	return findings
}

// ─── Default ServiceAccount dangerous permission check ────────────────────────

func checkDefaultSADangerousPerms(
	roleBindings []rbacv1.RoleBinding,
	clusterRoleBindings []rbacv1.ClusterRoleBinding,
	roles []rbacv1.Role,
	clusterRoles []rbacv1.ClusterRole,
) []*core.Finding {
	var findings []*core.Finding

	roleMap := make(map[string]rbacv1.Role)
	for _, r := range roles {
		roleMap[r.Namespace+"/"+r.Name] = r
	}
	crMap := make(map[string]rbacv1.ClusterRole)
	for _, cr := range clusterRoles {
		crMap[cr.Name] = cr
	}

	for _, rb := range roleBindings {
		for _, subj := range rb.Subjects {
			if subj.Kind == "ServiceAccount" && subj.Name == "default" {
				var rules []rbacv1.PolicyRule
				if rb.RoleRef.Kind == "Role" {
					key := rb.Namespace + "/" + rb.RoleRef.Name
					if r, ok := roleMap[key]; ok {
						rules = r.Rules
					}
				} else if rb.RoleRef.Kind == "ClusterRole" {
					if cr, ok := crMap[rb.RoleRef.Name]; ok {
						rules = cr.Rules
					}
				}

				if hasDangerousRules(rules) {
					findings = append(findings, &core.Finding{
						Severity:     core.SeverityHigh,
						Category:     "rbac",
						Title:        "Default ServiceAccount with Dangerous Permissions",
						Description:  fmt.Sprintf("Default ServiceAccount in namespace '%s' is bound to role '%s' with dangerous permissions.", rb.Namespace, rb.RoleRef.Name),
						ResourceType: "RoleBinding",
						ResourceName: rb.Name,
						Namespace:    rb.Namespace,
						Remediation:  "Create a dedicated ServiceAccount with minimal permissions. Avoid using the default SA for workloads.",
						Metadata: map[string]any{
							"role":         rb.RoleRef.Name,
							"binding_name": rb.Name,
							"subject":      "default",
						},
					})
				}
			}
		}
	}

	return findings
}

func hasDangerousRules(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		verbSet := utils.NewStringSet(rule.Verbs...)
		resourceSet := utils.NewStringSet(rule.Resources...)
		if verbSet.Has("*") || resourceSet.Has("*") {
			return true
		}
		if hasVerbForResource(rule, []string{"get", "list"}, "secrets") {
			return true
		}
		if hasVerbForResource(rule, []string{"create"}, "pods/exec") {
			return true
		}
		if hasVerbForResource(rule, []string{"bind", "escalate"}, "roles") ||
			hasVerbForResource(rule, []string{"bind", "escalate"}, "clusterroles") {
			return true
		}
	}
	return false
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var systemRolePrefixes = []string{
	"system:", "kubeadm:", "calico-", "cilium-", "weave-",
	"flannel-", "istio-", "cert-manager-", "aws-", "gke-", "aks-",
	"prometheus-", "grafana-", "coredns", "kube-",
	// Common GitOps / infrastructure operators whose roles fire false positives
	// because they legitimately need broad permissions to manage the cluster.
	"argocd-", "flux-", "velero-", "crossplane-",
	"tekton-", "knative-", "external-secrets-",
	"karpenter-", "cluster-autoscaler-",
	// kind / kubeadm storage provisioners
	"local-path-provisioner", "rancher-local-path",
}

// builtinClusterRoles are Kubernetes default roles present in every cluster.
// Flagging them as misconfigurations produces false positives.
var builtinClusterRoles = map[string]struct{}{
	"cluster-admin":  {},
	"admin":          {},
	"edit":           {},
	"view":           {},
	"cluster-view":   {},
	"cluster-viewer": {},
}

func isSystemRole(name string) bool {
	if _, ok := builtinClusterRoles[strings.ToLower(name)]; ok {
		return true
	}
	lowerName := strings.ToLower(name)
	for _, prefix := range systemRolePrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	return false
}

var systemSubjectPrefixes = []string{
	"system:", "kubeadm:", "kube-",
}

func isSystemSubject(name string) bool {
	for _, prefix := range systemSubjectPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// knownSafeRBACBindings are default ClusterRoleBindings/RoleBindings that ship
// with every kubeadm-bootstrapped cluster and grant only narrow, well-known
// permissions (self-introspection or unauthenticated /healthz, /version, etc.).
// Flagging them as "Overly Permissive" or "Anonymous User Granted" produces
// pure noise — they are part of the platform.
var knownSafeRBACBindings = map[string]bool{
	"system:basic-user":                    true, // SelfSubjectAccessReview / SelfSubjectRulesReview only
	"system:discovery":                     true, // /api, /apis, /version discovery endpoints only
	"system:public-info-viewer":            true, // /healthz, /livez, /readyz, /version only
	"kubeadm:bootstrap-signer-clusterinfo": true, // read-only access to cluster-info ConfigMap (required by kubeadm)
	// cluster-admin CRB ships with every cluster: system:masters → cluster-admin
	// This is the bootstrap binding — not user-created, cannot be removed safely.
	"cluster-admin":                        true,
	// bootstrap-signer cross-namespace binding is a built-in controller (kube-public)
	"system:controller:bootstrap-signer":   true,
}

// checkDefaultSAUsedByPods flags non-system pods that use the default service account.
// This is a MEDIUM signal — the default SA should not be used for workloads.
func checkDefaultSAUsedByPods(pods []corev1.Pod) []*core.Finding {
	var findings []*core.Finding
	seen := utils.NewStringSet()

	for _, pod := range pods {
		ns := pod.Namespace
		if isSystemNamespace(ns) {
			continue
		}
		// Only flag when using default SA (empty name defaults to "default")
		saName := pod.Spec.ServiceAccountName
		if saName != "" && saName != "default" {
			continue
		}
		// Skip pods managed by a controller — report at the controller level would be better,
		// but we deduplicate by namespace to avoid per-pod noise.
		key := ns
		if seen.Has(key) {
			continue
		}
		seen.Add(key)

		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "rbac",
			Title:        "Default Service Account Used",
			Description:  fmt.Sprintf("Pods in namespace '%s' are using the default service account. If this SA is granted any permissions they apply to all pods in the namespace.", ns),
			ResourceType: "Namespace",
			ResourceName: ns,
			Namespace:    ns,
			Remediation:  "Create dedicated service accounts per workload with automountServiceAccountToken: false and only the permissions needed.",
		})
	}
	return findings
}

// ─── Unused ServiceAccount ────────────────────────────────────────────────────

func checkUnusedServiceAccounts(sas []corev1.ServiceAccount, pods []corev1.Pod) []*core.Finding {
	// Build a set of (namespace, SA name) pairs actually in use by running pods
	used := utils.NewStringSet()
	for _, pod := range pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		used.Add(pod.Namespace + "/" + sa)
	}

	var findings []*core.Finding
	for _, sa := range sas {
		if isSystemNamespace(sa.Namespace) {
			continue
		}
		if sa.Name == "default" {
			continue // default SA is always "present" even if pods use it implicitly
		}
		key := sa.Namespace + "/" + sa.Name
		if !used.Has(key) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityLow,
				Category:     "rbac",
				Title:        "Unused ServiceAccount",
				Description:  fmt.Sprintf("ServiceAccount '%s' in namespace '%s' is not used by any running pod. Unused SAs with RBAC bindings represent latent attack surface.", sa.Name, sa.Namespace),
				ResourceType: "ServiceAccount",
				ResourceName: sa.Name,
				Namespace:    sa.Namespace,
				Remediation:  "Delete the ServiceAccount if it is no longer needed. If it is used by a batch job or external process, add a comment in the manifest.",
			})
		}
	}
	return findings
}

// ─── Legacy SA token auto-mount ───────────────────────────────────────────────

func checkLegacySATokenMount(pods []corev1.Pod) []*core.Finding {
	var findings []*core.Finding
	seen := utils.NewStringSet()

	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		// Only flag pods that explicitly enable auto-mount (or use the default which is true)
		automount := true
		if pod.Spec.AutomountServiceAccountToken != nil {
			automount = *pod.Spec.AutomountServiceAccountToken
		}
		if !automount {
			continue
		}

		// Check if any volume is a projected SA token (expiring token)
		hasProjectedToken := false
		for _, vol := range pod.Spec.Volumes {
			if vol.Projected == nil {
				continue
			}
			for _, src := range vol.Projected.Sources {
				if src.ServiceAccountToken != nil {
					hasProjectedToken = true
					break
				}
			}
			if hasProjectedToken {
				break
			}
		}

		if !hasProjectedToken {
			// Deduplicate by namespace to avoid per-pod noise
			key := pod.Namespace + "/" + pod.Spec.ServiceAccountName
			if seen.Has(key) {
				continue
			}
			seen.Add(key)
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "rbac",
				Title:        "Legacy ServiceAccount Token Auto-Mount",
				Description:  fmt.Sprintf("Pod '%s' (namespace: %s) uses the legacy service account token auto-mount mechanism — the token is long-lived with no expiration. Projected tokens expire and auto-rotate.", pod.Name, pod.Namespace),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Use projected service account tokens (spec.volumes[].projected.sources[].serviceAccountToken with expirationSeconds). Set automountServiceAccountToken: false if API access is not needed.",
			})
		}
	}
	return findings
}

// checkPrivilegedSABoundToWorkload flags pods that use a non-default ServiceAccount
// which has been granted sensitive permissions (secrets access, wildcard resources,
// dangerous verb combinations) via RoleBinding or ClusterRoleBinding.
// This catches the pattern where a developer creates a custom SA and accidentally
// (or deliberately) grants it far more access than the workload needs.
func checkPrivilegedSABoundToWorkload(
	pods []corev1.Pod,
	roleBindings []rbacv1.RoleBinding,
	clusterRoleBindings []rbacv1.ClusterRoleBinding,
	roles []rbacv1.Role,
	clusterRoles []rbacv1.ClusterRole,
) []*core.Finding {
	// Build role → sensitive flag lookup
	sensitiveRoles := make(map[string]string) // "ns/name" → reason
	for _, r := range roles {
		if isSystemRole(r.Name) {
			continue
		}
		for _, rule := range r.Rules {
			verbSet := utils.NewStringSet(rule.Verbs...)
			resourceSet := utils.NewStringSet(rule.Resources...)
			if verbSet.Has("*") || resourceSet.Has("*") {
				sensitiveRoles[r.Namespace+"/"+r.Name] = "wildcard permissions"
				break
			}
			if hasVerbForResource(rule, []string{"get", "list", "watch"}, "secrets") {
				sensitiveRoles[r.Namespace+"/"+r.Name] = "secrets read access"
				break
			}
		}
	}
	sensitiveClusterRoles := make(map[string]string) // "name" → reason
	for _, cr := range clusterRoles {
		if isSystemRole(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			verbSet := utils.NewStringSet(rule.Verbs...)
			resourceSet := utils.NewStringSet(rule.Resources...)
			if verbSet.Has("*") || resourceSet.Has("*") {
				sensitiveClusterRoles[cr.Name] = "wildcard permissions"
				break
			}
			if hasVerbForResource(rule, []string{"get", "list", "watch"}, "secrets") {
				sensitiveClusterRoles[cr.Name] = "secrets read access"
				break
			}
		}
	}

	// Build SA → sensitive reason via RoleBindings
	saSensitive := make(map[string]string) // "ns/sa" → reason
	for _, rb := range roleBindings {
		var reason string
		key := rb.Namespace + "/" + rb.RoleRef.Name
		if rb.RoleRef.Kind == "Role" {
			reason = sensitiveRoles[key]
		} else if rb.RoleRef.Kind == "ClusterRole" {
			reason = sensitiveClusterRoles[rb.RoleRef.Name]
		}
		if reason == "" {
			continue
		}
		for _, subj := range rb.Subjects {
			if subj.Kind == "ServiceAccount" {
				ns := subj.Namespace
				if ns == "" {
					ns = rb.Namespace
				}
				saSensitive[ns+"/"+subj.Name] = fmt.Sprintf("%s via RoleBinding '%s'", reason, rb.Name)
			}
		}
	}
	for _, crb := range clusterRoleBindings {
		reason := sensitiveClusterRoles[crb.RoleRef.Name]
		if reason == "" {
			continue
		}
		for _, subj := range crb.Subjects {
			if subj.Kind == "ServiceAccount" {
				ns := subj.Namespace
				if ns == "" {
					ns = "default"
				}
				saSensitive[ns+"/"+subj.Name] = fmt.Sprintf("%s via ClusterRoleBinding '%s'", reason, crb.Name)
			}
		}
	}

	seen := utils.NewStringSet()
	var findings []*core.Finding
	for _, pod := range pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" || sa == "default" {
			continue
		}
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		key := pod.Namespace + "/" + sa
		reason, ok := saSensitive[key]
		if !ok {
			continue
		}
		dedupKey := key + "/" + pod.GenerateName
		if seen.Has(dedupKey) {
			continue
		}
		seen.Add(dedupKey)

		autoMount := pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken
		desc := fmt.Sprintf(
			"Pod '%s' (namespace: %s) uses ServiceAccount '%s' which has %s. "+
				"The SA token is %s inside the pod at /var/run/secrets/kubernetes.io/serviceaccount/token — "+
				"any process in the container can use it to call the Kubernetes API.",
			pod.Name, pod.Namespace, sa, reason,
			map[bool]string{true: "automatically mounted", false: "NOT mounted"}[autoMount],
		)
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "rbac",
			Title:        "Sensitive ServiceAccount Bound to Workload",
			Description:  desc,
			ResourceType: "Pod",
			ResourceName: pod.Name,
			Namespace:    pod.Namespace,
			Remediation:  fmt.Sprintf("Set automountServiceAccountToken: false on ServiceAccount '%s' or the pod spec if the workload does not need API access. If it does, scope the Role to only the specific resources and resource names required.", sa),
			ProofOfConcept: fmt.Sprintf(
				"# Read secrets from inside the pod using the mounted SA token\n"+
					"kubectl exec -it %s -n %s -- sh -c \\\n"+
					"  'curl -sk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" "+
					"https://kubernetes.default.svc/api/v1/namespaces/%s/secrets'\n\n"+
					"# If secrets are returned: HIGH — scope the Role or disable automount",
				pod.Name, pod.Namespace, pod.Namespace,
			),
			Metadata: map[string]any{"service_account": sa, "reason": reason},
		})
	}
	return findings
}

var _ core.Scanner = RBACScanner{}
