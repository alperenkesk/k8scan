// Package compliance provides CIS Kubernetes Benchmark v1.8 mapping for k8scan findings.
// Each finding title is mapped to the CIS control ID, level, profile, and description.
package compliance

import "github.com/alperenkeskin/k8scan/internal/core"

// CISEntry holds the CIS Benchmark metadata for a single finding title.
type CISEntry struct {
	Control string // e.g. "5.2.1"
	Level   int    // 1 or 2
	Profile string // Master, Worker, Policy, RBAC, etcd, Secrets, Admission
	Title   string // CIS control human-readable title
}

// cisMapping maps k8scan finding titles to their CIS Benchmark controls.
// Source: CIS Kubernetes Benchmark v1.8 (https://www.cisecurity.org/benchmark/kubernetes)
var cisMapping = map[string]CISEntry{
	// ─── Control Plane (Section 1) ────────────────────────────────────────────
	"API Server Anonymous Access Enabled": {
		"1.2.1", 1, "Master",
		"Ensure that the --anonymous-auth argument is set to false",
	},
	"API Server Authorization Mode: AlwaysAllow": {
		"1.2.7", 1, "Master",
		"Ensure that the --authorization-mode argument is not set to AlwaysAllow",
	},
	"API Server Audit Logging Disabled": {
		"1.2.22", 1, "Master",
		"Ensure that the --audit-log-path argument is set",
	},
	"etcd Encryption at Rest Not Configured": {
		"1.2.33", 1, "Master",
		"Ensure that encryption providers are appropriately configured",
	},
	"API Server Insecure Port Enabled": {
		"1.2.19", 1, "Master",
		"Ensure that the --insecure-port argument is set to 0",
	},
	"API Server etcd Connection Not TLS": {
		"1.2.29", 1, "Master",
		"Ensure that the --etcd-cafile argument is set as appropriate",
	},
	"API Server Profiling Enabled": {
		"1.2.27", 1, "Master",
		"Ensure that the --profiling argument is set to false",
	},
	"Controller Manager Bound to All Interfaces": {
		"1.3.7", 1, "Master",
		"Ensure that the --bind-address argument is set to 127.0.0.1",
	},
	"Controller Manager Profiling Enabled": {
		"1.3.2", 1, "Master",
		"Ensure that the --profiling argument is set to false",
	},
	"Scheduler Bound to All Interfaces": {
		"1.4.1", 1, "Master",
		"Ensure that the --bind-address argument is set to 127.0.0.1",
	},

	// ─── etcd (Section 2) ─────────────────────────────────────────────────────
	"Exposed etcd Without Authentication": {
		"2.1", 1, "etcd",
		"Ensure that the --cert-file and --key-file arguments are set as appropriate",
	},
	"etcd Peer Communication Not Authenticated": {
		"2.5", 1, "etcd",
		"Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
	},

	// ─── Worker Node (Section 4) ──────────────────────────────────────────────
	"Kubelet Anonymous Access Enabled": {
		"4.2.1", 1, "Worker",
		"Ensure that the --anonymous-auth argument is set to false",
	},
	"Kubelet Read-Only Port Enabled": {
		"4.2.4", 1, "Worker",
		"Ensure that the --read-only-port argument is set to 0",
	},

	// ─── RBAC (Section 5.1) ───────────────────────────────────────────────────
	"Overly Permissive Role Binding": {
		"5.1.1", 1, "RBAC",
		"Ensure that the cluster-admin role is only used where required",
	},
	"Anonymous User Granted Permissions": {
		"5.1.2", 1, "RBAC",
		"Minimize access to secrets",
	},
	"Wildcard Permissions Granted": {
		"5.1.3", 1, "RBAC",
		"Minimize wildcard use in Roles and ClusterRoles",
	},
	"Pod Exec Permission Granted": {
		"5.1.3", 1, "RBAC",
		"Minimize wildcard use in Roles and ClusterRoles",
	},
	"Dangerous Permission Combination": {
		"5.1.3", 1, "RBAC",
		"Minimize wildcard use in Roles and ClusterRoles",
	},
	"Default Service Account Used": {
		"5.1.5", 1, "RBAC",
		"Ensure that default service accounts are not bound to active cluster roles",
	},
	"Service Account Token Auto-mounted": {
		"5.1.6", 1, "RBAC",
		"Ensure that Service Account Tokens are not automatically mounted",
	},
	"Legacy ServiceAccount Token Auto-Mount": {
		"5.1.6", 1, "RBAC",
		"Ensure that Service Account Tokens are not automatically mounted",
	},
	"Default ServiceAccount with Dangerous Permissions": {
		"5.1.5", 1, "RBAC",
		"Ensure that default service accounts are not bound to active cluster roles",
	},
	"system:masters Group Binding Detected": {
		"5.1.1", 1, "RBAC",
		"Ensure that the cluster-admin role is only used where required",
	},
	"Cross-Namespace ServiceAccount Binding": {
		"5.1.6", 1, "RBAC",
		"Ensure that Service Account Tokens are not automatically mounted",
	},

	// ─── RBAC — Faz 1 new checks ─────────────────────────────────────────────
	"ClusterRole Used in Namespace-Scoped Binding": {
		"5.1.1", 1, "RBAC",
		"Ensure that the cluster-admin role is only used where required",
	},
	"Unused ServiceAccount": {
		"5.1.5", 1, "RBAC",
		"Ensure that default service accounts are not bound to active cluster roles",
	},

	// ─── Secrets (Section 5.4) ────────────────────────────────────────────────
	"Secrets Read Access Granted": {
		"5.4.1", 1, "Secrets",
		"Prefer using secrets as files over secrets as environment variables",
	},
	"Secrets List/Watch Access Granted": {
		"5.4.1", 1, "Secrets",
		"Prefer using secrets as files over secrets as environment variables",
	},
	"Secret in Environment Variable": {
		"5.4.1", 1, "Secrets",
		"Prefer using secrets as files over secrets as environment variables",
	},

	// ─── Admission Control (Section 5.5) ──────────────────────────────────────
	"No Admission Policy Engine Detected": {
		"5.5.1", 1, "Admission",
		"Configure Image Provenance using ImagePolicyWebhook admission controller",
	},
	"Admission Webhook failurePolicy: Ignore": {
		"5.5.1", 1, "Admission",
		"Configure Image Provenance using ImagePolicyWebhook admission controller",
	},

	// ─── Pod Security (Section 5.2) ───────────────────────────────────────────
	"Privileged Container Detected": {
		"5.2.1", 1, "Policy",
		"Ensure that admission controller does not admit privileged containers",
	},
	"hostPID Enabled": {
		"5.2.2", 1, "Policy",
		"Ensure that admission controller does not admit containers wishing to share the host process ID namespace",
	},
	"hostIPC Enabled": {
		"5.2.3", 1, "Policy",
		"Ensure that admission controller does not admit containers wishing to share the host IPC namespace",
	},
	"hostNetwork Enabled": {
		"5.2.4", 1, "Policy",
		"Ensure that admission controller does not admit containers wishing to share the host network namespace",
	},
	"Privilege Escalation Allowed": {
		"5.2.5", 1, "Policy",
		"Ensure that admission controller does not admit containers with allowPrivilegeEscalation",
	},
	"Init Container Allows Privilege Escalation": {
		"5.2.5", 1, "Policy",
		"Ensure that admission controller does not admit containers with allowPrivilegeEscalation",
	},
	"Container Can Run as Root": {
		"5.2.6", 1, "Policy",
		"Ensure that admission controller does not admit root containers",
	},
	"Container Explicitly Runs as Root (UID 0)": {
		"5.2.6", 1, "Policy",
		"Ensure that admission controller does not admit root containers",
	},
	"Missing Capabilities Drop ALL": {
		"5.2.7", 1, "Policy",
		"Ensure that admission controller does not admit containers with added capabilities",
	},
	"Dangerous Capability Added": {
		"5.2.8", 1, "Policy",
		"Ensure that admission controller does not admit containers with added capabilities",
	},
	"Sensitive HostPath Mount": {
		"5.2.9", 1, "Policy",
		"Ensure that admission controller does not admit containers with added capabilities",
	},
	"Missing Security Context": {
		"5.2.1", 1, "Policy",
		"Ensure that admission controller does not admit privileged containers",
	},
	"Writable Root Filesystem": {
		"5.7.3", 2, "Policy",
		"Apply Security Context to your Pods and Containers",
	},
	"Root Filesystem is Writable": {
		"5.7.3", 2, "Policy",
		"Apply Security Context to your Pods and Containers",
	},
	"Seccomp Profile Not Set to RuntimeDefault": {
		"5.7.2", 2, "Policy",
		"Ensure that the seccomp profile is set to docker/default in your pod definitions",
	},
	"Pod Security Admission Not Configured": {
		"5.2.1", 1, "Policy",
		"Ensure that admission controller does not admit privileged containers",
	},
	"Pod Security Admission Set to Privileged": {
		"5.2.1", 1, "Policy",
		"Ensure that admission controller does not admit privileged containers",
	},
	// ─── Pod Security — Faz 1 new checks ─────────────────────────────────────
	"Shared Process Namespace Enabled": {
		"5.2.2", 1, "Policy",
		"Ensure that admission controller does not admit containers wishing to share the host process ID namespace",
	},
	"Ephemeral Container Without Security Context": {
		"5.2.1", 1, "Policy",
		"Ensure that admission controller does not admit privileged containers",
	},
	"Unmasked Proc Filesystem Mount": {
		"5.2.9", 1, "Policy",
		"Ensure that admission controller does not admit containers with added capabilities",
	},
	"No AppArmor Profile Configured": {
		"5.7.3", 2, "Policy",
		"Apply Security Context to your Pods and Containers",
	},
	"Unsafe Sysctl Parameter": {
		"5.7.3", 2, "Policy",
		"Apply Security Context to your Pods and Containers",
	},

	// ─── Network (Section 5.3) ────────────────────────────────────────────────
	"Missing Network Policy": {
		"5.3.2", 2, "Policy",
		"Ensure that all Namespaces have Network Policies defined",
	},
	"Missing Cross-Namespace Network Isolation": {
		"5.3.2", 2, "Policy",
		"Ensure that all Namespaces have Network Policies defined",
	},

	// ─── General Policies (Section 5.6 / 5.7) ────────────────────────────────
	"Missing LimitRange on Namespace": {
		"5.7.1", 1, "Policy",
		"Create administrative boundaries between resources using namespaces",
	},
	"Missing Resource Limits": {
		"5.7.3", 2, "Policy",
		"Apply Security Context to your Pods and Containers",
	},
	"Missing ResourceQuota on Namespace": {
		"5.7.1", 1, "Policy",
		"Create administrative boundaries between resources using namespaces",
	},
	"Workload Running in Default Namespace": {
		"5.7.4", 1, "Policy",
		"The default namespace should not be used",
	},
	"No Runtime Security Monitoring Detected": {
		"5.5.1", 1, "Admission",
		"Configure Image Provenance using ImagePolicyWebhook admission controller",
	},
}

// Enrich fills in CIS fields on each finding based on the title mapping.
// Findings with no mapping are left unchanged (CIS fields remain empty).
func Enrich(findings []*core.Finding) {
	for _, f := range findings {
		if entry, ok := cisMapping[f.Title]; ok {
			f.CISControl = entry.Control
			f.CISLevel = entry.Level
			f.CISProfile = entry.Profile
			f.CISTitle = entry.Title
		}
	}
}

// ComplianceSummary returns statistics about how many findings have CIS mappings
// and breaks them down by level.
type ComplianceSummary struct {
	TotalFindings  int
	MappedFindings int
	Level1Findings int
	Level2Findings int
	// Unique controls violated (deduplicated by CISControl)
	UniqueControlsViolated int
	// Controls by profile
	ByProfile map[string]int
}

// BuildComplianceSummary calculates CIS compliance statistics from enriched findings.
func BuildComplianceSummary(findings []*core.Finding) ComplianceSummary {
	cs := ComplianceSummary{
		TotalFindings: len(findings),
		ByProfile:     make(map[string]int),
	}
	controlsSeen := make(map[string]struct{})
	for _, f := range findings {
		if f.CISControl == "" {
			continue
		}
		cs.MappedFindings++
		if f.CISLevel == 1 {
			cs.Level1Findings++
		} else if f.CISLevel == 2 {
			cs.Level2Findings++
		}
		if _, seen := controlsSeen[f.CISControl]; !seen {
			controlsSeen[f.CISControl] = struct{}{}
			cs.UniqueControlsViolated++
		}
		cs.ByProfile[f.CISProfile]++
	}
	return cs
}
