package scanners

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"

	"github.com/alperenkesk/k8scan/internal/core"
	"github.com/alperenkesk/k8scan/internal/utils"
)

// ResourceScanner checks Deployments, StatefulSets, and DaemonSets.
// It mirrors all checks from PodScanner but targets workload templates so that
// findings are reported against the controller (not ephemeral pod names).
type ResourceScanner struct{}

func (ResourceScanner) Name() string { return "Workload Resource Security" }

func (ResourceScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	deployments, err := client.GetAllDeployments(ctx)
	if err != nil {
		return nil, err
	}
	statefulSets, err := client.GetAllStatefulSets(ctx)
	if err != nil {
		return nil, err
	}
	daemonSets, err := client.GetAllDaemonSets(ctx)
	if err != nil {
		return nil, err
	}
	cronJobs, err := client.GetAllCronJobs(ctx)
	if err != nil {
		return nil, err
	}
	jobs, err := client.GetAllJobs(ctx)
	if err != nil {
		return nil, err
	}
	pdbs, err := client.GetAllPodDisruptionBudgets(ctx)
	if err != nil {
		return nil, err
	}
	hpas, err := client.GetAllHorizontalPodAutoscalers(ctx)
	if err != nil {
		return nil, err
	}

	pdbIndex := buildPDBIndex(pdbs)
	hpaIndex := buildHPAIndex(hpas)

	var findings []*core.Finding

	for _, d := range deployments {
		findings = append(findings, checkDeployment(d, pdbIndex, hpaIndex)...)
	}
	for _, ss := range statefulSets {
		findings = append(findings, checkStatefulSet(ss)...)
	}
	for _, ds := range daemonSets {
		findings = append(findings, checkDaemonSet(ds)...)
	}
	for _, cj := range cronJobs {
		findings = append(findings, checkCronJob(cj)...)
	}
	for _, j := range jobs {
		findings = append(findings, checkJob(j)...)
	}

	return findings, nil
}

// buildPDBIndex returns a map of namespace → list of PDB matchLabels sets.
func buildPDBIndex(pdbs []policyv1.PodDisruptionBudget) map[string][]map[string]string {
	idx := make(map[string][]map[string]string)
	for _, pdb := range pdbs {
		if pdb.Spec.Selector == nil {
			continue
		}
		idx[pdb.Namespace] = append(idx[pdb.Namespace], pdb.Spec.Selector.MatchLabels)
	}
	return idx
}

// buildHPAIndex returns a set of "namespace/targetName" strings.
func buildHPAIndex(hpas []autoscalingv2.HorizontalPodAutoscaler) utils.StringSet {
	idx := utils.NewStringSet()
	for _, hpa := range hpas {
		idx.Add(hpa.Namespace + "/" + hpa.Spec.ScaleTargetRef.Name)
	}
	return idx
}

// hasPDB returns true if any PDB in the namespace covers the given pod template labels.
func hasPDB(pdbIndex map[string][]map[string]string, namespace string, podLabels map[string]string) bool {
	for _, pdbLabels := range pdbIndex[namespace] {
		covered := true
		for k, v := range pdbLabels {
			if podLabels[k] != v {
				covered = false
				break
			}
		}
		if covered {
			return true
		}
	}
	return false
}

// ─── Deployment ───────────────────────────────────────────────────────────────

func checkDeployment(d appsv1.Deployment, pdbIndex map[string][]map[string]string, hpaIndex utils.StringSet) []*core.Finding {
	if isSystemNamespace(d.Namespace) {
		return nil
	}
	var findings []*core.Finding
	rt, rn, ns := "Deployment", d.Name, d.Namespace

	if d.Namespace == "default" {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "workload",
			Title:        "Workload Running in Default Namespace",
			Description:  fmt.Sprintf("Deployment '%s' runs in the 'default' namespace. Production workloads should use dedicated namespaces for isolation and network policy enforcement.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Move workloads to a dedicated namespace with appropriate RBAC and NetworkPolicies. Avoid deploying applications to 'default'.",
		})
	}

	replicas := utils.Int32Val(d.Spec.Replicas)
	if replicas == 1 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Single Replica Deployment",
			Description:  fmt.Sprintf("Deployment '%s' has only 1 replica — single point of failure, no high availability.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set spec.replicas to at least 2 (ideally 3+) and use a PodDisruptionBudget.",
		})
	}

	if d.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Recreate Update Strategy",
			Description:  fmt.Sprintf("Deployment '%s' uses Recreate strategy — causes downtime during updates.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Switch to RollingUpdate with maxUnavailable: 0 and maxSurge: 1.",
		})
	}

	if replicas > 1 && !hasPDB(pdbIndex, ns, d.Spec.Template.Labels) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "workload",
			Title:        "Missing PodDisruptionBudget",
			Description:  fmt.Sprintf("Deployment '%s' has no PodDisruptionBudget — during node drain or rolling updates all replicas can be evicted simultaneously, causing downtime.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Create a PodDisruptionBudget with minAvailable: 1 (or maxUnavailable: 1) to ensure at least one pod stays running during voluntary disruptions.",
		})
	}

	if !hpaIndex.Has(ns + "/" + rn) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Missing HorizontalPodAutoscaler",
			Description:  fmt.Sprintf("Deployment '%s' has no HPA — the workload cannot automatically scale under load, risking resource exhaustion or over-provisioning.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Add a HorizontalPodAutoscaler targeting this deployment with CPU or memory metrics to enable autoscaling.",
		})
	}

	if len(d.Spec.Template.Spec.ImagePullSecrets) == 0 {
		for _, c := range d.Spec.Template.Spec.Containers {
			if looksPrivateRegistry(c.Image) {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityMedium,
					Category:     "workload",
					Title:        "Missing imagePullSecrets for Private Registry",
					Description:  fmt.Sprintf("Deployment '%s' uses image '%s' which may be from a private registry but has no imagePullSecrets configured — pulls may fail or fall back to unauthenticated access.", rn, c.Image),
					ResourceType: rt, ResourceName: rn, Namespace: ns,
					Remediation: "Add imagePullSecrets referencing a Secret of type kubernetes.io/dockerconfigjson with registry credentials.",
					Metadata:    map[string]any{"container": c.Name, "image": c.Image},
				})
				break
			}
		}
	}

	if d.Spec.RevisionHistoryLimit != nil && *d.Spec.RevisionHistoryLimit == 0 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "workload",
			Title:        "Revision History Disabled",
			Description:  fmt.Sprintf("Deployment '%s' sets revisionHistoryLimit: 0 — rollback is impossible because no previous ReplicaSets are retained.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set revisionHistoryLimit to at least 3 to allow rollback with 'kubectl rollout undo'.",
		})
	}

	spec := d.Spec.Template.Spec
	if replicas > 1 && (spec.Affinity == nil || spec.Affinity.PodAntiAffinity == nil) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "workload",
			Title:        "No Pod Anti-Affinity Configured",
			Description:  fmt.Sprintf("Deployment '%s' has multiple replicas but no podAntiAffinity rules — all replicas can be scheduled on the same node, creating a single point of failure.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Add spec.affinity.podAntiAffinity rules to spread replicas across nodes. Use preferredDuringSchedulingIgnoredDuringExecution for soft placement.",
		})
	}

	findings = append(findings, checkWorkloadContainers(spec, rt, rn, ns)...)
	return findings
}

// ─── StatefulSet ──────────────────────────────────────────────────────────────

func checkStatefulSet(ss appsv1.StatefulSet) []*core.Finding {
	if isSystemNamespace(ss.Namespace) {
		return nil
	}
	var findings []*core.Finding
	rt, rn, ns := "StatefulSet", ss.Name, ss.Namespace

	replicas := utils.Int32Val(ss.Spec.Replicas)
	if replicas == 1 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Single Replica Deployment",
			Description:  fmt.Sprintf("StatefulSet '%s' has only 1 replica — no high availability.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Increase replicas to at least 2 and configure appropriate storage replication.",
		})
	}

	findings = append(findings, checkWorkloadContainers(ss.Spec.Template.Spec, rt, rn, ns)...)
	return findings
}

// ─── DaemonSet ────────────────────────────────────────────────────────────────

func checkDaemonSet(ds appsv1.DaemonSet) []*core.Finding {
	if isSystemNamespace(ds.Namespace) {
		return nil
	}
	return checkWorkloadContainers(ds.Spec.Template.Spec, "DaemonSet", ds.Name, ds.Namespace)
}

// ─── Workload-level checks ────────────────────────────────────────────────────

// checkWorkloadContainers runs all security checks against a pod template spec.
func checkWorkloadContainers(spec corev1.PodSpec, rt, rn, ns string) []*core.Finding {
	var findings []*core.Finding

	// Determine target OS
	targetOS := "linux"
	if spec.NodeSelector != nil {
		if os, ok := spec.NodeSelector["kubernetes.io/os"]; ok {
			targetOS = strings.ToLower(os)
		}
	}

	// Pod-level seccomp — a configured profile (RuntimeDefault or Localhost) covers
	// all containers, so container-level checks must not flag them as "not set".
	podSeccompOK := spec.SecurityContext != nil &&
		spec.SecurityContext.SeccompProfile != nil &&
		isConfiguredSeccompType(spec.SecurityContext.SeccompProfile.Type)

	all := allTemplateContainers(spec)

	// Host namespace checks
	if spec.HostPID {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "hostPID Enabled",
			Description:  fmt.Sprintf("%s '%s' has hostPID: true — all host processes visible from containers.", rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set hostPID: false in pod template spec.",
		})
	}
	if spec.HostIPC {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "hostIPC Enabled",
			Description:  fmt.Sprintf("%s '%s' has hostIPC: true — host IPC namespace shared.", rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set hostIPC: false in pod template spec.",
		})
	}
	if spec.HostNetwork {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "hostNetwork Enabled",
			Description:  fmt.Sprintf("%s '%s' has hostNetwork: true — host network interface exposed.", rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set hostNetwork: false in pod template spec.",
		})
	}

	// HostPath volume checks — only flag volumes actually mounted in a container.
	// Volumes defined in spec.Volumes but absent from all container volumeMounts
	// are harmless and would produce false positives.
	mountedVols := make(map[string]bool)
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		for _, vm := range c.VolumeMounts {
			mountedVols[vm.Name] = true
		}
	}
	for _, vol := range spec.Volumes {
		if vol.HostPath == nil || !mountedVols[vol.Name] {
			continue
		}
		path := vol.HostPath.Path
		if info, ok := matchSensitiveHostPath(path); ok {
			findings = append(findings, &core.Finding{
				Severity:     info.Severity,
				Category:     "container",
				Title:        info.Title,
				Description:  fmt.Sprintf("%s '%s' mounts sensitive host path %s", rt, rn, path),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Remove hostPath mount. Use Kubernetes Secrets/ConfigMaps/PersistentVolumes.",
				Metadata:    map[string]any{"path": path, "volume": vol.Name},
				TargetOS:    targetOS,
			})
		} else {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Sensitive HostPath Mount",
				Description:  fmt.Sprintf("%s '%s' mounts host path %s", rt, rn, path),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Avoid mounting host paths. Use persistent volumes instead.",
				Metadata:    map[string]any{"path": path, "volume": vol.Name},
				TargetOS:    targetOS,
			})
		}
	}

	// Per-container checks
	for _, c := range all {
		findings = append(findings, checkWorkloadContainer(c, spec.SecurityContext, rt, rn, ns, targetOS, podSeccompOK)...)
	}

	// PriorityClass and probes do not apply to ephemeral batch workloads.
	isBatch := rt == "Job" || rt == "CronJob"

	if !isBatch && spec.PriorityClassName == "" {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Missing PriorityClass",
			Description:  fmt.Sprintf("%s '%s' has no priorityClassName — under resource pressure, pods will be evicted with default (lowest) priority and may not be rescheduled promptly.", rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Assign a priorityClassName appropriate to the workload's criticality (e.g. system-cluster-critical for infrastructure, or a custom PriorityClass).",
		})
	}

	if spec.DNSPolicy == corev1.DNSNone {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "workload",
			Title:        "Custom DNS Policy (dnsPolicy: None)",
			Description:  fmt.Sprintf("%s '%s' uses dnsPolicy: None with custom dnsConfig. Custom DNS resolvers can be hijacked or misconfigured, enabling DNS-based attacks.", rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Use dnsPolicy: ClusterFirst (default). Only override DNS if there's a specific, documented need.",
		})
	}

	if len(spec.HostAliases) > 0 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "workload",
			Title:        "hostAliases Configured",
			Description:  fmt.Sprintf("%s '%s' uses hostAliases to manipulate /etc/hosts inside pods — overrides DNS resolution and can enable DNS spoofing attacks.", rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Remove hostAliases. Use Kubernetes Services and DNS for service discovery instead of /etc/hosts overrides.",
			Metadata:    map[string]any{"host_count": len(spec.HostAliases)},
		})
	}

	findings = append(findings, checkCryptoMiner(spec.Containers, spec.InitContainers, rt, rn, ns, targetOS, core.ConfidenceHigh)...)
	findings = append(findings, checkDIND(spec.Volumes, spec.Containers, spec.InitContainers, rt, rn, ns, targetOS, core.ConfidenceHigh)...)

	return findings
}

func checkWorkloadContainer(c corev1.Container, podSC *corev1.PodSecurityContext, rt, rn, ns, targetOS string, podSeccompOK bool) []*core.Finding {
	var findings []*core.Finding

	// Privileged
	if c.SecurityContext != nil && utils.BoolVal(c.SecurityContext.Privileged) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityCritical,
			Category:     "container",
			Title:        "Privileged Container Detected",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' runs in privileged mode — full host kernel access.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set privileged: false. Use specific capabilities instead.",
			Metadata:    map[string]any{"container": c.Name},
			TargetOS:    targetOS,
		})
	}

	// Capabilities
	if targetOS != "windows" && c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
		for _, cap := range c.SecurityContext.Capabilities.Add {
			capStr := strings.ToUpper(string(cap))
			if dangerousCapabilities.Has(capStr) {
				sev := core.SeverityHigh
				if criticalCapabilities.Has(capStr) {
					sev = core.SeverityCritical
				}
				findings = append(findings, &core.Finding{
					Severity:     sev,
					Category:     "container",
					Title:        "Dangerous Capability Added",
					Description:  fmt.Sprintf("Container '%s' in %s '%s' adds the dangerous capability %s — this grants elevated kernel access and is a common container escape vector.", c.Name, rt, rn, capStr),
					ResourceType: rt, ResourceName: rn, Namespace: ns,
					Remediation: fmt.Sprintf("Remove capability %s. Use drop: [ALL] and add only required capabilities.", capStr),
					Metadata:    map[string]any{"container": c.Name, "capability": capStr},
					TargetOS:    targetOS,
				})
			}
		}
	}

	// Missing capabilities drop ALL
	if targetOS != "windows" {
		dropAll := false
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Drop {
				if strings.EqualFold(string(cap), "ALL") {
					dropAll = true
					break
				}
			}
		}
		if !dropAll {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityInfo,
				Category:     "container",
				Title:        "Missing Capabilities Drop ALL",
				Description:  fmt.Sprintf("Container '%s' in %s '%s' does not drop all capabilities (CIS Benchmark).", c.Name, rt, rn),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Add capabilities: { drop: [\"ALL\"] } to container securityContext.",
				Metadata:    map[string]any{"container": c.Name},
				TargetOS:    targetOS,
			})
		}
	}

	// Security context / runAsRoot / writable filesystem
	if c.SecurityContext == nil {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "container",
			Title:        "Missing Security Context",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' has no securityContext.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false.",
			Metadata:    map[string]any{"container": c.Name},
		})
	} else {
		if !guaranteedNonRootCtx(podSC, c.SecurityContext) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Container Can Run as Root",
				Description:  fmt.Sprintf("Container '%s' in %s '%s': runAsNonRoot is not set to true.", c.Name, rt, rn),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Set securityContext.runAsNonRoot: true",
				Metadata:    map[string]any{"container": c.Name},
			})
		}
		if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityLow,
				Category:     "container",
				Title:        "Root Filesystem is Writable",
				Description:  fmt.Sprintf("Container '%s' in %s '%s' has a writable root filesystem.", c.Name, rt, rn),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Set securityContext.readOnlyRootFilesystem: true",
				Metadata:    map[string]any{"container": c.Name},
			})
		}
		if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Privilege Escalation Allowed",
				Description:  fmt.Sprintf("Container '%s' in %s '%s': allowPrivilegeEscalation is not set to false.", c.Name, rt, rn),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Set securityContext.allowPrivilegeEscalation: false",
				Metadata:    map[string]any{"container": c.Name},
			})
		}
	}

	// Seccomp — skip if the pod-level seccomp profile is already RuntimeDefault,
	// which applies to all containers and prevents false positives here.
	if targetOS != "windows" && !podSeccompOK {
		if c.SecurityContext == nil || c.SecurityContext.SeccompProfile == nil ||
			!isConfiguredSeccompType(c.SecurityContext.SeccompProfile.Type) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityLow,
				Category:     "container",
				Title:        "Seccomp Profile Not Set to RuntimeDefault",
				Description:  fmt.Sprintf("Container '%s' in %s '%s' does not use seccompProfile.type: RuntimeDefault (neither at container nor pod level).", c.Name, rt, rn),
				ResourceType: rt, ResourceName: rn, Namespace: ns,
				Remediation: "Add securityContext.seccompProfile.type: RuntimeDefault at pod or container level.",
				Metadata:    map[string]any{"container": c.Name},
				TargetOS:    targetOS,
			})
		}
	}

	// Resource limits/requests
	cpuLimit := c.Resources.Limits.Cpu()
	memLimit := c.Resources.Limits.Memory()
	if cpuLimit.IsZero() && memLimit.IsZero() {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "workload",
			Title:        "Missing Resource Limits",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' has no CPU/memory limits — uncontrolled resource consumption can exhaust node capacity, evict neighboring pods, and be exploited for availability attacks in multi-tenant clusters.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set resource limits for both CPU and memory.",
		})
	}

	cpuReq := c.Resources.Requests.Cpu()
	memReq := c.Resources.Requests.Memory()
	if cpuReq.IsZero() && memReq.IsZero() {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Missing Resource Requests",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' has no CPU/memory requests.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set resource requests matching typical usage.",
		})
	}

	// Image tag — imageHasExplicitTag ignores the ":" in a registry host:port
	// prefix so an untagged "myreg:5000/app" is still treated as latest.
	isLatest := strings.HasSuffix(c.Image, ":latest") || !imageHasExplicitTag(c.Image)
	if isLatest {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Image Using Latest Tag",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' uses image '%s' — unpredictable deployments.", c.Name, rt, rn, c.Image),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Pin image to a specific version tag.",
		})
	}

	// ImagePullPolicy
	if c.ImagePullPolicy != corev1.PullAlways && strings.HasSuffix(c.Image, ":latest") {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "ImagePullPolicy Not Always",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' uses ':latest' but ImagePullPolicy is not 'Always'.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set imagePullPolicy: Always when using mutable tags.",
		})
	}

	// Probes are not applicable to ephemeral batch workloads (Job/CronJob) — they
	// run to completion and don't serve traffic, so liveness/readiness signals
	// would only generate noise.
	isLongRunning := rt != "Job" && rt != "CronJob"
	if isLongRunning && c.LivenessProbe == nil {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Missing Liveness Probe",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' has no liveness probe.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Add a livenessProbe to enable automatic container restart on deadlock.",
		})
	}
	if isLongRunning && c.ReadinessProbe == nil {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "Missing Readiness Probe",
			Description:  fmt.Sprintf("Container '%s' in %s '%s' has no readiness probe.", c.Name, rt, rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Add a readinessProbe to prevent routing traffic to pods before they're ready.",
		})
	}

	return findings
}

// ─── CronJob ──────────────────────────────────────────────────────────────────

func checkCronJob(cj batchv1.CronJob) []*core.Finding {
	if isSystemNamespace(cj.Namespace) {
		return nil
	}
	var findings []*core.Finding
	rt, rn, ns := "CronJob", cj.Name, cj.Namespace

	// Forbid concurrent runs — Allow keeps launching overlapping jobs
	if cj.Spec.ConcurrencyPolicy == batchv1.AllowConcurrent {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "workload",
			Title:        "CronJob Allows Concurrent Execution",
			Description:  fmt.Sprintf("CronJob '%s' has concurrencyPolicy: Allow — overlapping job runs can amplify resource exhaustion or cause race conditions.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set concurrencyPolicy: Forbid or Replace to prevent overlapping executions.",
		})
	}

	// Successful/failed job history — unlimited history wastes etcd space
	if cj.Spec.SuccessfulJobsHistoryLimit == nil || *cj.Spec.SuccessfulJobsHistoryLimit > 10 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "workload",
			Title:        "CronJob Unbounded Job History",
			Description:  fmt.Sprintf("CronJob '%s' does not limit successfulJobsHistoryLimit — completed Jobs accumulate and consume etcd storage.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set successfulJobsHistoryLimit: 3 and failedJobsHistoryLimit: 3.",
		})
	}

	if cj.Spec.StartingDeadlineSeconds == nil {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "workload",
			Title:        "CronJob Missing startingDeadlineSeconds",
			Description:  fmt.Sprintf("CronJob '%s' has no startingDeadlineSeconds — if the job controller misses its schedule window (e.g., after a cluster restart), it will attempt to catch up with all missed runs indefinitely.", rn),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set startingDeadlineSeconds to a reasonable window (e.g., 300 seconds). Combine with concurrencyPolicy: Forbid to prevent job pile-up.",
		})
	}

	// Security checks on the pod template
	findings = append(findings, checkWorkloadContainers(cj.Spec.JobTemplate.Spec.Template.Spec, rt, rn, ns)...)
	return findings
}

// ─── Job ──────────────────────────────────────────────────────────────────────

func checkJob(j batchv1.Job) []*core.Finding {
	if isSystemNamespace(j.Namespace) {
		return nil
	}
	// Skip jobs owned by a CronJob — already covered by checkCronJob
	for _, ref := range j.OwnerReferences {
		if ref.Kind == "CronJob" {
			return nil
		}
	}
	var findings []*core.Finding
	rt, rn, ns := "Job", j.Name, j.Namespace

	const backoffThreshold = int32(10)
	if j.Spec.BackoffLimit != nil && *j.Spec.BackoffLimit > backoffThreshold {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "workload",
			Title:        "Job backoffLimit Too High",
			Description:  fmt.Sprintf("Job '%s' sets backoffLimit: %d — a failing job will retry %d times, burning compute resources and potentially amplifying an error condition.", rn, *j.Spec.BackoffLimit, *j.Spec.BackoffLimit),
			ResourceType: rt, ResourceName: rn, Namespace: ns,
			Remediation: "Set backoffLimit to a small value (3–6). Add activeDeadlineSeconds to cap total job runtime.",
			Metadata:    map[string]any{"backoff_limit": *j.Spec.BackoffLimit},
		})
	}

	findings = append(findings, checkWorkloadContainers(j.Spec.Template.Spec, rt, rn, ns)...)
	return findings
}

// looksPrivateRegistry returns true for images that don't appear to come from
// the standard public registries and likely need credentials to pull.
func looksPrivateRegistry(image string) bool {
	publicPrefixes := []string{
		"docker.io/", "library/", "nginx", "redis", "postgres", "mysql",
		"alpine", "ubuntu", "debian", "python", "node", "golang",
		"k8s.gcr.io/", "gcr.io/google_containers/", "registry.k8s.io/",
	}
	imgLower := strings.ToLower(image)
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(imgLower, prefix) || strings.HasPrefix(imgLower, "docker.io/"+prefix) {
			return false
		}
	}
	// If the image starts with a domain-like string (contains a dot before the first slash), it's private
	slash := strings.Index(image, "/")
	if slash > 0 {
		host := image[:slash]
		return strings.Contains(host, ".") || strings.Contains(host, ":")
	}
	return false
}

func allTemplateContainers(spec corev1.PodSpec) []corev1.Container {
	out := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers))
	out = append(out, spec.Containers...)
	out = append(out, spec.InitContainers...)
	return out
}

var _ core.Scanner = ResourceScanner{}
