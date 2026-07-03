package scanners

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/alperenkesk/k8scan/internal/core"
	"github.com/alperenkesk/k8scan/internal/utils"
)

// selfPodName / selfPodNamespace identify k8scan's own pod when it runs in-cluster
// via Downward API. When set, the pod scanner skips the matching pod to avoid
// reporting findings against itself. Out-of-cluster runs leave both empty.
var (
	selfPodName      = os.Getenv("POD_NAME")
	selfPodNamespace = os.Getenv("POD_NAMESPACE")
)

// PodScanner checks individual pod and init-container security configurations.
type PodScanner struct{}

func (PodScanner) Name() string { return "Pod Security" }

func (PodScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	pods, err := client.GetAllPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("pod scanner: %w", err)
	}

	var findings []*core.Finding
	for _, pod := range pods {
		// Skip system namespaces — control plane components legitimately run privileged.
		// ControlPlaneScanner handles kube-apiserver/etcd analysis separately.
		if isSystemPodNamespace(pod.Namespace) {
			continue
		}
		// Skip pods owned by a higher-level workload (Deployment, StatefulSet, DaemonSet, Job).
		// ResourceScanner already scans those workloads at the spec level, avoiding duplicates.
		if hasWorkloadOwner(pod) {
			continue
		}
		if isSelfPod(pod) {
			continue
		}
		findings = append(findings, checkPod(pod)...)
	}
	return findings, nil
}

// isSystemPodNamespace delegates to the central utils.IsSystemNamespace so that
// PodScanner and all other scanners share one authoritative namespace exclusion list.
func isSystemPodNamespace(ns string) bool {
	return utils.IsSystemNamespace(ns)
}

// isSelfPod returns true when the pod is k8scan itself (in-cluster mode with
// Downward API set) or matches the conventional standalone naming.
func isSelfPod(pod corev1.Pod) bool {
	if selfPodName != "" && pod.Name == selfPodName &&
		(selfPodNamespace == "" || pod.Namespace == selfPodNamespace) {
		return true
	}
	if pod.Labels["app.kubernetes.io/name"] == "k8scan" {
		return true
	}
	return false
}

// hasWorkloadOwner returns true when the pod is managed by a higher-level workload
// controller that ResourceScanner already covers.
func hasWorkloadOwner(pod corev1.Pod) bool {
	for _, ref := range pod.OwnerReferences {
		switch ref.Kind {
		case "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
			return true
		}
	}
	return false
}

// allContainers returns both regular and init containers so init containers
// are also scanned for security issues.
func allContainers(pod corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	out = append(out, pod.Spec.Containers...)
	out = append(out, pod.Spec.InitContainers...)
	return out
}

func checkPod(pod corev1.Pod) []*core.Finding {
	// Determine target OS from node selector
	targetOS := "linux"
	if pod.Spec.NodeSelector != nil {
		if os, ok := pod.Spec.NodeSelector["kubernetes.io/os"]; ok {
			targetOS = strings.ToLower(os)
		}
	}

	trusted := isTrustedOperator(pod)
	conf := core.ConfidenceHigh
	if trusted {
		conf = core.ConfidenceMedium
	}

	var findings []*core.Finding
	findings = append(findings, checkPrivilegedContainer(pod, targetOS, conf)...)
	findings = append(findings, checkHostNamespaces(pod, targetOS, conf)...)
	findings = append(findings, checkHostPaths(pod, targetOS, conf)...)
	findings = append(findings, checkCapabilities(pod, targetOS, conf)...)
	findings = append(findings, checkSecurityContext(pod, targetOS, conf)...)
	findings = append(findings, checkPrivilegeEscalation(pod, targetOS, conf)...)
	findings = append(findings, checkCapabilitiesDrop(pod, targetOS, conf)...)
	findings = append(findings, checkSeccompProfile(pod, targetOS, conf)...)
	findings = append(findings, checkImageTags(pod, targetOS, conf)...)
	findings = append(findings, checkSecretsInEnv(pod, targetOS, conf)...)
	findings = append(findings, checkServiceAccountToken(pod, targetOS, conf)...)
	findings = append(findings, checkCryptoMiner(pod.Spec.Containers, pod.Spec.InitContainers, "Pod", pod.Name, pod.Namespace, targetOS, conf)...)
	findings = append(findings, checkDIND(pod.Spec.Volumes, pod.Spec.Containers, pod.Spec.InitContainers, "Pod", pod.Name, pod.Namespace, targetOS, conf)...)
	// New checks (FUTURE-PLAN Faz 1)
	findings = append(findings, checkExplicitRootUser(pod, targetOS, conf)...)
	findings = append(findings, checkHostPorts(pod, targetOS, conf)...)
	findings = append(findings, checkUnsafeSysctls(pod, targetOS, conf)...)
	findings = append(findings, checkShareProcessNamespace(pod, targetOS, conf)...)
	findings = append(findings, checkTerminationGracePeriod(pod, targetOS, conf)...)
	findings = append(findings, checkBidirectionalMount(pod, targetOS, conf)...)
	findings = append(findings, checkSSHServer(pod, targetOS, conf)...)
	findings = append(findings, checkProcMountUnmasked(pod, targetOS, conf)...)
	findings = append(findings, checkInitContainerPrivEsc(pod, targetOS, conf)...)
	findings = append(findings, checkAppArmorProfile(pod, targetOS, conf)...)
	findings = append(findings, checkEphemeralContainerSecurity(pod, targetOS, conf)...)
	return findings
}

// --- Individual checks ---

func checkPrivilegedContainer(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		if c.SecurityContext != nil && utils.BoolVal(c.SecurityContext.Privileged) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityCritical,
				Category:     "container",
				Title:        "Privileged Container Detected",
				Description:  fmt.Sprintf("Container %s in pod %s runs in privileged mode — full host access", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Set privileged: false. Use specific capabilities instead.",
				Metadata:     map[string]any{"container": c.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

func checkHostNamespaces(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	if pod.Spec.HostPID {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "hostPID Enabled",
			Description:  fmt.Sprintf("Pod %s has hostPID: true — all host processes are visible", pod.Name),
			ResourceType: "Pod",
			ResourceName: pod.Name,
			Namespace:    pod.Namespace,
			Remediation:  "Set hostPID: false",
			TargetOS:     targetOS,
			Confidence:   conf,
		})
	}
	if pod.Spec.HostIPC {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "hostIPC Enabled",
			Description:  fmt.Sprintf("Pod %s has hostIPC: true — host IPC namespace shared", pod.Name),
			ResourceType: "Pod",
			ResourceName: pod.Name,
			Namespace:    pod.Namespace,
			Remediation:  "Set hostIPC: false",
			TargetOS:     targetOS,
			Confidence:   conf,
		})
	}
	if pod.Spec.HostNetwork {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "hostNetwork Enabled",
			Description:  fmt.Sprintf("Pod %s has hostNetwork: true — host network interface exposed", pod.Name),
			ResourceType: "Pod",
			ResourceName: pod.Name,
			Namespace:    pod.Namespace,
			Remediation:  "Set hostNetwork: false",
			TargetOS:     targetOS,
			Confidence:   conf,
		})
	}
	return findings
}

var sensitiveHostPaths = map[string]struct {
	Title    string
	Severity core.Severity
}{
	"/var/run/docker.sock":            {"Docker Socket Mount Detected", core.SeverityCritical},
	"/run/docker.sock":                {"Docker Socket Mount Detected", core.SeverityCritical},
	"/run/containerd/containerd.sock": {"Containerd Socket Mount Detected", core.SeverityCritical},
	"/etc/kubernetes":                 {"Kubernetes Config Directory Mount", core.SeverityCritical},
	"/var/lib/kubelet":                {"Kubelet Directory Mount", core.SeverityCritical},
	"/":                               {"Root Directory Mount", core.SeverityCritical},
	"/root":                           {"Full Host Root Filesystem Mount", core.SeverityCritical},
	"/host":                           {"Full Host Filesystem Mount", core.SeverityHigh},
	"/etc":                            {"System /etc Directory Mount", core.SeverityHigh},
	"/var/run":                        {"Runtime /var/run Directory Mount", core.SeverityHigh},
	"/proc":                           {"Process /proc Directory Mount", core.SeverityHigh},
	"/sys":                            {"System /sys Directory Mount", core.SeverityHigh},
}

// matchSensitiveHostPath performs an exact match first, then a prefix match
// so that sub-paths like /etc/kubernetes/pki are caught as CRITICAL, not generic MEDIUM.
func matchSensitiveHostPath(path string) (struct {
	Title    string
	Severity core.Severity
}, bool) {
	if info, ok := sensitiveHostPaths[path]; ok {
		return info, true
	}
	// Prefix match — skip "/" to avoid matching every path as root.
	for prefix, info := range sensitiveHostPaths {
		if prefix == "/" {
			continue
		}
		if strings.HasPrefix(path, prefix+"/") {
			return info, true
		}
	}
	return struct {
		Title    string
		Severity core.Severity
	}{}, false
}

func checkHostPaths(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	// Build set of volume names actually mounted in any container (init or main).
	// Volumes defined in pod.Spec.Volumes but not referenced in any volumeMount
	// are harmless — skip them to avoid false positives.
	mountedVolumes := make(map[string]bool)
	for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
		for _, vm := range c.VolumeMounts {
			mountedVolumes[vm.Name] = true
		}
	}

	var findings []*core.Finding
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath == nil {
			continue
		}
		if !mountedVolumes[vol.Name] {
			continue
		}
		path := vol.HostPath.Path

		if info, ok := matchSensitiveHostPath(path); ok {
			findings = append(findings, &core.Finding{
				Severity:     info.Severity,
				Category:     "container",
				Title:        info.Title,
				Description:  fmt.Sprintf("Pod %s mounts sensitive host path %s", pod.Name, path),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Remove hostPath mount. Use Kubernetes Secrets/ConfigMaps/PersistentVolumes.",
				Metadata:     map[string]any{"path": path, "volume": vol.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		} else {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Sensitive HostPath Mount",
				Description:  fmt.Sprintf("Pod %s mounts host path %s", pod.Name, path),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Avoid mounting host paths. Use persistent volumes instead.",
				Metadata:     map[string]any{"path": path, "volume": vol.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

var dangerousCapabilities = utils.NewStringSet(
	"SYS_ADMIN", "SYS_PTRACE", "NET_RAW", "NET_ADMIN",
	"DAC_READ_SEARCH", "DAC_OVERRIDE", "BPF", "PERFMON",
	"SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
)
var criticalCapabilities = utils.NewStringSet("SYS_ADMIN", "BPF", "SYS_MODULE", "SYS_RAWIO")

func checkCapabilities(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	if targetOS == "windows" {
		return nil
	}
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
			continue
		}
		for _, cap := range c.SecurityContext.Capabilities.Add {
			capStr := strings.ToUpper(string(cap))
			if utils.InSet(dangerousCapabilities, capStr) {
				sev := core.SeverityHigh
				if utils.InSet(criticalCapabilities, capStr) {
					sev = core.SeverityCritical
				}
				findings = append(findings, &core.Finding{
					Severity:     sev,
					Category:     "container",
					Title:        "Dangerous Capability Added",
					Description:  fmt.Sprintf("Container '%s' in pod '%s' adds the dangerous capability %s — this grants elevated kernel access and is a common container escape vector.", c.Name, pod.Name, capStr),
					ResourceType: "Pod",
					ResourceName: pod.Name,
					Namespace:    pod.Namespace,
					Remediation:  fmt.Sprintf("Remove capability %s. Use drop: [ALL] and add only the specific capabilities actually required.", capStr),
					Metadata:     map[string]any{"container": c.Name, "capability": capStr},
					TargetOS:     targetOS,
					Confidence:   conf,
				})
			}
		}
	}
	return findings
}

func checkSecurityContext(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		if c.SecurityContext == nil {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Missing Security Context",
				Description:  fmt.Sprintf("Container %s in pod %s has no securityContext", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false",
				Metadata:     map[string]any{"container": c.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
			continue
		}
		// Check runAsNonRoot — honour a pod-level securityContext that already
		// guarantees non-root, and treat an explicit non-zero runAsUser as safe.
		// Without this, setting runAsNonRoot at the pod level (a common pattern)
		// still flagged every container. See guaranteedNonRoot.
		if !guaranteedNonRoot(pod, c) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Container Can Run as Root",
				Description:  fmt.Sprintf("Container %s in pod %s can run as root (runAsNonRoot not set)", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Set securityContext.runAsNonRoot: true",
				Metadata:     map[string]any{"container": c.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
		// Check readOnlyRootFilesystem
		if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityLow,
				Category:     "container",
				Title:        "Root Filesystem is Writable",
				Description:  fmt.Sprintf("Container '%s' in pod '%s' has a writable root filesystem.", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Set securityContext.readOnlyRootFilesystem: true",
				Metadata:     map[string]any{"container": c.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

// guaranteedNonRoot reports whether the container is guaranteed not to run as
// root, considering both the container securityContext and the pod-level
// securityContext fallback. A container-level setting takes precedence; an
// explicit runAsUser decides by UID (0 = root).
func guaranteedNonRoot(pod corev1.Pod, c corev1.Container) bool {
	return guaranteedNonRootCtx(pod.Spec.SecurityContext, c.SecurityContext)
}

// guaranteedNonRootCtx is the context-level core of guaranteedNonRoot, shared
// with the workload-template path in resource.go. A container-level setting takes
// precedence over the pod-level fallback; an explicit runAsUser decides by UID.
func guaranteedNonRootCtx(podSC *corev1.PodSecurityContext, cSC *corev1.SecurityContext) bool {
	if cSC != nil {
		if cSC.RunAsUser != nil {
			return *cSC.RunAsUser != 0
		}
		if cSC.RunAsNonRoot != nil {
			return *cSC.RunAsNonRoot
		}
	}
	if podSC != nil {
		if podSC.RunAsUser != nil {
			return *podSC.RunAsUser != 0
		}
		if podSC.RunAsNonRoot != nil {
			return *podSC.RunAsNonRoot
		}
	}
	return false
}

func checkPrivilegeEscalation(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		// If SecurityContext is nil, "Missing Security Context" already covers this container.
		// Avoid duplicate findings — only check when a SecurityContext exists but escalation
		// is not explicitly disabled.
		if c.SecurityContext == nil {
			continue
		}
		if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Privilege Escalation Allowed",
				Description:  fmt.Sprintf("Container %s in pod %s: allowPrivilegeEscalation is true or not explicitly set to false.", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Set securityContext.allowPrivilegeEscalation: false",
				Metadata:     map[string]any{"container": c.Name},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

func checkCapabilitiesDrop(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	if targetOS == "windows" {
		return nil
	}
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
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
				Description:  fmt.Sprintf("Container %s in pod %s does not drop all capabilities. CIS Benchmark: drop ALL, then add only required.", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Add capabilities: { drop: [\"ALL\"] } to securityContext",
				Metadata:     map[string]any{"container": c.Name, "cis_benchmark": true},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

func checkSeccompProfile(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	if targetOS == "windows" {
		return nil
	}
	var findings []*core.Finding
	// Pod-level seccomp. A Localhost profile points to a node-loaded profile that
	// is typically MORE restrictive than RuntimeDefault, so it counts as configured.
	podHasSeccomp := false
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		if isConfiguredSeccompType(pod.Spec.SecurityContext.SeccompProfile.Type) {
			podHasSeccomp = true
		}
	}
	for _, c := range allContainers(pod) {
		if podHasSeccomp {
			continue
		}
		containerHasSeccomp := false
		if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
			if isConfiguredSeccompType(c.SecurityContext.SeccompProfile.Type) {
				containerHasSeccomp = true
			}
		}
		if !containerHasSeccomp {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityLow,
				Category:     "container",
				Title:        "Seccomp Profile Not Set to RuntimeDefault",
				Description:  fmt.Sprintf("Container %s in pod %s does not use seccompProfile.type: RuntimeDefault", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Add securityContext.seccompProfile.type: RuntimeDefault at pod or container level",
				Metadata:     map[string]any{"container": c.Name, "pss_violation": true},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

// isConfiguredSeccompType reports whether a seccomp profile type provides real
// syscall filtering. Both RuntimeDefault and Localhost qualify; only an unset or
// Unconfined profile leaves syscalls unrestricted.
func isConfiguredSeccompType(t corev1.SeccompProfileType) bool {
	return t == corev1.SeccompProfileTypeRuntimeDefault || t == corev1.SeccompProfileTypeLocalhost
}

func checkImageTags(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		image := c.Image
		// imageHasExplicitTag ignores the ":" in a registry host:port prefix so an
		// untagged image like "myreg:5000/app" is still caught as latest.
		if !imageHasExplicitTag(image) || strings.HasSuffix(image, ":latest") {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityInfo,
				Category:     "workload",
				Title:        "Image Using Latest Tag",
				Description:  fmt.Sprintf("Container %s in pod %s uses :latest tag or no tag — unpredictable", c.Name, pod.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Use specific image tags (e.g., nginx:1.21.0) instead of :latest",
				Metadata:     map[string]any{"container": c.Name, "image": image},
				TargetOS:     targetOS,
				Confidence:   conf,
			})
		}
	}
	return findings
}

// High-confidence secret patterns — name/value matching
var secretEnvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|token|access_key|private_key|auth_token|db_pass)`),
}
var highConfidenceEnvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                   // AWS key
	regexp.MustCompile(`ghp_[A-Za-z0-9_]{36,}`),              // GitHub token
	regexp.MustCompile(`-----BEGIN [A-Z]+ PRIVATE KEY-----`), // private key
}

func checkSecretsInEnv(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		for _, env := range c.Env {
			// Skip env vars sourced from K8s Secrets/ConfigMaps — already secure
			if env.ValueFrom != nil {
				continue
			}
			val := env.Value
			if val == "" {
				continue
			}

			// Check for high-confidence patterns in value first
			highConf := false
			for _, re := range highConfidenceEnvPatterns {
				if re.MatchString(val) {
					highConf = true
					break
				}
			}

			// Check name pattern
			nameMatch := false
			for _, re := range secretEnvPatterns {
				if re.MatchString(env.Name) {
					nameMatch = true
					break
				}
			}

			if !highConf && !nameMatch {
				continue
			}

			sev := core.SeverityHigh
			detConf := core.ConfidenceHigh
			if nameMatch && !highConf {
				sev = core.SeverityMedium
				detConf = core.ConfidenceMedium
			}

			findings = append(findings, &core.Finding{
				Severity:     sev,
				Category:     "secrets",
				Title:        "Secret in Environment Variable",
				Description:  fmt.Sprintf("Container %s in pod %s has plaintext secret in env var %s", c.Name, pod.Name, env.Name),
				ResourceType: "Pod",
				ResourceName: pod.Name,
				Namespace:    pod.Namespace,
				Remediation:  "Use secretKeyRef instead of plaintext env values",
				Metadata:     map[string]any{"container": c.Name, "env_var": env.Name},
				TargetOS:     targetOS,
				Confidence:   detConf,
			})
		}
	}
	return findings
}

func checkServiceAccountToken(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	automount := true
	if pod.Spec.AutomountServiceAccountToken != nil {
		automount = *pod.Spec.AutomountServiceAccountToken
	}
	if !automount {
		return nil
	}

	// Skip pods on the default SA — default SA without token is separately caught by
	// RBAC scanner; auto-mounting on default SA is low signal (almost universal default).
	saName := pod.Spec.ServiceAccountName
	if saName == "" || saName == "default" {
		return nil
	}

	return []*core.Finding{{
		Severity:     core.SeverityMedium,
		Category:     "secrets",
		Title:        "Service Account Token Auto-mounted",
		Description:  fmt.Sprintf("Pod %s uses service account '%s' and auto-mounts its token at /var/run/secrets/kubernetes.io/serviceaccount/token — compromised container can call Kubernetes API.", pod.Name, saName),
		ResourceType: "Pod",
		ResourceName: pod.Name,
		Namespace:    pod.Namespace,
		Remediation:  "Set automountServiceAccountToken: false if the pod doesn't need API access. Or disable at the ServiceAccount level.",
		TargetOS:     targetOS,
		Confidence:   conf,
	}}
}

// --- Crypto miner detection ---

var minerImageKeywords = []string{
	"xmrig", "minergate", "cryptonight", "monero", "ethminer",
	"cgminer", "bfgminer", "cpuminer", "nicehash", "claymore",
	"nanopool", "teamredminer", "lolminer", "phoenixminer", "nbminer",
	"gminer", "trex-miner", "kawpow", "cryptominer", "coinhive",
	"coinimp", "jsecoin", "minergate",
}

// Known mining pool / stratum protocol ports
var minerPorts = map[int32]string{
	3333:  "stratum (xmrig default)",
	4444:  "stratum (ethminer default)",
	7777:  "stratum (cgminer default)",
	8888:  "stratum (mining pool)",
	14433: "stratum+ssl",
	14444: "stratum (monero)",
	45700: "stratum (nicehash)",
	3256:  "stratum (mining proxy)",
	5555:  "stratum (ethOS)",
}

var minerEnvPatterns = []string{
	"POOL_URL", "POOL_PASS", "WALLET_ADDR", "WALLET_ADDRESS",
	"MINING_POOL", "WORKER_NAME", "COIN_ALGO", "XMR_WALLET",
	"ETH_WALLET", "STRATUM_URL", "MINING_KEY",
}

func checkCryptoMiner(containers, initContainers []corev1.Container, rt, rn, ns, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	all := make([]corev1.Container, 0, len(containers)+len(initContainers))
	all = append(all, containers...)
	all = append(all, initContainers...)
	for _, c := range all {
		imgLower := strings.ToLower(c.Image)
		for _, kw := range minerImageKeywords {
			if strings.Contains(imgLower, kw) {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityCritical,
					Category:     "runtime-threat",
					Title:        "Crypto Miner Container Detected",
					Description:  fmt.Sprintf("Container '%s' in %s '%s' uses image '%s' — recognized crypto miner image.", c.Name, rt, rn, c.Image),
					ResourceType: rt, ResourceName: rn, Namespace: ns,
					Remediation: "Remove the miner container immediately. Investigate how it was deployed — likely indicates cluster compromise.",
					Metadata:    map[string]any{"container": c.Name, "image": c.Image, "keyword": kw},
					TargetOS:    targetOS,
					Confidence:  core.ConfidenceHigh,
				})
				break
			}
		}

		// Check for mining pool ports
		for _, port := range c.Ports {
			if desc, ok := minerPorts[port.ContainerPort]; ok {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "runtime-threat",
					Title:        "Crypto Mining Pool Port Detected",
					Description:  fmt.Sprintf("Container '%s' in %s '%s' exposes port %d (%s) — common crypto mining stratum protocol port.", c.Name, rt, rn, port.ContainerPort, desc),
					ResourceType: rt, ResourceName: rn, Namespace: ns,
					Remediation: "Investigate this container for crypto mining activity. Block outbound stratum traffic via NetworkPolicy.",
					Metadata:    map[string]any{"container": c.Name, "port": port.ContainerPort},
					TargetOS:    targetOS,
					Confidence:  core.ConfidenceMedium,
				})
			}
		}

		// Check for miner-specific env vars
		for _, env := range c.Env {
			for _, pattern := range minerEnvPatterns {
				if strings.EqualFold(env.Name, pattern) {
					findings = append(findings, &core.Finding{
						Severity:     core.SeverityHigh,
						Category:     "runtime-threat",
						Title:        "Crypto Mining Configuration in Environment Variable",
						Description:  fmt.Sprintf("Container '%s' in %s '%s' has env var '%s' — typical crypto miner configuration variable.", c.Name, rt, rn, env.Name),
						ResourceType: rt, ResourceName: rn, Namespace: ns,
						Remediation: "Remove miner configuration. Audit how this workload was created.",
						Metadata:    map[string]any{"container": c.Name, "env_var": env.Name},
						TargetOS:    targetOS,
						Confidence:  core.ConfidenceMedium,
					})
					break
				}
			}
		}
	}
	return findings
}

// --- DIND (Docker-in-Docker) detection ---

var dindImageKeywords = []string{
	"docker:dind", "docker:latest", "docker:stable", "docker:rc",
	"jpetazzo/dind", "docker-in-docker",
}

func checkDIND(volumes []corev1.Volume, containers, initContainers []corev1.Container, rt, rn, ns, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	all := make([]corev1.Container, 0, len(containers)+len(initContainers))
	all = append(all, containers...)
	all = append(all, initContainers...)

	// Detect docker:dind image — always a flag in production workloads
	for _, c := range all {
		imgLower := strings.ToLower(c.Image)
		for _, kw := range dindImageKeywords {
			if strings.HasPrefix(imgLower, kw) || strings.Contains(imgLower, "/"+kw) {
				priv := c.SecurityContext != nil && utils.BoolVal(c.SecurityContext.Privileged)
				sev := core.SeverityHigh
				if priv {
					sev = core.SeverityCritical
				}
				findings = append(findings, &core.Finding{
					Severity:     sev,
					Category:     "container",
					Title:        "Docker-in-Docker (DIND) Container Detected",
					Description:  fmt.Sprintf("Container '%s' in %s '%s' runs a Docker daemon inside a container (image: %s). DIND grants access to the Docker daemon, enabling container escape to the host.", c.Name, rt, rn, c.Image),
					ResourceType: rt, ResourceName: rn, Namespace: ns,
					Remediation: "Replace DIND with rootless container builds (kaniko, buildah, img). DIND requires privileged mode — use rootless builders instead.",
					Metadata:    map[string]any{"container": c.Name, "image": c.Image, "privileged": priv},
					TargetOS:    targetOS,
					Confidence:  core.ConfidenceHigh,
				})
				break
			}
		}
	}

	return findings
}

// --- Trusted operator helpers ---

var trustedOperatorPrefixes = []string{
	"calico", "cert-manager", "ingress-nginx", "istio", "linkerd",
	"flannel", "weave", "cilium", "coredns", "metrics-server",
	"kube-proxy", "node-exporter", "prometheus", "grafana", "datadog",
	"fluentd", "fluentbit", "vector", "velero", "argocd", "flux",
	"external-secrets", "external-dns", "karpenter", "cluster-autoscaler",
}

var trustedOperatorNamespaces = utils.NewStringSet(
	"kube-system", "kube-public", "kube-node-lease",
	"cert-manager", "ingress-nginx", "istio-system", "linkerd",
	"monitoring", "logging", "argocd", "flux-system",
)

func isTrustedOperator(pod corev1.Pod) bool {
	if trustedOperatorNamespaces.Has(pod.Namespace) {
		return true
	}
	return utils.HasAnyPrefix(pod.Name, trustedOperatorPrefixes) ||
		utils.HasAnyPrefix(pod.Namespace, trustedOperatorPrefixes)
}

// ─── Explicit root user ──────────────────────────────────────────────────────

func checkExplicitRootUser(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "container",
				Title:        "Container Explicitly Runs as Root (UID 0)",
				Description:  fmt.Sprintf("Container '%s' in pod '%s' sets runAsUser: 0 — explicitly running as root. Even with runAsNonRoot: false this is a deliberate misconfiguration.", c.Name, pod.Name),
				ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
				Remediation: "Set runAsUser to a non-zero UID (e.g. 1000) and runAsNonRoot: true.",
				TargetOS:    targetOS, Confidence: conf,
			})
		}
	}
	// Pod-level check
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "container",
			Title:        "Container Explicitly Runs as Root (UID 0)",
			Description:  fmt.Sprintf("Pod '%s' sets pod-level runAsUser: 0 — all containers run as root unless overridden.", pod.Name),
			ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
			Remediation: "Set runAsUser to a non-zero UID and runAsNonRoot: true at pod or container level.",
			TargetOS:    targetOS, Confidence: conf,
		})
	}
	return findings
}

// ─── hostPort usage ──────────────────────────────────────────────────────────

func checkHostPorts(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		for _, p := range c.Ports {
			if p.HostPort > 0 {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "container",
					Title:        "Container HostPort Binding",
					Description:  fmt.Sprintf("Container '%s' in pod '%s' binds hostPort %d — the port is exposed directly on the node's IP, bypassing NetworkPolicy and Service abstractions.", c.Name, pod.Name, p.HostPort),
					ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
					Remediation: "Use a Service (ClusterIP/NodePort/LoadBalancer) instead of hostPort. HostPort is a node-level binding that breaks network policy enforcement.",
					TargetOS:    targetOS, Confidence: conf,
					Metadata: map[string]any{"container": c.Name, "host_port": p.HostPort},
				})
			}
		}
	}
	return findings
}

// ─── Unsafe sysctls ──────────────────────────────────────────────────────────

var unsafeSysctlPrefixes = []string{
	"kernel.shm", "kernel.msg", "kernel.sem",
	"fs.mqueue", "net.",
}

func checkUnsafeSysctls(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	sc := pod.Spec.SecurityContext
	if sc == nil || len(sc.Sysctls) == 0 {
		return nil
	}
	var findings []*core.Finding
	for _, s := range sc.Sysctls {
		for _, prefix := range unsafeSysctlPrefixes {
			if strings.HasPrefix(s.Name, prefix) {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "container",
					Title:        "Unsafe Sysctl Parameter",
					Description:  fmt.Sprintf("Pod '%s' sets sysctl '%s=%s' — modifying kernel parameters can destabilize the node or enable privilege escalation.", pod.Name, s.Name, s.Value),
					ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
					Remediation: "Remove unsafe sysctl settings. If required, use only safe sysctls listed in the Kubernetes documentation and enforce with Pod Security Admission.",
					TargetOS:    targetOS, Confidence: conf,
					Metadata: map[string]any{"sysctl": s.Name, "value": s.Value},
				})
				break
			}
		}
	}
	return findings
}

// ─── shareProcessNamespace ───────────────────────────────────────────────────

func checkShareProcessNamespace(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	if pod.Spec.ShareProcessNamespace == nil || !*pod.Spec.ShareProcessNamespace {
		return nil
	}
	return []*core.Finding{{
		Severity:     core.SeverityMedium,
		Category:     "container",
		Title:        "Shared Process Namespace Enabled",
		Description:  fmt.Sprintf("Pod '%s' has shareProcessNamespace: true — all containers share the same PID namespace and can inspect each other's processes and memory.", pod.Name),
		ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
		Remediation: "Set shareProcessNamespace: false (default). Only enable if a sidecar must signal the main process (e.g. log rotation).",
		TargetOS:    targetOS, Confidence: conf,
	}}
}

// ─── terminationGracePeriodSeconds: 0 ────────────────────────────────────────

func checkTerminationGracePeriod(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	if pod.Spec.TerminationGracePeriodSeconds == nil || *pod.Spec.TerminationGracePeriodSeconds != 0 {
		return nil
	}
	return []*core.Finding{{
		Severity:     core.SeverityMedium,
		Category:     "container",
		Title:        "Zero Termination Grace Period",
		Description:  fmt.Sprintf("Pod '%s' sets terminationGracePeriodSeconds: 0 — containers receive SIGKILL immediately with no chance to flush buffers, close connections, or complete in-flight requests.", pod.Name),
		ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
		Remediation: "Set terminationGracePeriodSeconds to at least 30 seconds. Implement SIGTERM handler in your application for graceful shutdown.",
		TargetOS:    targetOS, Confidence: conf,
	}}
}

// ─── Bidirectional MountPropagation ──────────────────────────────────────────

func checkBidirectionalMount(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		for _, vm := range c.VolumeMounts {
			if vm.MountPropagation != nil && *vm.MountPropagation == corev1.MountPropagationBidirectional {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "container",
					Title:        "Bidirectional Volume Mount Propagation",
					Description:  fmt.Sprintf("Container '%s' in pod '%s' uses Bidirectional mount propagation on volume '%s' — the container can create mounts on the host that persist after the container exits.", c.Name, pod.Name, vm.Name),
					ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
					Remediation: "Use HostToContainer or None mount propagation. Bidirectional requires privileged mode and allows host filesystem manipulation.",
					TargetOS:    targetOS, Confidence: conf,
					Metadata: map[string]any{"container": c.Name, "volume": vm.Name},
				})
			}
		}
	}
	return findings
}

// ─── SSH server detection ────────────────────────────────────────────────────

var sshKeywords = []string{"sshd", "openssh", "ssh-server", "/usr/sbin/sshd"}

func checkSSHServer(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		detected := false
		for _, kw := range sshKeywords {
			for _, arg := range append(c.Command, c.Args...) {
				if strings.Contains(strings.ToLower(arg), kw) {
					detected = true
					break
				}
			}
			if strings.Contains(strings.ToLower(c.Image), kw) {
				detected = true
			}
			if detected {
				break
			}
		}
		if detected {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "container",
				Title:        "SSH Server Running in Container",
				Description:  fmt.Sprintf("Container '%s' in pod '%s' appears to run an SSH server — SSH in containers creates a persistent backdoor and bypasses Kubernetes audit logging.", c.Name, pod.Name),
				ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
				Remediation: "Remove the SSH server. Use 'kubectl exec' for debugging. For remote access, use ephemeral debug containers.",
				TargetOS:    targetOS, Confidence: core.ConfidenceMedium,
				Metadata: map[string]any{"container": c.Name, "image": c.Image},
			})
		}
	}
	return findings
}

// ─── procMount Unmasked ──────────────────────────────────────────────────────

func checkProcMountUnmasked(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		if c.SecurityContext != nil && c.SecurityContext.ProcMount != nil {
			if *c.SecurityContext.ProcMount == corev1.UnmaskedProcMount {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "container",
					Title:        "Unmasked Proc Filesystem Mount",
					Description:  fmt.Sprintf("Container '%s' in pod '%s' uses procMount: Unmasked — exposes the full host /proc filesystem, enabling host information disclosure and potential privilege escalation.", c.Name, pod.Name),
					ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
					Remediation: "Remove procMount: Unmasked. Use the default (Default) proc mount which masks sensitive /proc paths.",
					TargetOS:    targetOS, Confidence: conf,
					Metadata: map[string]any{"container": c.Name},
				})
			}
		}
	}
	return findings
}

// ─── Init container privilege escalation ─────────────────────────────────────

func checkInitContainerPrivEsc(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, c := range pod.Spec.InitContainers {
		if c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "container",
				Title:        "Init Container Allows Privilege Escalation",
				Description:  fmt.Sprintf("Init container '%s' in pod '%s' has allowPrivilegeEscalation: true — init containers run before the application and can obtain elevated privileges during setup.", c.Name, pod.Name),
				ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
				Remediation: "Set allowPrivilegeEscalation: false on all init containers. They should perform only the minimum setup required.",
				TargetOS:    targetOS, Confidence: conf,
				Metadata: map[string]any{"init_container": c.Name},
			})
		}
	}
	return findings
}

// ─── AppArmor profile ────────────────────────────────────────────────────────

func checkAppArmorProfile(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	if targetOS == "windows" {
		return nil
	}
	var findings []*core.Finding
	for _, c := range allContainers(pod) {
		if hasAppArmorConfigured(pod, c) {
			continue
		}
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "container",
			Title:        "No AppArmor Profile Configured",
			Description:  fmt.Sprintf("Container '%s' in pod '%s' has no AppArmor profile — kernel Mandatory Access Control (MAC) enforcement is disabled, leaving all syscalls unrestricted.", c.Name, pod.Name),
			ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
			Remediation: "Set securityContext.appArmorProfile.type: RuntimeDefault (k8s 1.30+), or the legacy annotation 'container.apparmor.security.beta.kubernetes.io/<container>: runtime/default'.",
			TargetOS:    targetOS, Confidence: conf,
			Metadata: map[string]any{"container": c.Name},
		})
	}
	return findings
}

// hasAppArmorConfigured reports whether an AppArmor profile is enforced for the
// container via any supported mechanism:
//   - the k8s 1.30+ securityContext.appArmorProfile field (container or pod level)
//   - the legacy beta annotation container.apparmor.security.beta.kubernetes.io/<name>
//
// An Unconfined profile (either form) counts as NOT configured.
func hasAppArmorConfigured(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && isEnforcedAppArmor(c.SecurityContext.AppArmorProfile) {
		return true
	}
	if pod.Spec.SecurityContext != nil && isEnforcedAppArmor(pod.Spec.SecurityContext.AppArmorProfile) {
		return true
	}
	annotationKey := "container.apparmor.security.beta.kubernetes.io/" + c.Name
	if val, ok := pod.Annotations[annotationKey]; ok && val != "" && val != "unconfined" {
		return true
	}
	return false
}

func isEnforcedAppArmor(p *corev1.AppArmorProfile) bool {
	if p == nil {
		return false
	}
	return p.Type == corev1.AppArmorProfileTypeRuntimeDefault || p.Type == corev1.AppArmorProfileTypeLocalhost
}

// ─── Ephemeral container security context ────────────────────────────────────

func checkEphemeralContainerSecurity(pod corev1.Pod, targetOS string, conf core.Confidence) []*core.Finding {
	var findings []*core.Finding
	for _, ec := range pod.Spec.EphemeralContainers {
		if ec.SecurityContext == nil {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "container",
				Title:        "Ephemeral Container Without Security Context",
				Description:  fmt.Sprintf("Ephemeral container '%s' in pod '%s' has no securityContext — debug containers run without restrictions and can be used for privilege escalation.", ec.Name, pod.Name),
				ResourceType: "Pod", ResourceName: pod.Name, Namespace: pod.Namespace,
				Remediation: "Add securityContext to ephemeral containers with at minimum: runAsNonRoot: true, allowPrivilegeEscalation: false.",
				TargetOS:    targetOS, Confidence: conf,
				Metadata: map[string]any{"ephemeral_container": ec.Name},
			})
		}
	}
	return findings
}

var _ core.Scanner = PodScanner{}
