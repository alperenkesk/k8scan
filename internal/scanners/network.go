package scanners

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/alperenkeskin/k8scan/internal/core"
	"github.com/alperenkeskin/k8scan/internal/utils"
)

// NetworkScanner checks NetworkPolicies, Services, and Ingress resources.
type NetworkScanner struct{}

func (NetworkScanner) Name() string { return "Network Security" }

func (NetworkScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	namespaces, err := client.GetAllNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := client.GetAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	netpols, err := client.GetAllNetworkPolicies(ctx)
	if err != nil {
		return nil, err
	}
	services, err := client.GetAllServices(ctx)
	if err != nil {
		return nil, err
	}
	ingresses, err := client.GetAllIngresses(ctx)
	if err != nil {
		return nil, err
	}
	quotas, err := client.GetAllResourceQuotas(ctx)
	if err != nil {
		return nil, err
	}
	limitRanges, err := client.GetAllLimitRanges(ctx)
	if err != nil {
		return nil, err
	}
	endpoints, err := client.GetAllEndpoints(ctx)
	if err != nil {
		return nil, err
	}

	nc := utils.NewNamespaceClassifier()
	var findings []*core.Finding

	findings = append(findings, checkMissingNetworkPolicies(namespaces, netpols, nc)...)
	if isCloudCluster(nodes) {
		findings = append(findings, checkCloudMetadataExposure(namespaces, netpols, nc)...)
	}
	findings = append(findings, checkNamespaceResourceGovernance(namespaces, quotas, limitRanges, nc)...)
	findings = append(findings, checkCrossNamespaceIsolation(namespaces, netpols, nc)...)
	findings = append(findings, checkEndpointSSRF(endpoints)...)
	findings = append(findings, checkUnauthenticatedDataStores(services, netpols, nc)...)

	for _, np := range netpols {
		findings = append(findings, checkNetworkPolicy(np)...)
	}

	for _, svc := range services {
		findings = append(findings, checkService(svc)...)
	}

	for _, ing := range ingresses {
		findings = append(findings, checkIngress(ing)...)
	}

	return findings, nil
}

// ─── Network policy checks ────────────────────────────────────────────────────

func namespacesWithNetpols(netpols []networkingv1.NetworkPolicy) utils.StringSet {
	covered := utils.NewStringSet()
	for _, np := range netpols {
		covered.Add(np.Namespace)
	}
	return covered
}

func checkMissingNetworkPolicies(
	namespaces []corev1.Namespace,
	netpols []networkingv1.NetworkPolicy,
	nc *utils.NamespaceClassifier,
) []*core.Finding {
	covered := namespacesWithNetpols(netpols)
	var findings []*core.Finding

	for _, ns := range namespaces {
		name := ns.Name
		if nc.IsLowRiskForNetworkPolicy(name) {
			continue
		}
		if covered.Has(name) {
			continue
		}

		severity := core.SeverityMedium
		nsClass := nc.Classify(name)
		if nsClass == utils.NSClassProduction {
			severity = core.SeverityHigh
		}

		findings = append(findings, &core.Finding{
			Severity:     severity,
			Category:     "network",
			Title:        "Missing Network Policy",
			Description:  fmt.Sprintf("Namespace '%s' has no NetworkPolicy. All pods can communicate freely — no micro-segmentation.", name),
			ResourceType: "Namespace",
			ResourceName: name,
			Namespace:    name,
			Remediation:  "Apply a default-deny-all NetworkPolicy and allow only required traffic explicitly.",
		})
	}
	return findings
}

// isCloudCluster returns true when at least one node has a cloud providerID
// (aws://, gce://, azure://, digitalocean://, vsphere://, openstack://).
// On kind, minikube, and bare-metal clusters providerID is empty or "kind://".
func isCloudCluster(nodes []corev1.Node) bool {
	cloudPrefixes := []string{"aws://", "gce://", "azure://", "digitalocean://", "vsphere://", "openstack://", "alicloud://"}
	for _, node := range nodes {
		for _, prefix := range cloudPrefixes {
			if strings.HasPrefix(node.Spec.ProviderID, prefix) {
				return true
			}
		}
	}
	return false
}

// checkCloudMetadataExposure flags namespaces that do NOT have an egress rule
// explicitly blocking 169.254.169.254 (cloud metadata API). Pods in such
// namespaces can steal cloud IAM credentials via SSRF.
// Only called when isCloudCluster() is true — on-prem/kind clusters skip this check.
func checkCloudMetadataExposure(
	namespaces []corev1.Namespace,
	netpols []networkingv1.NetworkPolicy,
	nc *utils.NamespaceClassifier,
) []*core.Finding {
	// Build: namespace → set of blocked egress CIDRs
	blockedCIDRs := make(map[string]bool)
	for _, np := range netpols {
		if !hasEgressPolicyType(np) {
			continue
		}
		for _, rule := range np.Spec.Egress {
			for _, ipBlock := range rule.To {
				if ipBlock.IPBlock != nil {
					if strings.HasPrefix(ipBlock.IPBlock.CIDR, "169.254.169.254") {
						// This CIDR is allowed, not blocked.
						// Cloud metadata is blocked only if it appears in an Except list or denied by default-deny.
					}
					// Default-deny egress (empty To) with no explicit allow to 169.254.169.254 means it's blocked.
				}
			}
		}
		// A NetworkPolicy that has Egress type + empty Egress rules = deny-all egress = metadata blocked
		if hasEgressPolicyType(np) && len(np.Spec.Egress) == 0 {
			blockedCIDRs[np.Namespace] = true
		}
		// Also consider: explicit metadata block via except
		for _, rule := range np.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil {
					for _, except := range peer.IPBlock.Except {
						if strings.HasPrefix(except, "169.254.169.254") {
							blockedCIDRs[np.Namespace] = true
						}
					}
				}
			}
		}
	}

	var findings []*core.Finding
	for _, ns := range namespaces {
		name := ns.Name
		if nc.IsLowRiskForNetworkPolicy(name) {
			continue
		}
		if blockedCIDRs[name] {
			continue
		}
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "network",
			Title:        "Cloud Metadata API Exposed",
			Description:  fmt.Sprintf("Namespace '%s' has no egress NetworkPolicy blocking 169.254.169.254 (cloud metadata API). Pods may steal cloud IAM credentials via SSRF.", name),
			ResourceType: "Namespace",
			ResourceName: name,
			Namespace:    name,
			Remediation:  "Add a NetworkPolicy with egress rule that excludes 169.254.169.254/32, or use a default-deny egress policy.",
			Confidence:   core.ConfidenceLow,
		})
	}
	return findings
}

func checkNetworkPolicy(np networkingv1.NetworkPolicy) []*core.Finding {
	var findings []*core.Finding
	name := np.Name
	ns := np.Namespace

	for _, rule := range np.Spec.Ingress {
		if isPermissiveIngressRule(rule) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "network",
				Title:        "Permissive Ingress Rule",
				Description:  fmt.Sprintf("NetworkPolicy '%s' has an overly permissive ingress rule allowing traffic from all pods/namespaces.", name),
				ResourceType: "NetworkPolicy",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Restrict ingress rules to specific pod selectors and namespace selectors.",
			})
			break
		}
		if hasBroadNamespaceSelector(rule) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "network",
				Title:        "Broad Namespace Selector",
				Description:  fmt.Sprintf("NetworkPolicy '%s' uses a namespace selector that matches many or all namespaces.", name),
				ResourceType: "NetworkPolicy",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Use specific namespace labels to limit ingress scope.",
			})
			break
		}
	}

	for _, rule := range np.Spec.Egress {
		if isPermissiveEgressRule(rule) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "network",
				Title:        "Egress Allow-All Policy",
				Description:  fmt.Sprintf("NetworkPolicy '%s' declares Egress type but has an allow-all rule — all outbound traffic is permitted, negating egress enforcement and enabling data exfiltration.", name),
				ResourceType: "NetworkPolicy",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Replace the allow-all egress rule with explicit destination selectors (pods, namespaces, IP blocks). Deny all by default and allow only required traffic.",
			})
			break
		}
	}

	if hasIngressPolicyType(np) && !hasEgressPolicyType(np) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "network",
			Title:        "No Egress Policy Defined",
			Description:  fmt.Sprintf("NetworkPolicy '%s' defines ingress rules but no egress policy — outbound traffic is unrestricted.", name),
			ResourceType: "NetworkPolicy",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Add egress rules to restrict outbound traffic from pods.",
		})
	}

	if hasEgressPolicyType(np) && len(np.Spec.Egress) == 0 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "network",
			Title:        "Deny-All Egress Blocks DNS Resolution",
			Description:  fmt.Sprintf("NetworkPolicy '%s' enforces deny-all egress (no egress rules). While this hardens outbound traffic, it also blocks DNS (UDP/TCP 53 to kube-dns) — pods will fail to resolve service names unless a DNS egress exception is added.", name),
			ResourceType: "NetworkPolicy",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Add an explicit egress rule for DNS: allow UDP/TCP port 53 to kube-system namespace (kube-dns), then allow only the specific upstream services your pods need.",
		})
	}

	return findings
}

func isPermissiveIngressRule(rule networkingv1.NetworkPolicyIngressRule) bool {
	// len(From)==0 means "allow from all sources" — this IS permissive (not deny-all;
	// deny-all is represented by having NO ingress rules at all, not an empty From).
	if len(rule.From) == 0 {
		return true
	}
	for _, peer := range rule.From {
		// Empty NamespaceSelector (no matchLabels, no matchExpressions) = matches ALL namespaces.
		if peer.NamespaceSelector != nil && len(peer.NamespaceSelector.MatchLabels) == 0 &&
			len(peer.NamespaceSelector.MatchExpressions) == 0 &&
			peer.PodSelector == nil {
			return true
		}
	}
	return false
}

func hasBroadNamespaceSelector(rule networkingv1.NetworkPolicyIngressRule) bool {
	for _, peer := range rule.From {
		if peer.NamespaceSelector != nil && len(peer.NamespaceSelector.MatchLabels) == 0 {
			return true
		}
	}
	return false
}

func isPermissiveEgressRule(rule networkingv1.NetworkPolicyEgressRule) bool {
	// len(To)==0 in a rule means "allow to all destinations" — permissive.
	// (Deny-all egress = PolicyType Egress with ZERO rules, handled separately.)
	if len(rule.To) == 0 {
		return true
	}
	for _, peer := range rule.To {
		if peer.NamespaceSelector != nil && len(peer.NamespaceSelector.MatchLabels) == 0 &&
			len(peer.NamespaceSelector.MatchExpressions) == 0 &&
			peer.PodSelector == nil && peer.IPBlock == nil {
			return true
		}
	}
	return false
}

func hasIngressPolicyType(np networkingv1.NetworkPolicy) bool {
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

func hasEgressPolicyType(np networkingv1.NetworkPolicy) bool {
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeEgress {
			return true
		}
	}
	return false
}

// ─── Service checks ───────────────────────────────────────────────────────────

var sensitiveDbPorts = map[int32]string{
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
	27018: "MongoDB",
	6379:  "Redis",
	6380:  "Redis",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch",
	5984:  "CouchDB",
	7474:  "Neo4j",
	9042:  "Cassandra",
	// Note: port 5000 (container registry) is handled separately by the
	// dedicated "Insecure Private Container Registry Exposed" check below,
	// with a different severity model. It is intentionally NOT in this map.
}

func checkService(svc corev1.Service) []*core.Finding {
	var findings []*core.Finding
	name := svc.Name
	ns := svc.Namespace

	if isSystemNamespace(ns) {
		return nil
	}

	switch svc.Spec.Type {
	case corev1.ServiceTypeNodePort:
		var nodePorts []interface{}
		for _, port := range svc.Spec.Ports {
			if port.NodePort != 0 {
				nodePorts = append(nodePorts, port.NodePort)
			}
		}
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "network",
			Title:        "NodePort Service Exposed",
			Description:  fmt.Sprintf("Service '%s' uses NodePort type — exposes port on every cluster node's IP.", name),
			ResourceType: "Service",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Replace NodePort with LoadBalancer or Ingress for controlled external access.",
			Metadata:     map[string]any{"ports": nodePorts},
		})

		for _, port := range svc.Spec.Ports {
			if dbName, ok := sensitiveDbPorts[port.Port]; ok {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityCritical,
					Category:     "network",
					Title:        "Exposed Sensitive Database",
					Description:  fmt.Sprintf("Service '%s' exposes %s (port %d) via NodePort — database directly accessible from all nodes.", name, dbName, port.Port),
					ResourceType: "Service",
					ResourceName: name,
					Namespace:    ns,
					Remediation:  "Change service type to ClusterIP. Databases should not be directly accessible from outside the cluster.",
				})
			}
		}

	case corev1.ServiceTypeLoadBalancer:
		if len(svc.Spec.LoadBalancerSourceRanges) == 0 {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "network",
				Title:        "LoadBalancer Without Source Ranges",
				Description:  fmt.Sprintf("LoadBalancer service '%s' has no loadBalancerSourceRanges — accessible from the entire internet (0.0.0.0/0).", name),
				ResourceType: "Service",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Set spec.loadBalancerSourceRanges to restrict access to specific IP ranges.",
			})
		}

		for _, port := range svc.Spec.Ports {
			if dbName, ok := sensitiveDbPorts[port.Port]; ok {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityCritical,
					Category:     "network",
					Title:        "Exposed Sensitive Database",
					Description:  fmt.Sprintf("Service '%s' exposes %s (port %d) via LoadBalancer — database internet-facing.", name, dbName, port.Port),
					ResourceType: "Service",
					ResourceName: name,
					Namespace:    ns,
					Remediation:  "Change service type to ClusterIP. Use VPN or private cloud connectivity for database access.",
				})
			}
		}
	}

	if (svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort) &&
		svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeCluster {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityLow,
			Category:     "network",
			Title:        "externalTrafficPolicy: Cluster Loses Source IP",
			Description:  fmt.Sprintf("Service '%s' uses externalTrafficPolicy: Cluster (default) — the original client IP is SNAT'd to a node IP. Access logs, IP-based rate limiting, and geo-blocking cannot see the real client.", name),
			ResourceType: "Service",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Set externalTrafficPolicy: Local to preserve the source IP. Note: this may cause uneven load distribution — ensure readinessProbes are configured.",
		})
	}

	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer && svc.Annotations != nil {
		if scheme := svc.Annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"]; scheme == "internet-facing" {
			if _, hasACL := svc.Annotations["service.beta.kubernetes.io/load-balancer-source-ranges"]; !hasACL {
				if len(svc.Spec.LoadBalancerSourceRanges) == 0 {
					findings = append(findings, &core.Finding{
						Severity:     core.SeverityMedium,
						Category:     "network",
						Title:        "Internet-Facing LoadBalancer Without Source Restriction",
						Description:  fmt.Sprintf("Service '%s' is an internet-facing AWS ALB/NLB with no source IP restriction — accessible from the entire internet (0.0.0.0/0).", name),
						ResourceType: "Service",
						ResourceName: name,
						Namespace:    ns,
						Remediation:  "Add spec.loadBalancerSourceRanges or the 'service.beta.kubernetes.io/load-balancer-source-ranges' annotation to restrict access to known IP ranges.",
					})
				}
			}
		}
		// GCP: internal annotation missing but service is LoadBalancer
		if svc.Annotations["networking.gke.io/load-balancer-type"] == "" &&
			svc.Annotations["cloud.google.com/load-balancer-type"] == "" {
			// Only flag for GKE-style annotations if there's some GKE indicator
			// (conservative — don't flag on non-GKE clusters)
		}
	}

	// ExternalIPs risk — CVE-2020-8554, applies to any service type
	if len(svc.Spec.ExternalIPs) > 0 {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityHigh,
			Category:     "network",
			Title:        "ExternalIPs MITM / Hijacking Risk",
			Description:  fmt.Sprintf("Service '%s' uses externalIPs %v — CVE-2020-8554: an attacker can intercept traffic by claiming these IPs.", name, svc.Spec.ExternalIPs),
			ResourceType: "Service",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Remove externalIPs. Enforce via DenyServiceExternalIPs admission webhook.",
		})
	}

	// Port 5000 is commonly used by Docker/OCI registries (HTTP, no TLS) but is
	// also Flask/Python dev-server default and used by many internal apps.
	// Only treat as a registry-specific finding when the service or its workload
	// name actually looks like a registry — otherwise this fires on every Flask
	// app exposed via NodePort. False positive otherwise.
	if looksLikeRegistry(svc) {
		for _, port := range svc.Spec.Ports {
			if port.Port == 5000 && svc.Spec.Type != corev1.ServiceTypeClusterIP {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "network",
					Title:        "Insecure Private Container Registry Exposed",
					Description:  fmt.Sprintf("Service '%s' exposes port 5000 (container registry) without TLS via %s.", name, svc.Spec.Type),
					ResourceType: "Service",
					ResourceName: name,
					Namespace:    ns,
					Remediation:  "Enable TLS on the registry. Use ClusterIP with Ingress+TLS for external access.",
				})
			}
		}
	}

	return findings
}

// looksLikeRegistry returns true when the service name or its selector targets
// a workload that plausibly is an image registry. We stay conservative: only
// fire when "registry" or "docker" appears in the service name or selector
// values, otherwise port 5000 is far more often a Python/Flask app.
func looksLikeRegistry(svc corev1.Service) bool {
	lname := strings.ToLower(svc.Name)
	if strings.Contains(lname, "registry") || strings.Contains(lname, "harbor") {
		return true
	}
	for _, v := range svc.Spec.Selector {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "registry") || strings.Contains(lv, "harbor") {
			return true
		}
	}
	return false
}

// ─── Ingress checks ───────────────────────────────────────────────────────────

func checkIngress(ing networkingv1.Ingress) []*core.Finding {
	var findings []*core.Finding
	name := ing.Name
	ns := ing.Namespace

	if isSystemNamespace(ns) {
		return nil
	}

	annotations := ing.Annotations

	hasTLS := len(ing.Spec.TLS) > 0
	if !hasTLS {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityMedium,
			Category:     "network",
			Title:        "Missing TLS in Ingress",
			Description:  fmt.Sprintf("Ingress '%s' has no TLS configuration — traffic is served over HTTP, exposing credentials and session tokens.", name),
			ResourceType: "Ingress",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Add TLS section with a valid certificate (use cert-manager for automatic TLS).",
		})
	} else {
		rulesWithoutTLS := ingressRulesWithoutTLS(ing)
		if len(rulesWithoutTLS) > 0 {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "network",
				Title:        "Partial TLS Coverage in Ingress",
				Description:  fmt.Sprintf("Ingress '%s' has TLS for some hosts but rules for %s are not covered by TLS.", name, strings.Join(rulesWithoutTLS, ", ")),
				ResourceType: "Ingress",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Ensure all ingress rules are covered by a TLS certificate.",
			})
		}
	}

	for _, rule := range ing.Spec.Rules {
		if rule.Host == "" || rule.Host == "*" {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityHigh,
				Category:     "network",
				Title:        "Ingress Wildcard Host",
				Description:  fmt.Sprintf("Ingress '%s' has an empty or wildcard host — accepts requests for any domain name, bypassing virtual-host isolation and potentially exposing unintended backends.", name),
				ResourceType: "Ingress",
				ResourceName: name,
				Namespace:    ns,
				Remediation:  "Set a specific FQDN in spec.rules[].host. Never leave host empty in production Ingress resources.",
			})
			break
		}
	}

	if !hasAuthAnnotation(annotations) {
		findings = append(findings, &core.Finding{
			Severity:     core.SeverityInfo,
			Category:     "network",
			Title:        "Public Ingress (No Authentication/Whitelist)",
			Description:  fmt.Sprintf("Ingress '%s' has no authentication or IP whitelist annotation — backend may be publicly reachable without access controls.", name),
			ResourceType: "Ingress",
			ResourceName: name,
			Namespace:    ns,
			Remediation:  "Add authentication via nginx.ingress.kubernetes.io/auth-url or restrict access with whitelist-source-range.",
			Confidence:   core.ConfidenceLow,
		})
	}

	return findings
}

func ingressRulesWithoutTLS(ing networkingv1.Ingress) []string {
	tlsHosts := utils.NewStringSet()
	for _, tls := range ing.Spec.TLS {
		for _, h := range tls.Hosts {
			tlsHosts.Add(h)
		}
	}
	var uncovered []string
	for _, rule := range ing.Spec.Rules {
		if rule.Host != "" && !tlsHosts.Has(rule.Host) {
			uncovered = append(uncovered, rule.Host)
		}
	}
	return uncovered
}

func hasAuthAnnotation(annotations map[string]string) bool {
	if annotations == nil {
		return false
	}
	authAnnotations := []string{
		"nginx.ingress.kubernetes.io/auth-url",
		"nginx.ingress.kubernetes.io/auth-type",
		"nginx.ingress.kubernetes.io/whitelist-source-range",
		"traefik.ingress.kubernetes.io/router.middlewares",
		"alb.ingress.kubernetes.io/auth-type",
	}
	for _, a := range authAnnotations {
		if _, ok := annotations[a]; ok {
			return true
		}
	}
	return false
}

// isSystemNamespace delegates to utils.IsSystemNamespace — the single source of
// truth shared by all scanners. Keeps network.go in sync with pod.go/resource.go.
func isSystemNamespace(ns string) bool {
	return utils.IsSystemNamespace(ns)
}


// checkNamespaceResourceGovernance reports namespaces that have no ResourceQuota
// (DoS risk — a runaway pod can exhaust all cluster resources) and no LimitRange
// (containers get no default limits, same root cause).
func checkNamespaceResourceGovernance(
	namespaces []corev1.Namespace,
	quotas []corev1.ResourceQuota,
	limitRanges []corev1.LimitRange,
	nc *utils.NamespaceClassifier,
) []*core.Finding {
	quotaNS := utils.NewStringSet()
	for _, q := range quotas {
		quotaNS.Add(q.Namespace)
	}
	limitNS := utils.NewStringSet()
	for _, lr := range limitRanges {
		limitNS.Add(lr.Namespace)
	}

	var findings []*core.Finding
	for _, ns := range namespaces {
		name := ns.Name
		if isSystemNamespace(name) {
			continue
		}
		if !quotaNS.Has(name) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityLow,
				Category:     "workload",
				Title:        "Missing ResourceQuota on Namespace",
				Description:  fmt.Sprintf("Namespace '%s' has no ResourceQuota. A single misbehaving workload can exhaust CPU/memory for the entire namespace or cluster.", name),
				ResourceType: "Namespace",
				ResourceName: name,
				Namespace:    name,
				Remediation:  "Define a ResourceQuota with CPU, memory, and pod count limits for every namespace.",
			})
		}
		if !limitNS.Has(name) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityInfo,
				Category:     "workload",
				Title:        "Missing LimitRange on Namespace",
				Description:  fmt.Sprintf("Namespace '%s' has no LimitRange. Containers without explicit limits inherit no defaults and can consume unbounded resources.", name),
				ResourceType: "Namespace",
				ResourceName: name,
				Namespace:    name,
				Remediation:  "Add a LimitRange to set default CPU/memory requests and limits for all containers in the namespace.",
			})
		}
	}
	return findings
}

// ─── N-03: Cross-namespace isolation ─────────────────────────────────────────
// Flags namespaces that have a NetworkPolicy with an ingress rule allowing
// traffic from ALL namespaces (empty namespaceSelector), meaning pods in any
// namespace can reach this namespace without restriction.

func checkCrossNamespaceIsolation(
	namespaces []corev1.Namespace,
	netpols []networkingv1.NetworkPolicy,
	nc *utils.NamespaceClassifier,
) []*core.Finding {
	// Build set of namespaces where any ingress rule allows from all namespaces
	openToAll := utils.NewStringSet()
	for _, np := range netpols {
		for _, rule := range np.Spec.Ingress {
			for _, peer := range rule.From {
				// Empty namespaceSelector (non-nil but no matchLabels/expressions) = all namespaces
				if peer.NamespaceSelector != nil &&
					len(peer.NamespaceSelector.MatchLabels) == 0 &&
					len(peer.NamespaceSelector.MatchExpressions) == 0 {
					openToAll.Add(np.Namespace)
				}
			}
		}
	}

	var findings []*core.Finding
	for _, ns := range namespaces {
		name := ns.Name
		if nc.IsLowRiskForNetworkPolicy(name) {
			continue
		}
		if openToAll.Has(name) {
			findings = append(findings, &core.Finding{
				Severity:     core.SeverityMedium,
				Category:     "network",
				Title:        "Missing Cross-Namespace Network Isolation",
				Description:  fmt.Sprintf("Namespace '%s' has a NetworkPolicy with an ingress rule that allows traffic from ALL namespaces (empty namespaceSelector). Pods in any namespace — including potentially compromised ones — can reach this namespace.", name),
				ResourceType: "Namespace",
				ResourceName: name,
				Namespace:    name,
				Remediation:  "Use a namespaceSelector with matchLabels to restrict ingress to specific trusted namespaces. Add 'kubernetes.io/metadata.name: <namespace>' to limit to the same namespace.",
			})
		}
	}
	return findings
}

// ─── N-06: Endpoints pointing to suspicious IPs (SSRF risk) ──────────────────

var suspiciousIPPrefixes = []string{
	"169.254.169.254", // Cloud metadata API (AWS/GCP/Azure/DigitalOcean)
	"100.100.100.200", // Alibaba Cloud metadata
	"fd00:ec2::254",   // AWS IMDSv2 IPv6
}

func checkEndpointSSRF(endpoints []corev1.Endpoints) []*core.Finding {
	var findings []*core.Finding
	for _, ep := range endpoints {
		if isSystemNamespace(ep.Namespace) {
			continue
		}
		for _, subset := range ep.Subsets {
			for _, addr := range subset.Addresses {
				for _, prefix := range suspiciousIPPrefixes {
					if strings.HasPrefix(addr.IP, prefix) {
						findings = append(findings, &core.Finding{
							Severity:     core.SeverityHigh,
							Category:     "network",
							Title:        "Endpoints Pointing to Cloud Metadata IP (SSRF Risk)",
							Description:  fmt.Sprintf("Endpoints '%s' (namespace: %s) contains address %s — a cloud metadata service IP. A workload using this Service will be redirected to the metadata API, potentially leaking IAM credentials via SSRF.", ep.Name, ep.Namespace, addr.IP),
							ResourceType: "Endpoints",
							ResourceName: ep.Name,
							Namespace:    ep.Namespace,
							Remediation:  "Remove the cloud metadata IP from Endpoints. Block 169.254.169.254 via NetworkPolicy egress rules and use IMDSv2 with hop limit=1.",
							Metadata:     map[string]any{"ip": addr.IP},
						})
					}
				}
			}
		}
	}
	return findings
}

// checkUnauthenticatedDataStores flags well-known data store services (Redis,
// Memcached, MongoDB, Elasticsearch) that are reachable within the cluster
// without any NetworkPolicy restricting ingress. These services commonly ship
// with authentication disabled by default and are a frequent lateral-movement
// target once an attacker has a foothold in any pod.
func checkUnauthenticatedDataStores(
	services []corev1.Service,
	netpols []networkingv1.NetworkPolicy,
	nc *utils.NamespaceClassifier,
) []*core.Finding {
	type storeSpec struct {
		port int32
		name string
		poc  string
	}
	stores := []storeSpec{
		{6379, "Redis", "redis-cli -h {svc} KEYS '*' && redis-cli -h {svc} CONFIG GET requirepass"},
		{11211, "Memcached", "echo 'stats' | nc {svc} 11211"},
		{27017, "MongoDB", "mongo {svc}:27017 --eval 'db.adminCommand({listDatabases:1})'"},
		{9200, "Elasticsearch", "curl -s http://{svc}:9200/_cat/indices"},
		{5432, "PostgreSQL (no TLS check)", "psql -h {svc} -U postgres -c '\\l' 2>/dev/null"},
	}

	// Build set of namespaces that have ingress NetworkPolicy covering these ports
	protectedNS := make(map[string]bool)
	for _, np := range netpols {
		if hasIngressPolicyType(np) {
			protectedNS[np.Namespace] = true
		}
	}

	var findings []*core.Finding

	// Detect unauthenticated Docker registries (port 5000 with "registry" in name).
	// Port 5000 is too generic (Flask, Python devservers) so we use a name heuristic.
	for _, svc := range services {
		if nc.IsLowRiskForNetworkPolicy(svc.Namespace) {
			continue
		}
		nameLower := strings.ToLower(svc.Name)
		if !strings.Contains(nameLower, "registry") {
			continue
		}
		for _, port := range svc.Spec.Ports {
			if port.Port != 5000 {
				continue
			}
			protected := protectedNS[svc.Namespace]
			severity := core.SeverityHigh
			desc := fmt.Sprintf(
				"Service '%s' (namespace: %s) appears to be a Docker registry (port 5000, name contains 'registry'). "+
					"Unauthenticated registries allow any pod to pull images and enumerate repository contents, "+
					"which may expose secrets baked into image layers or enable image substitution attacks.",
				svc.Name, svc.Namespace,
			)
			if !protected {
				severity = core.SeverityCritical
				desc += " No NetworkPolicy is active in this namespace."
			}
			svcFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace)
			findings = append(findings, &core.Finding{
				Severity:     severity,
				Category:     "network",
				Title:        "Unauthenticated Container Registry Exposed",
				Description:  desc,
				ResourceType: "Service",
				ResourceName: svc.Name,
				Namespace:    svc.Namespace,
				Remediation:  "Enable registry authentication (htpasswd or token-based). Add a NetworkPolicy restricting port 5000 to authorized workloads only.",
				ProofOfConcept: fmt.Sprintf(
					"# Enumerate unauthenticated registry from any pod in the cluster\n"+
						"kubectl run poc-test --rm -it --restart=Never --image=alpine -- sh -c \\\n"+
						"  \"wget -qO- http://%s/v2/_catalog && wget -qO- http://%s/v2/<repo>/manifests/latest\"\n\n"+
						"# Check image manifests for secrets in ENV layers:\n"+
						"# Look for ENV API_KEY=, ENV DB_PASSWORD=, ENV SECRET= in v1Compatibility fields",
					svcFQDN, svcFQDN,
				),
				Metadata: map[string]any{"port": int32(5000), "store": "Docker Registry"},
			})
		}
	}

	for _, svc := range services {
		if nc.IsLowRiskForNetworkPolicy(svc.Namespace) {
			continue
		}
		for _, port := range svc.Spec.Ports {
			for _, store := range stores {
				if port.Port != store.port {
					continue
				}
				protected := protectedNS[svc.Namespace]
				severity := core.SeverityHigh
				desc := fmt.Sprintf(
					"Service '%s' (namespace: %s) exposes %s on port %d with no NetworkPolicy restricting ingress. "+
						"%s commonly ships with authentication disabled — any pod in the cluster can connect and read data.",
					svc.Name, svc.Namespace, store.name, store.port, store.name,
				)
				if !protected {
					severity = core.SeverityCritical
					desc += " No NetworkPolicy is active in this namespace."
				}
				pocCmd := strings.ReplaceAll(store.poc, "{svc}", fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace))
				findings = append(findings, &core.Finding{
					Severity:     severity,
					Category:     "network",
					Title:        fmt.Sprintf("Unauthenticated %s Service Exposed", store.name),
					Description:  desc,
					ResourceType: "Service",
					ResourceName: svc.Name,
					Namespace:    svc.Namespace,
					Remediation:  fmt.Sprintf("Enable authentication on %s. Add a NetworkPolicy restricting ingress to port %d to only pods that require access.", store.name, store.port),
					ProofOfConcept: fmt.Sprintf(
						"# Verify unauthenticated %s access from any pod in the cluster\n"+
							"kubectl run poc-test --rm -it --restart=Never --image=alpine -- sh -c \"%s\"\n\n"+
							"# If connected without credentials: CRITICAL — enable auth immediately",
						store.name, pocCmd,
					),
					Metadata: map[string]any{"port": store.port, "store": store.name},
				})
			}
		}
	}
	return findings
}

var _ core.Scanner = NetworkScanner{}
