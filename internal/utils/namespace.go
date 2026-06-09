package utils

import "strings"

// NamespaceClassifier categorises namespaces so scanners can adjust
// severity and confidence based on the environment type.
type NamespaceClassifier struct{}

// NewNamespaceClassifier returns a new NamespaceClassifier.
func NewNamespaceClassifier() *NamespaceClassifier {
	return &NamespaceClassifier{}
}

// systemNamespacePrefixes is the single source of truth for namespace classification
// across all scanners. Any namespace whose name starts with one of these prefixes
// is treated as a system/infrastructure namespace and skipped by security checks
// that would produce false positives there.
//
// Keep this list in sync with the infraPrefixes and monitoringPrefixes slices below.
var systemNamespacePrefixes = []string{
	"kube-",
	"monitoring", "observability", "metrics", "logging",
	"prometheus", "grafana", "datadog", "elastic", "loki", "jaeger",
	"kube-prometheus", "opentelemetry", "victoria-metrics",
	"istio-", "istio", "linkerd",
	"cert-manager",
	"ingress", "ingress-nginx",
	"flux-system", "argocd",
	"vault", "external-dns", "external-secrets",
	"cluster-autoscaler", "karpenter",
	"velero", "crossplane", "tekton", "knative",
	"cattle-", "fleet-", "rancher",
}

// fixedSystemNamespaces are exact-match names not covered by the prefix list.
var fixedSystemNamespaces = NewStringSet(
	"kube-system", "kube-public", "kube-node-lease",
	"monitoring", "logging", "cert-manager", "istio-system",
)

// IsSystemNamespace returns true when the namespace should be excluded from
// user-facing security checks. This is the single authoritative implementation;
// all scanners must call this instead of maintaining their own lists.
func IsSystemNamespace(name string) bool {
	if fixedSystemNamespaces.Has(name) {
		return true
	}
	lower := strings.ToLower(name)
	return HasAnyPrefix(lower, systemNamespacePrefixes)
}

var systemNamespaces = NewStringSet("kube-system", "kube-public", "kube-node-lease")


var monitoringPrefixes = []string{
	"monitoring", "observability", "metrics", "logging",
	"prometheus", "grafana", "datadog", "elastic", "loki", "jaeger",
	"kube-prometheus", "opentelemetry", "victoria-metrics",
}

var infraPrefixes = []string{
	"ingress", "ingress-nginx", "cert-manager", "external-secrets",
	"istio-system", "istio", "linkerd", "flux-system", "argocd",
	"vault", "external-dns", "cluster-autoscaler", "karpenter",
	"velero", "crossplane", "tekton", "knative",
}

// NSType represents the namespace classification result.
type NSType string

const (
	NSSystem        NSType = "system"
	NSMonitoring    NSType = "monitoring"
	NSInfra         NSType = "infra"
	NSProduction    NSType = "production"
	NSNonProduction NSType = "non-production"

	// NSClassProduction is an alias for NSProduction.
	NSClassProduction = NSProduction
)

// Classify returns the type of the namespace.
// Labels are optional — pass nil if not available.
// Conservative default is "production" to avoid under-flagging.
func (nc *NamespaceClassifier) Classify(name string) NSType {
	return nc.ClassifyWithLabels(name, nil)
}

// ClassifyWithLabels returns the type of the namespace using its labels for extra context.
func (nc *NamespaceClassifier) ClassifyWithLabels(name string, labels map[string]string) NSType {
	if systemNamespaces.Has(name) {
		return NSSystem
	}

	if labels != nil {
		env := strings.ToLower(labels["environment"])
		if env == "" {
			env = strings.ToLower(labels["env"])
		}
		switch env {
		case "production", "prod":
			return NSProduction
		case "staging", "stage", "dev", "development", "test", "qa", "sandbox":
			return NSNonProduction
		}
	}

	nl := strings.ToLower(name)
	if HasAnyPrefix(nl, monitoringPrefixes) {
		return NSMonitoring
	}
	if HasAnyPrefix(nl, infraPrefixes) {
		return NSInfra
	}
	return NSProduction
}

// IsLowRiskForNetworkPolicy returns true for namespaces where a missing
// network policy is less critical (monitoring / infra / non-prod / system).
func (nc *NamespaceClassifier) IsLowRiskForNetworkPolicy(name string) bool {
	t := nc.Classify(name)
	return t == NSSystem || t == NSMonitoring || t == NSInfra || t == NSNonProduction
}
