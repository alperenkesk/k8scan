package lint

import (
	"context"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/alperenkesk/k8scan/internal/core"
)

// StaticClient implements core.KubeReader by serving data from a ManifestStore
// instead of a live Kubernetes API server.
type StaticClient struct {
	store *ManifestStore
}

// NewStaticClient wraps a ManifestStore into a KubeReader.
func NewStaticClient(store *ManifestStore) *StaticClient {
	return &StaticClient{store: store}
}

// SourceFile returns the file path for a given kind/namespace/name, or "".
func (c *StaticClient) SourceFile(kind, namespace, name string) string {
	if ref, ok := c.store.SourceMap[sourceKey(kind, namespace, name)]; ok {
		return ref.File
	}
	return ""
}

// SourceLine returns the line number for a given kind/namespace/name, or 0.
func (c *StaticClient) SourceLine(kind, namespace, name string) int {
	if ref, ok := c.store.SourceMap[sourceKey(kind, namespace, name)]; ok {
		return ref.Line
	}
	return 0
}

// Compile-time interface check.
var _ core.KubeReader = (*StaticClient)(nil)

func (c *StaticClient) GetAllNodes(_ context.Context) ([]corev1.Node, error) {
	return c.store.Nodes, nil
}

func (c *StaticClient) GetAllPods(_ context.Context) ([]corev1.Pod, error) {
	return c.store.Pods, nil
}

func (c *StaticClient) GetAllSecrets(_ context.Context) ([]corev1.Secret, error) {
	return c.store.Secrets, nil
}

func (c *StaticClient) GetAllConfigMaps(_ context.Context) ([]corev1.ConfigMap, error) {
	return c.store.ConfigMaps, nil
}

func (c *StaticClient) GetAllServices(_ context.Context) ([]corev1.Service, error) {
	return c.store.Services, nil
}

func (c *StaticClient) GetAllNamespaces(_ context.Context) ([]corev1.Namespace, error) {
	return c.store.Namespaces, nil
}

func (c *StaticClient) GetAllServiceAccounts(_ context.Context) ([]corev1.ServiceAccount, error) {
	return c.store.ServiceAccounts, nil
}

func (c *StaticClient) GetAllDeployments(_ context.Context) ([]appsv1.Deployment, error) {
	return c.store.Deployments, nil
}

func (c *StaticClient) GetAllStatefulSets(_ context.Context) ([]appsv1.StatefulSet, error) {
	return c.store.StatefulSets, nil
}

func (c *StaticClient) GetAllDaemonSets(_ context.Context) ([]appsv1.DaemonSet, error) {
	return c.store.DaemonSets, nil
}

func (c *StaticClient) GetAllRoles(_ context.Context) ([]rbacv1.Role, error) {
	return c.store.Roles, nil
}

func (c *StaticClient) GetAllClusterRoles(_ context.Context) ([]rbacv1.ClusterRole, error) {
	return c.store.ClusterRoles, nil
}

func (c *StaticClient) GetAllRoleBindings(_ context.Context) ([]rbacv1.RoleBinding, error) {
	return c.store.RoleBindings, nil
}

func (c *StaticClient) GetAllClusterRoleBindings(_ context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	return c.store.ClusterRoleBindings, nil
}

func (c *StaticClient) GetAllNetworkPolicies(_ context.Context) ([]networkingv1.NetworkPolicy, error) {
	return c.store.NetworkPolicies, nil
}

func (c *StaticClient) GetAllIngresses(_ context.Context) ([]networkingv1.Ingress, error) {
	return c.store.Ingresses, nil
}

func (c *StaticClient) GetAllCronJobs(_ context.Context) ([]batchv1.CronJob, error) {
	return c.store.CronJobs, nil
}

func (c *StaticClient) GetAllJobs(_ context.Context) ([]batchv1.Job, error) {
	return c.store.Jobs, nil
}

func (c *StaticClient) GetAllValidatingWebhooks(_ context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	return c.store.ValidatingWebhooks, nil
}

func (c *StaticClient) GetAllMutatingWebhooks(_ context.Context) ([]admissionv1.MutatingWebhookConfiguration, error) {
	return c.store.MutatingWebhooks, nil
}

func (c *StaticClient) GetAllResourceQuotas(_ context.Context) ([]corev1.ResourceQuota, error) {
	return c.store.ResourceQuotas, nil
}

func (c *StaticClient) GetAllLimitRanges(_ context.Context) ([]corev1.LimitRange, error) {
	return c.store.LimitRanges, nil
}

func (c *StaticClient) GetAllEndpoints(_ context.Context) ([]corev1.Endpoints, error) {
	return c.store.Endpoints, nil
}

func (c *StaticClient) GetAllPodDisruptionBudgets(_ context.Context) ([]policyv1.PodDisruptionBudget, error) {
	return c.store.PodDisruptionBudgets, nil
}

func (c *StaticClient) GetAllHorizontalPodAutoscalers(_ context.Context) ([]autoscalingv2.HorizontalPodAutoscaler, error) {
	return c.store.HorizontalPodAutoscalers, nil
}
