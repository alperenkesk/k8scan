package core

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
)

// KubeReader is the read-only interface used by all scanners.
// Both K8sClient (live cluster) and StaticClient (YAML/Helm offline) implement it.
type KubeReader interface {
	GetAllNodes(ctx context.Context) ([]corev1.Node, error)
	GetAllPods(ctx context.Context) ([]corev1.Pod, error)
	GetAllSecrets(ctx context.Context) ([]corev1.Secret, error)
	GetAllConfigMaps(ctx context.Context) ([]corev1.ConfigMap, error)
	GetAllServices(ctx context.Context) ([]corev1.Service, error)
	GetAllNamespaces(ctx context.Context) ([]corev1.Namespace, error)
	GetAllServiceAccounts(ctx context.Context) ([]corev1.ServiceAccount, error)
	GetAllDeployments(ctx context.Context) ([]appsv1.Deployment, error)
	GetAllStatefulSets(ctx context.Context) ([]appsv1.StatefulSet, error)
	GetAllDaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error)
	GetAllRoles(ctx context.Context) ([]rbacv1.Role, error)
	GetAllClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error)
	GetAllRoleBindings(ctx context.Context) ([]rbacv1.RoleBinding, error)
	GetAllClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error)
	GetAllNetworkPolicies(ctx context.Context) ([]networkingv1.NetworkPolicy, error)
	GetAllIngresses(ctx context.Context) ([]networkingv1.Ingress, error)
	GetAllCronJobs(ctx context.Context) ([]batchv1.CronJob, error)
	GetAllJobs(ctx context.Context) ([]batchv1.Job, error)
	GetAllValidatingWebhooks(ctx context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error)
	GetAllMutatingWebhooks(ctx context.Context) ([]admissionv1.MutatingWebhookConfiguration, error)
	GetAllResourceQuotas(ctx context.Context) ([]corev1.ResourceQuota, error)
	GetAllLimitRanges(ctx context.Context) ([]corev1.LimitRange, error)
	GetAllEndpoints(ctx context.Context) ([]corev1.Endpoints, error)
	GetAllPodDisruptionBudgets(ctx context.Context) ([]policyv1.PodDisruptionBudget, error)
	GetAllHorizontalPodAutoscalers(ctx context.Context) ([]autoscalingv2.HorizontalPodAutoscaler, error)
}

// Scanner is the interface that all security scanners must implement.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, client KubeReader) ([]*Finding, error)
}
