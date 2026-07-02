package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sClient wraps the Kubernetes clientset with convenience methods.
// All Get* methods return an empty slice on permission errors so the
// scanner degrades gracefully instead of crashing.
type K8sClient struct {
	cs *kubernetes.Clientset
}

// NewK8sClient creates a client from kubeconfig (out-of-cluster) or
// the in-cluster service account token.
func NewK8sClient() (*K8sClient, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot create kubernetes client: %w", err)
	}
	return &K8sClient{cs: cs}, nil
}

func loadConfig() (*rest.Config, error) {
	// 1. Try explicit KUBECONFIG env var
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}
	// 2. Try ~/.kube/config
	home, err := os.UserHomeDir()
	if err == nil {
		kubeconfig := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfig); err == nil {
			if cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig); err == nil {
				return cfg, nil
			}
		}
	}
	// 3. Try in-cluster config (pod with SA token)
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("no kubeconfig file and not running in-cluster")
	}
	return cfg, nil
}

// Clientset returns the underlying kubernetes.Clientset for advanced use.
func (k *K8sClient) Clientset() *kubernetes.Clientset {
	return k.cs
}

// ClusterInfo holds metadata about the cluster being scanned.
type ClusterInfo struct {
	ContextName    string
	ServerVersion  string
	NodeCount      int
	NamespaceCount int
}

// GetClusterInfo returns lightweight cluster metadata for display in reports.
// All fields degrade gracefully — permission errors return empty/zero values.
func (k *K8sClient) GetClusterInfo(ctx context.Context) ClusterInfo {
	info := ClusterInfo{}

	// K8s server version via discovery (no RBAC needed)
	if sv, err := k.cs.Discovery().ServerVersion(); err == nil {
		info.ServerVersion = sv.GitVersion
	}

	// Node count
	if nodes, err := k.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err == nil {
		info.NodeCount = len(nodes.Items)
	}

	// Namespace count
	if ns, err := k.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
		info.NamespaceCount = len(ns.Items)
	}

	// Current kubeconfig context name
	if rules := clientcmd.NewDefaultClientConfigLoadingRules(); rules != nil {
		cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
		if raw, err := cc.RawConfig(); err == nil {
			info.ContextName = raw.CurrentContext
		}
	}

	return info
}

// isForbidden returns true for 403/404 API errors so callers can
// silently skip resources they have no permission to read.
func isForbidden(err error) bool {
	return errors.IsForbidden(err) || errors.IsUnauthorized(err) || errors.IsNotFound(err)
}

// --- Core v1 ---

func (k *K8sClient) GetAllNodes(ctx context.Context) ([]corev1.Node, error) {
	list, err := k.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllPods(ctx context.Context) ([]corev1.Pod, error) {
	list, err := k.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllSecrets(ctx context.Context) ([]corev1.Secret, error) {
	list, err := k.cs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllConfigMaps(ctx context.Context) ([]corev1.ConfigMap, error) {
	list, err := k.cs.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllServices(ctx context.Context) ([]corev1.Service, error) {
	list, err := k.cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	list, err := k.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllServiceAccounts(ctx context.Context) ([]corev1.ServiceAccount, error) {
	list, err := k.cs.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Apps v1 ---

func (k *K8sClient) GetAllDeployments(ctx context.Context) ([]appsv1.Deployment, error) {
	list, err := k.cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllStatefulSets(ctx context.Context) ([]appsv1.StatefulSet, error) {
	list, err := k.cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllDaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	list, err := k.cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- RBAC v1 ---

func (k *K8sClient) GetAllRoles(ctx context.Context) ([]rbacv1.Role, error) {
	list, err := k.cs.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error) {
	list, err := k.cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllRoleBindings(ctx context.Context) ([]rbacv1.RoleBinding, error) {
	list, err := k.cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	list, err := k.cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Networking v1 ---

func (k *K8sClient) GetAllNetworkPolicies(ctx context.Context) ([]networkingv1.NetworkPolicy, error) {
	list, err := k.cs.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllIngresses(ctx context.Context) ([]networkingv1.Ingress, error) {
	list, err := k.cs.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Batch v1 ---

func (k *K8sClient) GetAllCronJobs(ctx context.Context) ([]batchv1.CronJob, error) {
	list, err := k.cs.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Admission v1 ---

func (k *K8sClient) GetAllValidatingWebhooks(ctx context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	list, err := k.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllMutatingWebhooks(ctx context.Context) ([]admissionv1.MutatingWebhookConfiguration, error) {
	list, err := k.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Core v1 (namespace-scoped resources) ---

func (k *K8sClient) GetAllResourceQuotas(ctx context.Context) ([]corev1.ResourceQuota, error) {
	list, err := k.cs.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllLimitRanges(ctx context.Context) ([]corev1.LimitRange, error) {
	list, err := k.cs.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func (k *K8sClient) GetAllEndpoints(ctx context.Context) ([]corev1.Endpoints, error) {
	list, err := k.cs.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Policy v1 ---

func (k *K8sClient) GetAllPodDisruptionBudgets(ctx context.Context) ([]policyv1.PodDisruptionBudget, error) {
	list, err := k.cs.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Autoscaling v2 ---

func (k *K8sClient) GetAllHorizontalPodAutoscalers(ctx context.Context) ([]autoscalingv2.HorizontalPodAutoscaler, error) {
	list, err := k.cs.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

// --- Batch v1 (Jobs) ---

func (k *K8sClient) GetAllJobs(ctx context.Context) ([]batchv1.Job, error) {
	list, err := k.cs.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if isForbidden(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}
