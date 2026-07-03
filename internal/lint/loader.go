// Package lint provides YAML/Helm/Kustomize manifest loading for static analysis mode.
package lint

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
)

// ManifestStore holds all Kubernetes objects parsed from YAML manifests.
type ManifestStore struct {
	Nodes                    []corev1.Node
	Pods                     []corev1.Pod
	Secrets                  []corev1.Secret
	ConfigMaps               []corev1.ConfigMap
	Services                 []corev1.Service
	Namespaces               []corev1.Namespace
	ServiceAccounts          []corev1.ServiceAccount
	ResourceQuotas           []corev1.ResourceQuota
	LimitRanges              []corev1.LimitRange
	Endpoints                []corev1.Endpoints
	Deployments              []appsv1.Deployment
	StatefulSets             []appsv1.StatefulSet
	DaemonSets               []appsv1.DaemonSet
	Roles                    []rbacv1.Role
	ClusterRoles             []rbacv1.ClusterRole
	RoleBindings             []rbacv1.RoleBinding
	ClusterRoleBindings      []rbacv1.ClusterRoleBinding
	NetworkPolicies          []networkingv1.NetworkPolicy
	Ingresses                []networkingv1.Ingress
	CronJobs                 []batchv1.CronJob
	Jobs                     []batchv1.Job
	ValidatingWebhooks       []admissionv1.ValidatingWebhookConfiguration
	MutatingWebhooks         []admissionv1.MutatingWebhookConfiguration
	PodDisruptionBudgets     []policyv1.PodDisruptionBudget
	HorizontalPodAutoscalers []autoscalingv2.HorizontalPodAutoscaler
	// SourceMap records which file each object came from (keyed by kind/namespace/name).
	SourceMap map[string]sourceRef
}

type sourceRef struct {
	File string
	Line int
}

var (
	decoder runtime.Decoder
)

func init() {
	_ = admissionv1.AddToScheme(scheme.Scheme)
	_ = autoscalingv2.AddToScheme(scheme.Scheme)
	_ = policyv1.AddToScheme(scheme.Scheme)
	decoder = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer()
}

// LoadPaths loads manifests from a list of paths (files or directories).
// Directories are walked recursively for *.yaml / *.yml files.
func LoadPaths(paths []string) (*ManifestStore, error) {
	store := &ManifestStore{SourceMap: make(map[string]sourceRef)}
	for _, p := range paths {
		if err := store.loadPath(p); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// LoadStdin reads YAML manifests from stdin.
func LoadStdin() (*ManifestStore, error) {
	store := &ManifestStore{SourceMap: make(map[string]sourceRef)}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	store.parseYAML(data, "<stdin>")
	return store, nil
}

func (s *ManifestStore) loadPath(p string) error {
	info, err := os.Stat(p)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				s.parseYAML(data, path)
			}
			return nil
		})
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	s.parseYAML(data, p)
	return nil
}

func (s *ManifestStore) parseYAML(data []byte, sourcePath string) {
	// Split multi-document YAML on "\n---" but derive each document's line number
	// from its absolute byte offset in the original data. Counting within the
	// (trimmed) document instead — as the previous implementation did — accumulates
	// drift so later documents report increasingly wrong line numbers.
	sep := []byte("\n---")
	pos := 0
	for pos <= len(data) {
		end := len(data)
		rel := bytes.Index(data[pos:], sep)
		if rel >= 0 {
			end = pos + rel
		}
		seg := data[pos:end]
		trimmed := bytes.TrimSpace(seg)
		if len(trimmed) > 0 {
			// Report the first non-blank content line, skipping a leading "---"
			// document-start marker if present.
			lead := firstContentOffset(seg)
			line := 1 + bytes.Count(data[:pos+lead], []byte("\n"))
			if obj, _, err := decoder.Decode(trimmed, nil, nil); err == nil {
				s.store(obj, sourcePath, line)
			}
		}
		if rel < 0 {
			break
		}
		pos = end + 1 // skip the '\n'; the "---" marker begins the next segment
	}
}

// firstContentOffset returns the byte offset within seg of the first line that
// carries real content, skipping leading blank lines and an optional "---" marker.
func firstContentOffset(seg []byte) int {
	tl := bytes.TrimLeft(seg, " \t\r\n")
	off := len(seg) - len(tl)
	if bytes.HasPrefix(tl, []byte("---")) {
		if nl := bytes.IndexByte(tl, '\n'); nl >= 0 {
			rest := tl[nl+1:]
			off += nl + 1 + (len(rest) - len(bytes.TrimLeft(rest, " \t\r\n")))
		}
	}
	return off
}

func (s *ManifestStore) store(obj runtime.Object, file string, line int) {
	switch o := obj.(type) {
	case *corev1.Pod:
		s.SourceMap[sourceKey("Pod", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Pods = append(s.Pods, *o)
	case *corev1.Secret:
		s.SourceMap[sourceKey("Secret", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Secrets = append(s.Secrets, *o)
	case *corev1.ConfigMap:
		s.SourceMap[sourceKey("ConfigMap", o.Namespace, o.Name)] = sourceRef{file, line}
		s.ConfigMaps = append(s.ConfigMaps, *o)
	case *corev1.Service:
		s.SourceMap[sourceKey("Service", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Services = append(s.Services, *o)
	case *corev1.Namespace:
		s.SourceMap[sourceKey("Namespace", "", o.Name)] = sourceRef{file, line}
		s.Namespaces = append(s.Namespaces, *o)
	case *corev1.ServiceAccount:
		s.SourceMap[sourceKey("ServiceAccount", o.Namespace, o.Name)] = sourceRef{file, line}
		s.ServiceAccounts = append(s.ServiceAccounts, *o)
	case *corev1.ResourceQuota:
		s.SourceMap[sourceKey("ResourceQuota", o.Namespace, o.Name)] = sourceRef{file, line}
		s.ResourceQuotas = append(s.ResourceQuotas, *o)
	case *corev1.LimitRange:
		s.SourceMap[sourceKey("LimitRange", o.Namespace, o.Name)] = sourceRef{file, line}
		s.LimitRanges = append(s.LimitRanges, *o)
	case *corev1.Endpoints:
		s.SourceMap[sourceKey("Endpoints", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Endpoints = append(s.Endpoints, *o)
	case *appsv1.Deployment:
		s.SourceMap[sourceKey("Deployment", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Deployments = append(s.Deployments, *o)
	case *appsv1.StatefulSet:
		s.SourceMap[sourceKey("StatefulSet", o.Namespace, o.Name)] = sourceRef{file, line}
		s.StatefulSets = append(s.StatefulSets, *o)
	case *appsv1.DaemonSet:
		s.SourceMap[sourceKey("DaemonSet", o.Namespace, o.Name)] = sourceRef{file, line}
		s.DaemonSets = append(s.DaemonSets, *o)
	case *rbacv1.Role:
		s.SourceMap[sourceKey("Role", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Roles = append(s.Roles, *o)
	case *rbacv1.ClusterRole:
		s.SourceMap[sourceKey("ClusterRole", "", o.Name)] = sourceRef{file, line}
		s.ClusterRoles = append(s.ClusterRoles, *o)
	case *rbacv1.RoleBinding:
		s.SourceMap[sourceKey("RoleBinding", o.Namespace, o.Name)] = sourceRef{file, line}
		s.RoleBindings = append(s.RoleBindings, *o)
	case *rbacv1.ClusterRoleBinding:
		s.SourceMap[sourceKey("ClusterRoleBinding", "", o.Name)] = sourceRef{file, line}
		s.ClusterRoleBindings = append(s.ClusterRoleBindings, *o)
	case *networkingv1.NetworkPolicy:
		s.SourceMap[sourceKey("NetworkPolicy", o.Namespace, o.Name)] = sourceRef{file, line}
		s.NetworkPolicies = append(s.NetworkPolicies, *o)
	case *networkingv1.Ingress:
		s.SourceMap[sourceKey("Ingress", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Ingresses = append(s.Ingresses, *o)
	case *batchv1.CronJob:
		s.SourceMap[sourceKey("CronJob", o.Namespace, o.Name)] = sourceRef{file, line}
		s.CronJobs = append(s.CronJobs, *o)
	case *batchv1.Job:
		s.SourceMap[sourceKey("Job", o.Namespace, o.Name)] = sourceRef{file, line}
		s.Jobs = append(s.Jobs, *o)
	case *admissionv1.ValidatingWebhookConfiguration:
		s.SourceMap[sourceKey("ValidatingWebhookConfiguration", "", o.Name)] = sourceRef{file, line}
		s.ValidatingWebhooks = append(s.ValidatingWebhooks, *o)
	case *admissionv1.MutatingWebhookConfiguration:
		s.SourceMap[sourceKey("MutatingWebhookConfiguration", "", o.Name)] = sourceRef{file, line}
		s.MutatingWebhooks = append(s.MutatingWebhooks, *o)
	case *policyv1.PodDisruptionBudget:
		s.SourceMap[sourceKey("PodDisruptionBudget", o.Namespace, o.Name)] = sourceRef{file, line}
		s.PodDisruptionBudgets = append(s.PodDisruptionBudgets, *o)
	case *autoscalingv2.HorizontalPodAutoscaler:
		s.SourceMap[sourceKey("HorizontalPodAutoscaler", o.Namespace, o.Name)] = sourceRef{file, line}
		s.HorizontalPodAutoscalers = append(s.HorizontalPodAutoscalers, *o)
	}
}

func sourceKey(kind, namespace, name string) string {
	return kind + "/" + namespace + "/" + name
}
