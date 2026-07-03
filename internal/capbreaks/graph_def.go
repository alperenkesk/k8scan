package capbreaks

import (
	"encoding/json"

	"github.com/alperenkesk/k8scan/internal/core"
)

// graphPayload is the JSON structure consumed by the canvas renderer.
type graphPayload struct {
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
}

type graphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"` // use \n for two-line labels
	Type  string `json:"type"`  // workload|identity|node|cp|secret|cloud|target
}

type graphEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
	Style string `json:"style"` // escape|steal|escalate|access|compromise
}

// BuildCBGraphJSON returns the pre-serialized JSON for a CB's attack graph,
// filling in real resource names from the evidence findings.
func BuildCBGraphJSON(cbID string, evidence []core.CBEvidence) string {
	pod, ns := firstPod(evidence)
	resourceLabel := pod
	if ns != "" && ns != "<namespace>" {
		resourceLabel = ns + "/" + pod
	}

	var gd graphPayload
	switch cbID {
	case "CB-001":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "container", Label: resourceLabel + "\n(vulnerable container)", Type: "workload"},
				{ID: "host_proc", Label: "Host /proc\n(node filesystem)", Type: "node"},
				{ID: "kubelet", Label: "Kubelet\n(node agent)", Type: "cp"},
				{ID: "admin", Label: "cluster-admin\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "container", To: "host_proc", Label: "privileged / hostPID", Style: "escape"},
				{From: "host_proc", To: "kubelet", Label: "steal kubeconfig / cert", Style: "steal"},
				{From: "kubelet", To: "admin", Label: "full API access", Style: "escalate"},
			},
		}
	case "CB-002":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "workload", Label: resourceLabel + "\n(Namespace A)", Type: "workload"},
				{ID: "crb", Label: "ClusterRoleBinding\n(cluster-scoped)", Type: "identity"},
				{ID: "ns_b", Label: "All Namespaces\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "workload", To: "crb", Label: "via SA token", Style: "access"},
				{From: "crb", To: "ns_b", Label: "cross-ns access", Style: "escalate"},
			},
		}
	case "CB-003":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "identity", Label: resourceLabel + "\n(identity)", Type: "identity"},
				{ID: "rbac_perm", Label: "escalate / bind\n(dangerous verbs)", Type: "identity"},
				{ID: "new_binding", Label: "New Binding\n(self-created)", Type: "identity"},
				{ID: "admin", Label: "cluster-admin\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "identity", To: "rbac_perm", Label: "has permission", Style: "access"},
				{From: "rbac_perm", To: "new_binding", Label: "create binding", Style: "escalate"},
				{From: "new_binding", To: "admin", Label: "grant cluster-admin", Style: "compromise"},
			},
		}
	case "CB-004":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "pod", Label: resourceLabel + "\n(workload pod)", Type: "workload"},
				{ID: "token", Label: "SA Token\n(auto-mounted)", Type: "identity"},
				{ID: "api", Label: "K8s API Server\n(control plane)", Type: "cp"},
				{ID: "secrets", Label: "Cluster Secrets\n[TARGET]", Type: "secret"},
			},
			Edges: []graphEdge{
				{From: "pod", To: "token", Label: "auto-mount read", Style: "access"},
				{From: "token", To: "api", Label: "excessive RBAC", Style: "access"},
				{From: "api", To: "secrets", Label: "list / get secrets", Style: "steal"},
			},
		}
	case "CB-005":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "attacker", Label: "Attacker\n(any kubectl user)", Type: "workload"},
				{ID: "admission", Label: "Admission Control\n(MISSING / WEAK)", Type: "cp"},
				{ID: "priv_pod", Label: "Privileged Pod\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "attacker", To: "admission", Label: "submit manifest", Style: "access"},
				{From: "admission", To: "priv_pod", Label: "bypass → schedule", Style: "compromise"},
			},
		}
	case "CB-006":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "container", Label: resourceLabel + "\n(container)", Type: "workload"},
				{ID: "socket", Label: "docker.sock\n(runtime socket)", Type: "node"},
				{ID: "new_ctr", Label: "Privileged Container\n(spawned via CRI)", Type: "workload"},
				{ID: "host_root", Label: "Node Root\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "container", To: "socket", Label: "mounted socket", Style: "access"},
				{From: "socket", To: "new_ctr", Label: "CRI API: run --privileged", Style: "escape"},
				{From: "new_ctr", To: "host_root", Label: "mount / chroot /host", Style: "compromise"},
			},
		}
	case "CB-007":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "attacker", Label: resourceLabel + "\n(attacker identity)", Type: "identity"},
				{ID: "rbac", Label: "RBAC Read\n(secrets permissions)", Type: "identity"},
				{ID: "secrets", Label: "K8s Secrets\n(credentials store)", Type: "secret"},
				{ID: "creds", Label: "DB / API Keys\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "attacker", To: "rbac", Label: "has list/read", Style: "access"},
				{From: "rbac", To: "secrets", Label: "list / get secrets", Style: "steal"},
				{From: "secrets", To: "creds", Label: "base64 decode", Style: "steal"},
			},
		}
	case "CB-008":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "workload", Label: resourceLabel + "\n(runs untrusted image)", Type: "workload"},
				{ID: "registry", Label: "Untrusted Registry\n(unknown provenance)", Type: "cloud"},
				{ID: "image", Label: "Poisoned Image Layer\n(supply-chain payload)", Type: "workload"},
				{ID: "cluster", Label: "Workload Identity\n+ Cluster Foothold\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "workload", To: "registry", Label: "pulls image", Style: "access"},
				{From: "registry", To: "image", Label: "malicious image push", Style: "steal"},
				{From: "image", To: "cluster", Label: "executes with SA token", Style: "compromise"},
			},
		}
	case "CB-009":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "tenant_a", Label: resourceLabel + "\n(Tenant A workload)", Type: "workload"},
				{ID: "shared_sa", Label: "Shared SA\n(identity bridge)", Type: "identity"},
				{ID: "tenant_b", Label: "Tenant B Resources\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "tenant_a", To: "shared_sa", Label: "same SA / controller", Style: "access"},
				{From: "shared_sa", To: "tenant_b", Label: "cross-tenant access", Style: "compromise"},
			},
		}
	case "CB-010":
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "pod", Label: resourceLabel + "\n(any pod)", Type: "workload"},
				{ID: "metadata", Label: "169.254.169.254\n(cloud metadata API)", Type: "cloud"},
				{ID: "iam", Label: "IAM Credentials\n(temporary tokens)", Type: "secret"},
				{ID: "cloud", Label: "Cloud Account\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "pod", To: "metadata", Label: "HTTP unrestricted", Style: "access"},
				{From: "metadata", To: "iam", Label: "retrieve tokens", Style: "steal"},
				{From: "iam", To: "cloud", Label: "cloud API access", Style: "compromise"},
			},
		}
	default:
		gd = graphPayload{
			Nodes: []graphNode{
				{ID: "n1", Label: "Finding\n(evidence)", Type: "workload"},
				{ID: "n2", Label: "Target\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{{From: "n1", To: "n2", Label: "exploit", Style: "compromise"}},
		}
	}

	b, _ := json.Marshal(gd)
	return string(b)
}

// BuildCompoundGraphJSON returns the graph JSON for a compound break,
// showing the full multi-stage attack path across constituent CBs.
func BuildCompoundGraphJSON(compoundID string, cbs []core.CapabilityBreak) string {
	// Get the first evidence pod from the first CB for labeling
	firstLabel := "workload"
	for _, cb := range cbs {
		if len(cb.Evidence) > 0 {
			e := cb.Evidence[0]
			if e.Namespace != "" {
				firstLabel = e.Namespace + "/" + e.ResourceName
			} else {
				firstLabel = e.ResourceName
			}
			break
		}
	}

	switch compoundID {
	case "COMPOUND-1": // CB-001 + CB-003
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "container", Label: firstLabel + "\n(container)", Type: "workload"},
				{ID: "node", Label: "Node Filesystem\n(host access)", Type: "node"},
				{ID: "stolen_id", Label: "Stolen kubeconfig\n(node credentials)", Type: "identity"},
				{ID: "rbac", Label: "RBAC Escalation\n(escalate / bind)", Type: "identity"},
				{ID: "admin", Label: "cluster-admin\n[FULL CLUSTER]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "container", To: "node", Label: "CB-001: privileged escape", Style: "escape"},
				{From: "node", To: "stolen_id", Label: "steal kubeconfig / cert", Style: "steal"},
				{From: "stolen_id", To: "rbac", Label: "CB-003: escalate/bind", Style: "escalate"},
				{From: "rbac", To: "admin", Label: "create cluster-admin binding", Style: "compromise"},
			},
		})
	case "COMPOUND-2": // CB-004 + CB-003
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "pod", Label: firstLabel + "\n(compromised pod)", Type: "workload"},
				{ID: "token", Label: "SA Token\n(auto-mounted)", Type: "identity"},
				{ID: "api", Label: "K8s API Server", Type: "cp"},
				{ID: "rbac", Label: "RBAC escalate/bind\n(CB-003)", Type: "identity"},
				{ID: "admin", Label: "cluster-admin\n[FULL CLUSTER]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "pod", To: "token", Label: "CB-004: read token", Style: "steal"},
				{From: "token", To: "api", Label: "authenticate to API", Style: "access"},
				{From: "api", To: "rbac", Label: "use escalate perm", Style: "escalate"},
				{From: "rbac", To: "admin", Label: "create cluster-admin binding", Style: "compromise"},
			},
		})
	case "COMPOUND-3": // CB-001 + CB-010
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "container", Label: firstLabel + "\n(container)", Type: "workload"},
				{ID: "node", Label: "Node\n(host access)", Type: "node"},
				{ID: "metadata", Label: "169.254.169.254\n(cloud metadata)", Type: "cloud"},
				{ID: "iam", Label: "IAM Credentials\n(cloud tokens)", Type: "secret"},
				{ID: "cloud", Label: "Cloud Account\n[AWS/GCP/Azure]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "container", To: "node", Label: "CB-001: escape to node", Style: "escape"},
				{From: "node", To: "metadata", Label: "CB-010: reach IMDS", Style: "access"},
				{From: "metadata", To: "iam", Label: "retrieve IAM tokens", Style: "steal"},
				{From: "iam", To: "cloud", Label: "cloud account takeover", Style: "compromise"},
			},
		})
	case "COMPOUND-4": // CB-005 + CB-001
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "attacker", Label: "Attacker\n(any kubectl user)", Type: "workload"},
				{ID: "admission", Label: "Admission Control\n(CB-005: MISSING)", Type: "cp"},
				{ID: "priv_pod", Label: "Privileged Pod\n(deployed)", Type: "workload"},
				{ID: "node", Label: "Node Root\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "attacker", To: "admission", Label: "CB-005: submit manifest", Style: "access"},
				{From: "admission", To: "priv_pod", Label: "bypass — schedule", Style: "escape"},
				{From: "priv_pod", To: "node", Label: "CB-001: container escape", Style: "compromise"},
			},
		})
	case "COMPOUND-5": // CB-001 + CB-003 + CB-007
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "container", Label: firstLabel + "\n(container)", Type: "workload"},
				{ID: "node", Label: "Node\n(host access)", Type: "node"},
				{ID: "token", Label: "Stolen Token\n(kubeconfig)", Type: "identity"},
				{ID: "rbac", Label: "RBAC Escalation\n(cluster-admin)", Type: "identity"},
				{ID: "secrets", Label: "All Secrets\n(CB-007)", Type: "secret"},
				{ID: "target", Label: "Full Cluster\n+ All Credentials\n[TOTAL COMPROMISE]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "container", To: "node", Label: "CB-001: escape", Style: "escape"},
				{From: "node", To: "token", Label: "steal credentials", Style: "steal"},
				{From: "token", To: "rbac", Label: "CB-003: escalate", Style: "escalate"},
				{From: "rbac", To: "secrets", Label: "CB-007: read all secrets", Style: "steal"},
				{From: "secrets", To: "target", Label: "total compromise", Style: "compromise"},
			},
		})
	case "COMPOUND-6": // CB-002 + CB-003
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "workload", Label: firstLabel + "\n(Namespace A)", Type: "workload"},
				{ID: "crb", Label: "ClusterRoleBinding\n(CB-002)", Type: "identity"},
				{ID: "rbac", Label: "RBAC escalate/bind\n(CB-003)", Type: "identity"},
				{ID: "all_ns", Label: "All Namespaces\n[TENANT ESCAPE]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "workload", To: "crb", Label: "CB-002: cluster-wide", Style: "access"},
				{From: "crb", To: "rbac", Label: "CB-003: use escalate", Style: "escalate"},
				{From: "rbac", To: "all_ns", Label: "create bindings in all ns", Style: "compromise"},
			},
		})
	case "COMPOUND-7": // CB-008 + CB-004
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "image", Label: "Untrusted Image\n(CB-008: supply chain)", Type: "workload"},
				{ID: "workload", Label: firstLabel + "\n(runs the image)", Type: "workload"},
				{ID: "token", Label: "Over-Permissioned SA\n(CB-004)", Type: "identity"},
				{ID: "cluster", Label: "K8s Cluster\n[SUPPLY CHAIN TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "image", To: "workload", Label: "CB-008: poisoned image runs", Style: "access"},
				{From: "workload", To: "token", Label: "reads mounted SA token", Style: "steal"},
				{From: "token", To: "cluster", Label: "CB-004: excessive RBAC", Style: "compromise"},
			},
		})
	case "COMPOUND-8": // CB-009 + CB-002
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "tenant_a", Label: firstLabel + "\n(Tenant A)", Type: "workload"},
				{ID: "shared", Label: "Shared SA\n(CB-009: identity bridge)", Type: "identity"},
				{ID: "crb", Label: "ClusterRoleBinding\n(CB-002)", Type: "identity"},
				{ID: "tenant_b", Label: "Tenant B Resources\n[TENANT ESCAPE]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "tenant_a", To: "shared", Label: "CB-009: shared SA", Style: "access"},
				{From: "shared", To: "crb", Label: "cluster binding", Style: "escalate"},
				{From: "crb", To: "tenant_b", Label: "CB-002: cross-ns access", Style: "compromise"},
			},
		})
	case "COMPOUND-9": // CB-010 + CB-003
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "pod", Label: firstLabel + "\n(pod)", Type: "workload"},
				{ID: "metadata", Label: "169.254.169.254\n(CB-010: IMDS)", Type: "cloud"},
				{ID: "iam_creds", Label: "IAM Credentials\n(K8s API scope)", Type: "secret"},
				{ID: "rbac", Label: "RBAC Escalation\n(CB-003)", Type: "identity"},
				{ID: "target", Label: "Cloud + Cluster\n[BIDIRECTIONAL TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "pod", To: "metadata", Label: "CB-010: reach IMDS", Style: "access"},
				{From: "metadata", To: "iam_creds", Label: "retrieve tokens", Style: "steal"},
				{From: "iam_creds", To: "rbac", Label: "CB-003: K8s escalate", Style: "escalate"},
				{From: "rbac", To: "target", Label: "cluster + cloud admin", Style: "compromise"},
			},
		})
	case "COMPOUND-10": // CB-006 + CB-001
		return marshalGraph(graphPayload{
			Nodes: []graphNode{
				{ID: "container", Label: firstLabel + "\n(container)", Type: "workload"},
				{ID: "socket", Label: "docker.sock\n(CB-006: runtime)", Type: "node"},
				{ID: "new_priv", Label: "Privileged Container\n(spawned)", Type: "workload"},
				{ID: "node", Label: "Node Root\n[TARGET]", Type: "target"},
			},
			Edges: []graphEdge{
				{From: "container", To: "socket", Label: "CB-006: mounted socket", Style: "access"},
				{From: "socket", To: "new_priv", Label: "run --privileged", Style: "escape"},
				{From: "new_priv", To: "node", Label: "CB-001: mount /host", Style: "compromise"},
			},
		})
	}

	// Fallback: generic two-node graph
	return marshalGraph(graphPayload{
		Nodes: []graphNode{{ID: "n1", Label: "Entry Point", Type: "workload"}, {ID: "n2", Label: "Target", Type: "target"}},
		Edges: []graphEdge{{From: "n1", To: "n2", Label: "attack path", Style: "compromise"}},
	})
}

func marshalGraph(gd graphPayload) string {
	b, _ := json.Marshal(gd)
	return string(b)
}
