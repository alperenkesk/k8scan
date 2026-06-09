package capbreaks

import (
	"context"

	"github.com/alperenkeskin/k8scan/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// calculateBlast computes blast radius for a set of evidence findings.
// Mode selection:
//   - BlastModeInfer    → count from evidence only (lint / static)
//   - BlastModeProjected → heuristic simulation (hybrid / Arsenal demo)
//   - BlastModeActual   → live API queries (requires k8sClient != nil)
func calculateBlast(ev []core.CBEvidence, mode core.CBBlastMode, k8sClient kubernetes.Interface) core.CBBlastRadius {
	switch mode {
	case core.BlastModeActual:
		if k8sClient != nil {
			return calcActual(k8sClient)
		}
		// Graceful degradation: fall through to projected if client unavailable.
		fallthrough
	case core.BlastModeProjected:
		return calcProjected(ev)
	default:
		return calcInfer(ev)
	}
}

func calcInfer(ev []core.CBEvidence) core.CBBlastRadius {
	nsSet := make(map[string]struct{})
	for _, e := range ev {
		if e.Namespace != "" {
			nsSet[e.Namespace] = struct{}{}
		}
	}
	ns := len(nsSet)
	if ns == 0 {
		ns = 1
	}
	pods := len(ev) * 3
	secrets := ns * 2

	return core.CBBlastRadius{
		Mode:       core.BlastModeInfer,
		Pods:       pods,
		Namespaces: ns,
		Nodes:      0, // unknowable from static manifests
		Secrets:    secrets,
		Level:      blastLevel(ns, pods, 0),
	}
}

func calcProjected(ev []core.CBEvidence) core.CBBlastRadius {
	nsSet := make(map[string]struct{})
	critCount := 0
	for _, e := range ev {
		if e.Namespace != "" {
			nsSet[e.Namespace] = struct{}{}
		}
		if e.Severity == "CRITICAL" {
			critCount++
		}
	}
	ns := len(nsSet)
	if ns == 0 {
		ns = 1
	}
	nodes := 0
	if critCount > 0 {
		nodes = 1
	}
	pods := ns*5 + critCount*3
	secrets := ns * 3

	return core.CBBlastRadius{
		Mode:       core.BlastModeProjected,
		Pods:       pods,
		Namespaces: ns,
		Nodes:      nodes,
		Secrets:    secrets,
		Level:      blastLevel(ns, pods, nodes),
	}
}

func calcActual(k8sClient kubernetes.Interface) core.CBBlastRadius {
	ctx := context.Background()
	opts := metav1.ListOptions{}

	pods := 0
	ns := 0
	nodes := 0
	secrets := 0

	if pl, err := k8sClient.CoreV1().Pods("").List(ctx, opts); err == nil {
		pods = len(pl.Items)
	}
	if nl, err := k8sClient.CoreV1().Namespaces().List(ctx, opts); err == nil {
		ns = len(nl.Items)
	}
	if ndl, err := k8sClient.CoreV1().Nodes().List(ctx, opts); err == nil {
		nodes = len(ndl.Items)
	}
	if sl, err := k8sClient.CoreV1().Secrets("").List(ctx, opts); err == nil {
		secrets = len(sl.Items)
	}

	return core.CBBlastRadius{
		Mode:       core.BlastModeActual,
		Pods:       pods,
		Namespaces: ns,
		Nodes:      nodes,
		Secrets:    secrets,
		Level:      blastLevel(ns, pods, nodes),
	}
}

func blastLevel(ns, pods, nodes int) string {
	switch {
	case nodes > 1 || (ns > 5 && pods > 30):
		return "CRITICAL"
	case nodes > 0 || ns > 3 || pods > 15:
		return "HIGH"
	case ns > 1 || pods > 5:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
