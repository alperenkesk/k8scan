package capbreaks

import (
	"fmt"
	"sort"

	"github.com/alperenkesk/k8scan/internal/core"
	"k8s.io/client-go/kubernetes"
)

// AnalyzeOptions controls blast-radius mode and optional live cluster access.
type AnalyzeOptions struct {
	// BlastMode selects INFER (lint), PROJECTED (hybrid), or ACTUAL (live).
	BlastMode core.CBBlastMode
	// K8sClient is required for BlastModeActual; pass nil for lint/hybrid modes.
	K8sClient kubernetes.Interface
}

// Analyze evaluates all CB rules against the given findings, detects compound
// breaks, and builds cross-reference maps for the HTML reporter.
func Analyze(findings []*core.Finding, opts AnalyzeOptions) core.CBAnalysisResult {
	if opts.BlastMode == "" {
		opts.BlastMode = core.BlastModeInfer
	}

	// ── Step 1: evaluate all CB rules ────────────────────────
	var activeCBs []core.CapabilityBreak
	// findingIDtoCBs: FindingID (string) → list of CB IDs
	findingCBMap := make(map[string][]string)

	for _, rule := range allRules() {
		matched, cb := rule(findings)
		if cb == nil {
			continue
		}
		// Attach blast radius, PoC, validation proof, and attack graph
		cb.BlastRadius = calculateBlast(cb.Evidence, opts.BlastMode, opts.K8sClient)
		cb.ProofOfConcept = buildPoC(cb.ID, cb.Evidence)
		cb.ValidationProof = buildValidationProof(cb.ID, matched)
		cb.GraphJSON = BuildCBGraphJSON(cb.ID, cb.Evidence)
		activeCBs = append(activeCBs, *cb)

		// Register cross-references
		for _, sig := range matched {
			key := fmt.Sprintf("%d", sig.finding.FindingID)
			cbIDs := findingCBMap[key]
			if !containsStr(cbIDs, cb.ID) {
				findingCBMap[key] = append(cbIDs, cb.ID)
			}
		}
	}

	// Sort CBs: BROKEN first, then by exploitability, then confidence desc.
	sort.Slice(activeCBs, func(i, j int) bool {
		si := cbSortScore(activeCBs[i])
		sj := cbSortScore(activeCBs[j])
		if si != sj {
			return si < sj
		}
		return activeCBs[i].Confidence > activeCBs[j].Confidence
	})

	// ── Step 2: detect compound breaks ───────────────────────
	compounds := detectCompounds(activeCBs, opts.BlastMode, nil)

	// Attach attack graph JSON to each compound
	for i := range compounds {
		compounds[i].GraphJSON = BuildCompoundGraphJSON(compounds[i].ID, compounds[i].CBs)
	}

	// Build FindingCompoundMap: FindingID → compound IDs
	findingCompoundMap := make(map[string][]string)
	for _, compound := range compounds {
		// Any finding that contributes to a constituent CB also contributes to this compound.
		for _, cb := range compound.CBs {
			for _, ev := range cb.Evidence {
				key := fmt.Sprintf("%d", ev.FindingID)
				ids := findingCompoundMap[key]
				if !containsStr(ids, compound.ID) {
					findingCompoundMap[key] = append(ids, compound.ID)
				}
			}
		}
	}

	return core.CBAnalysisResult{
		CapabilityBreaks:   activeCBs,
		CompoundBreaks:     compounds,
		FindingCBMap:       findingCBMap,
		FindingCompoundMap: findingCompoundMap,
		BlastMode:          opts.BlastMode,
	}
}

// cbSortScore returns a sort key (lower = more urgent).
func cbSortScore(cb core.CapabilityBreak) int {
	status := map[core.CBStatus]int{
		core.CBStatusBroken:   0,
		core.CBStatusDegraded: 1,
		core.CBStatusWeak:     2,
	}
	exploit := map[core.CBExploitability]int{
		core.CBExploitImmediate: 0,
		core.CBExploitHigh:      1,
		core.CBExploitMedium:    2,
		core.CBExploitLow:       3,
	}
	return status[cb.Status]*10 + exploit[cb.Exploitability]
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
