package core

import (
	"context"
	"fmt"
	"sync"
)

// ScanResult holds the findings and errors from a single scanner.
type ScanResult struct {
	ScannerName string
	Findings    []*Finding
	Err         error
}

// OrchestratorOptions controls scan execution. Finding-level filtering
// (namespace / category / severity) is performed by ApplyUserFilters after
// chain detection, not here, so chain context is preserved.
type OrchestratorOptions struct {
	// Parallel controls whether scanners run concurrently.
	Parallel bool
	// MinSeverity, if set, filters out findings below this threshold during
	// the merge phase. Prefer ApplyUserFilters for post-chain filtering.
	MinSeverity Severity
}

// RunScanners executes all provided scanners against client.
// When opts.Parallel is true, scanners run concurrently and their findings
// are merged once all complete.
func RunScanners(ctx context.Context, client KubeReader, scanners []Scanner, opts OrchestratorOptions) ([]*Finding, []ScanResult) {
	var (
		mu      sync.Mutex
		results []ScanResult
	)

	if opts.Parallel {
		var wg sync.WaitGroup
		wg.Add(len(scanners))
		for _, s := range scanners {
			s := s
			go func() {
				defer wg.Done()
				findings, err := s.Scan(ctx, client)
				mu.Lock()
				results = append(results, ScanResult{ScannerName: s.Name(), Findings: findings, Err: err})
				mu.Unlock()
			}()
		}
		wg.Wait()
	} else {
		for _, s := range scanners {
			findings, err := s.Scan(ctx, client)
			results = append(results, ScanResult{ScannerName: s.Name(), Findings: findings, Err: err})
		}
	}

	// Merge findings, deduplicate, assign sequential IDs, apply filters.
	// Deduplication key: (title, severity, namespace, resource_name) — prevents the same
	// security issue from appearing multiple times when multiple containers in
	// the same workload all trigger the same check, while keeping distinct severity
	// variants (e.g. SYS_ADMIN CRITICAL vs NET_RAW HIGH on the same workload).
	var all []*Finding
	seen := make(map[string]struct{})
	id := 1
	for _, r := range results {
		for _, f := range r.Findings {
			key := f.Title + "\x00" + string(f.Severity) + "\x00" + f.Namespace + "\x00" + f.ResourceName
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			f.FindingID = id
			id++
			all = append(all, f)
		}
	}

	if opts.MinSeverity != "" {
		all = FilterBySeverity(all, opts.MinSeverity)
	}
	SortFindings(all)
	return all, results
}

// ApplyUserFilters narrows a findings slice by namespace, category, and minimum
// severity. Attack-chain findings are kept as long as they match the namespace
// and severity constraints (so the user does not lose chain context when
// filtering by category).
func ApplyUserFilters(findings []*Finding, namespaces, categories []string, minSeverity Severity) []*Finding {
	out := findings
	if minSeverity != "" {
		out = FilterBySeverity(out, minSeverity)
	}
	if len(categories) > 0 {
		var filtered []*Finding
		for _, f := range out {
			// Always keep attack-chain findings — they synthesise context across
			// multiple categories and should not disappear when the user filters
			// down to a single category.
			if f.Category == "attack-chain" {
				filtered = append(filtered, f)
				continue
			}
			for _, cat := range categories {
				if containsFold(f.Category, cat) {
					filtered = append(filtered, f)
					break
				}
			}
		}
		out = filtered
	}
	if len(namespaces) > 0 {
		var filtered []*Finding
		for _, f := range out {
			// Cluster-wide findings (Namespace == "") are always included —
			// ControlPlane, Kubelet and similar scanners produce findings
			// without a namespace and must never be silently dropped by a
			// namespace filter.
			if f.Namespace == "" {
				filtered = append(filtered, f)
				continue
			}
			for _, ns := range namespaces {
				if f.Namespace == ns {
					filtered = append(filtered, f)
					break
				}
			}
		}
		out = filtered
	}
	return out
}

// ScanErrors returns a combined error string from scan results, or nil if all succeeded.
func ScanErrors(results []ScanResult) error {
	var errs []string
	for _, r := range results {
		if r.Err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.ScannerName, r.Err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%d scanner(s) failed: %v", len(errs), errs)
}
