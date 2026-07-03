package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/alperenkesk/k8scan/internal/capbreaks"
	"github.com/alperenkesk/k8scan/internal/compliance"
	"github.com/alperenkesk/k8scan/internal/core"
	"github.com/alperenkesk/k8scan/internal/exploits"
	"github.com/alperenkesk/k8scan/internal/lint"
	"github.com/alperenkesk/k8scan/internal/report"
	"github.com/alperenkesk/k8scan/internal/scanners"
	"github.com/alperenkesk/k8scan/internal/utils"
)

// version is set at build time via:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

// exitError is a sentinel that carries a desired process exit code.
// main() unwraps it so that defer statements always run before exit.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

func main() {
	if err := rootCmd().Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

// ─── Root command ─────────────────────────────────────────────────────────────

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "k8scan",
		Short: "k8scan — Kubernetes security scanner",
		Long: `k8scan performs read-only security audits of Kubernetes clusters.
It requires kubeconfig access or runs in-cluster via a service account.`,
	}
	cmd.AddCommand(scanCmd(), lintCmd(), categoriesCmd(), versionCmd())
	return cmd
}

// ─── Scan command ─────────────────────────────────────────────────────────────

type scanFlags struct {
	namespaces  []string
	categories  []string
	minSeverity string
	outputJSON  string
	outputHTML  string
	outputSARIF string
	outputMD    string
	parallel    bool
	noExploits  bool
	ignoreFile  string
	timeout     int
	failOn      string
	group       bool
	cisReport   bool
}

func scanCmd() *cobra.Command {
	var flags scanFlags

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a Kubernetes cluster for security issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(flags)
		},
	}

	cmd.Flags().StringSliceVarP(&flags.namespaces, "namespace", "n", nil, "Namespaces to scan (default: all)")
	cmd.Flags().StringSliceVar(&flags.categories, "category", nil, "Filter by category (container,rbac,secrets,network,control-plane,workload)")
	cmd.Flags().StringVar(&flags.minSeverity, "min-severity", "", "Minimum severity to report (CRITICAL,HIGH,MEDIUM,LOW,INFO)")
	cmd.Flags().StringVar(&flags.outputJSON, "output-json", "", "Write JSON report to file")
	cmd.Flags().StringVar(&flags.outputHTML, "output-html", "", "Write HTML report to file")
	cmd.Flags().StringVar(&flags.outputSARIF, "output-sarif", "", "Write SARIF 2.1.0 report (GitHub Advanced Security compatible)")
	cmd.Flags().StringVar(&flags.outputMD, "output-md", "", "Write Markdown report to file")
	cmd.Flags().BoolVar(&flags.parallel, "parallel", true, "Run scanners in parallel")
	cmd.Flags().BoolVar(&flags.noExploits, "no-exploits", false, "Skip PoC/exploitation enrichment")
	cmd.Flags().StringVar(&flags.ignoreFile, "ignore-file", ".k8scan-ignore.yaml", "Suppression rules file")
	cmd.Flags().IntVar(&flags.timeout, "timeout", 120, "Scan timeout in seconds")
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "", "Exit with code 2 if findings at this severity or above exist (CRITICAL,HIGH,MEDIUM,LOW)")
	cmd.Flags().BoolVar(&flags.group, "group", false, "Group identical findings — show count instead of one line per resource")
	cmd.Flags().BoolVar(&flags.cisReport, "cis-report", false, "Print CIS Benchmark compliance summary after scan")

	return cmd
}

func runScan(flags scanFlags) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flags.timeout)*time.Second)
	defer cancel()

	printBanner()

	// Connect to cluster
	spinner, _ := pterm.DefaultSpinner.Start("Connecting to cluster...")
	client, err := core.NewK8sClient()
	if err != nil {
		spinner.Fail("Failed to connect: " + err.Error())
		return err
	}
	spinner.Success("Connected to cluster")

	// Fetch cluster metadata
	clusterInfo := client.GetClusterInfo(ctx)
	printClusterInfo(clusterInfo)

	// Load suppression rules
	sm, err := utils.NewSuppressionManager(flags.ignoreFile)
	if err != nil {
		pterm.Warning.Printf("Could not load ignore file: %v\n", err)
		sm, _ = utils.NewSuppressionManager("")
	}
	if sm.ActiveRuleCount() > 0 {
		pterm.Info.Printf("Loaded %d suppression rule(s) from %s\n", sm.ActiveRuleCount(), flags.ignoreFile)
	}

	// Build scanner list
	allScanners := buildScanners(flags.categories)

	// Run scans with per-scanner spinners
	fmt.Println()
	pterm.DefaultSection.Printf("Running %d scanner(s)%s...\n", len(allScanners), parallelLabel(flags.parallel))
	start := time.Now()

	var minSev core.Severity
	if flags.minSeverity != "" {
		minSev = core.Severity(strings.ToUpper(flags.minSeverity))
	}

	// Run scanners with NO filtering so chain analysis sees the full picture.
	// User-provided filters (--category / --namespace / --min-severity) are
	// applied AFTER chain detection so cross-category chains (e.g. container
	// finding + RBAC finding) are not silently broken when the user filters on
	// just one category.
	opts := core.OrchestratorOptions{
		Parallel: flags.parallel,
	}

	findings, results := core.RunScanners(ctx, client, allScanners, opts)

	for _, r := range results {
		if r.Err != nil {
			pterm.Warning.Printf("Scanner '%s' error: %v\n", r.ScannerName, r.Err)
		}
	}

	elapsed := time.Since(start)
	pterm.Success.Printf("Scan completed in %.2fs — %d raw finding(s)\n", elapsed.Seconds(), len(findings))

	// Enrich findings with exploit info
	if !flags.noExploits {
		findings = exploits.EnrichFindings(findings)
	}

	// CIS-03: Enrich all findings with CIS Benchmark metadata
	compliance.Enrich(findings)

	// Capability Break analysis on the full unfiltered set — user filters only
	// affect the Findings tab display, not the boundary-failure analysis.
	cbResult := capbreaks.Analyze(findings, capbreaks.AnalyzeOptions{
		BlastMode: core.BlastModeActual,
		K8sClient: client.Clientset(),
	})
	if len(cbResult.CapabilityBreaks) > 0 {
		pterm.Warning.Printf("Capability break analysis: %d break(s) detected, %d compound path(s)\n",
			len(cbResult.CapabilityBreaks), len(cbResult.CompoundBreaks))
	}

	// Apply user-provided filters AFTER chain detection and enrichment so that
	// chain findings benefit from CIS metadata and so cross-category chains
	// remain visible even when the user narrows the report.
	findings = core.ApplyUserFilters(findings, flags.namespaces, flags.categories, minSev)

	// Apply suppressions
	findings = sm.Filter(findings)

	// Print results
	if flags.group {
		printGroupedFindings(findings)
	} else {
		printFindings(findings)
	}

	// CIS-06: --cis-report flag — compliance summary
	if flags.cisReport {
		printCISReport(findings)
	}

	// Write reports
	meta := report.ReportMeta{
		ClusterContext: clusterInfo.ContextName,
		ClusterVersion: clusterInfo.ServerVersion,
		NodeCount:      clusterInfo.NodeCount,
		NamespaceCount: clusterInfo.NamespaceCount,
		ScanDurationMS: elapsed.Milliseconds(),
		K8scanVersion:  version,
	}
	writeReports(flags, findings, cbResult, meta)

	// CI exit code gate
	if flags.failOn != "" {
		return checkFailOn(findings, flags.failOn)
	}

	return nil
}

// ─── Output: banner + cluster info ───────────────────────────────────────────

func printBanner() {
	fmt.Println()
	pterm.DefaultHeader.
		WithBackgroundStyle(pterm.NewStyle(pterm.BgDarkGray)).
		WithTextStyle(pterm.NewStyle(pterm.FgLightWhite)).
		WithMargin(2).
		Println("k8scan — Kubernetes Security Scanner")
	fmt.Println()
}

func printClusterInfo(info core.ClusterInfo) {
	parts := []string{}
	if info.ContextName != "" {
		parts = append(parts, pterm.Bold.Sprint(info.ContextName))
	}
	if info.ServerVersion != "" {
		parts = append(parts, pterm.Gray(info.ServerVersion))
	}
	if info.NodeCount > 0 {
		parts = append(parts, fmt.Sprintf("%d nodes", info.NodeCount))
	}
	if info.NamespaceCount > 0 {
		parts = append(parts, fmt.Sprintf("%d namespaces", info.NamespaceCount))
	}
	if len(parts) > 0 {
		pterm.Info.Printf("Cluster: %s\n", strings.Join(parts, "  │  "))
	}
}

// ─── Output: findings (flat) ──────────────────────────────────────────────────

func printFindings(findings []*core.Finding) {
	summary := core.BuildSummary(findings)
	score, grade := summary.SecurityScore()

	fmt.Println()
	pterm.DefaultSection.Println("Security Score")
	printScoreBar(score, grade)

	fmt.Println()
	pterm.DefaultSection.Println("Findings by Severity")
	printSeverityBars(summary)

	if summary.Total == 0 {
		fmt.Println()
		pterm.Success.Println("No security issues found!")
		return
	}

	fmt.Println()
	pterm.DefaultSection.Println("Findings")

	for _, f := range findings {
		prefix := severityPrefix(f.Severity)
		cisTag := ""
		if f.CISControl != "" {
			cisTag = pterm.Gray(fmt.Sprintf("  CIS %s · L%d", f.CISControl, f.CISLevel))
		}
		if isChainFinding(f) {
			// Attack chains get a distinct visual block.
			fmt.Println(pterm.Red("  ╔══════════════════════════════════════════════════════════════╗"))
			fmt.Printf(pterm.Red("  ║ ATTACK CHAIN DETECTED: %s\n"), f.Title)
			fmt.Println(pterm.Red("  ╚══════════════════════════════════════════════════════════════╝"))
			if f.Namespace != "" {
				fmt.Printf("          Namespace:    %s\n", f.Namespace)
			}
			if f.Impact != "" {
				fmt.Printf("          Impact:       %s\n", f.Impact)
			}
			if f.Remediation != "" {
				fmt.Printf("          Remediation:  %s\n", f.Remediation)
			}
			fmt.Println()
			continue
		}
		fmt.Printf("%s [%s/%s] %s%s\n",
			prefix,
			f.ResourceType, f.ResourceName,
			f.Title, cisTag,
		)
		if f.Namespace != "" {
			fmt.Printf("          Namespace:    %s\n", f.Namespace)
		}
		if f.Description != "" {
			fmt.Printf("          Description:  %s\n", f.Description)
		}
		if f.Remediation != "" {
			fmt.Printf("          Remediation:  %s\n", f.Remediation)
		}
		fmt.Println()
	}
}

// ─── Output: findings (grouped) ──────────────────────────────────────────────

func printGroupedFindings(findings []*core.Finding) {
	summary := core.BuildSummary(findings)
	score, grade := summary.SecurityScore()

	fmt.Println()
	pterm.DefaultSection.Println("Security Score")
	printScoreBar(score, grade)

	fmt.Println()
	pterm.DefaultSection.Println("Findings by Severity")
	printSeverityBars(summary)

	if summary.Total == 0 {
		fmt.Println()
		pterm.Success.Println("No security issues found!")
		return
	}

	fmt.Println()
	pterm.DefaultSection.Println("Grouped Findings")

	grouped := core.GroupFindings(findings)
	for _, g := range grouped {
		prefix := severityPrefix(g.Severity)
		countLabel := ""
		if g.Count > 1 {
			countLabel = pterm.Gray(fmt.Sprintf(" (×%d resources)", g.Count))
		}
		fmt.Printf("%s %s%s\n", prefix, g.Title, countLabel)
		for _, ex := range g.Examples {
			ns := ""
			if ex.Namespace != "" {
				ns = " [" + ex.Namespace + "]"
			}
			fmt.Printf("          ↳ %s/%s%s\n", ex.ResourceType, ex.ResourceName, ns)
		}
		if g.Count > len(g.Examples) {
			fmt.Printf("          ↳ … and %d more\n", g.Count-len(g.Examples))
		}
		if g.Remediation != "" {
			fmt.Printf("          Remediation: %s\n", g.Remediation)
		}
		fmt.Println()
	}
}

// ─── CIS-06: CIS Benchmark compliance report ──────────────────────────────────

func printCISReport(findings []*core.Finding) {
	cs := compliance.BuildComplianceSummary(findings)
	fmt.Println()
	pterm.DefaultSection.Println("CIS Kubernetes Benchmark v1.8 — Compliance Report")

	mappedPct := 0
	if cs.TotalFindings > 0 {
		mappedPct = cs.MappedFindings * 100 / cs.TotalFindings
	}

	fmt.Printf("  Total findings:          %d\n", cs.TotalFindings)
	fmt.Printf("  CIS-mapped findings:     %d (%d%%)\n", cs.MappedFindings, mappedPct)
	fmt.Printf("  Unique CIS controls hit: %d\n", cs.UniqueControlsViolated)
	fmt.Printf("  Level 1 findings:        %d\n", cs.Level1Findings)
	fmt.Printf("  Level 2 findings:        %d\n", cs.Level2Findings)

	if len(cs.ByProfile) > 0 {
		fmt.Println()
		fmt.Println("  Breakdown by profile:")
		profiles := []string{"Master", "Worker", "etcd", "Policy", "RBAC", "Secrets", "Admission"}
		for _, p := range profiles {
			if count, ok := cs.ByProfile[p]; ok {
				fmt.Printf("    %-12s %d finding(s)\n", p, count)
			}
		}
	}

	// Top violated controls
	type ctrlCount struct {
		ctrl  string
		title string
		count int
	}
	ctrlMap := make(map[string]*ctrlCount)
	for _, f := range findings {
		if f.CISControl == "" {
			continue
		}
		if cc, ok := ctrlMap[f.CISControl]; ok {
			cc.count++
		} else {
			ctrlMap[f.CISControl] = &ctrlCount{ctrl: f.CISControl, title: f.CISTitle, count: 1}
		}
	}
	if len(ctrlMap) > 0 {
		fmt.Println()
		fmt.Println("  Most violated CIS controls:")
		// Print top 5
		printed := 0
		for printed < 5 {
			var best *ctrlCount
			for _, cc := range ctrlMap {
				if best == nil || cc.count > best.count {
					best = cc
				}
			}
			if best == nil {
				break
			}
			fmt.Printf("    CIS %-8s %d finding(s) — %s\n", best.ctrl, best.count, best.title)
			delete(ctrlMap, best.ctrl)
			printed++
		}
	}
	fmt.Println()
}

// ─── Output: score bar + severity bars ───────────────────────────────────────

func printScoreBar(score int, grade string) {
	gradeColor := scoreGradeColor(grade)
	scoreStr := gradeColor(fmt.Sprintf("%d/100  Grade: %s", score, grade))
	fmt.Printf("  Score: %s\n", scoreStr)

	barWidth := 40
	filled := score * barWidth / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("  %s %d%%\n", gradeColor(bar), score)
}

func printSeverityBars(summary core.Summary) {
	type row struct {
		label string
		count int
		color func(...interface{}) string
	}
	maxCount := max(summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info, 1)
	barWidth := 30
	rows := []row{
		{"CRITICAL", summary.Critical, pterm.Red},
		{"HIGH    ", summary.High, pterm.LightRed},
		{"MEDIUM  ", summary.Medium, pterm.Yellow},
		{"LOW     ", summary.Low, pterm.Blue},
		{"INFO    ", summary.Info, pterm.Gray},
	}
	for _, r := range rows {
		filled := r.count * barWidth / maxCount
		bar := strings.Repeat("█", filled)
		fmt.Printf("  %s %s %d\n", pterm.Bold.Sprint(r.label), r.color(bar), r.count)
	}
	fmt.Printf("  %s Total: %d\n", strings.Repeat(" ", 9), summary.Total)
}

func scoreGradeColor(grade string) func(...interface{}) string {
	switch grade {
	case "A":
		return pterm.Green
	case "B":
		return pterm.LightGreen
	case "C":
		return pterm.Yellow
	case "D":
		return pterm.LightRed
	default:
		return pterm.Red
	}
}

// ─── CI/CD: --fail-on ────────────────────────────────────────────────────────

func checkFailOn(findings []*core.Finding, failOn string) error {
	threshold := core.Severity(strings.ToUpper(failOn))
	threshScore := severityNumeric(threshold)

	for _, f := range findings {
		if severityNumeric(f.Severity) <= threshScore {
			pterm.Error.Printf("--fail-on %s: findings at or above threshold detected (exit code 2)\n", failOn)
			// Return a sentinel error so that main() can call os.Exit(2) after
			// all deferred cleanup functions have run.
			return exitError{code: 2}
		}
	}
	return nil
}

func severityNumeric(s core.Severity) int {
	switch s {
	case core.SeverityCritical:
		return 1
	case core.SeverityHigh:
		return 2
	case core.SeverityMedium:
		return 3
	case core.SeverityLow:
		return 4
	default:
		return 5
	}
}

// ─── Report writers ───────────────────────────────────────────────────────────

// inReportsDir returns path unchanged if it contains a directory component,
// otherwise places it under reports/ so all output files land in one folder.
func inReportsDir(path string) string {
	if filepath.Dir(path) != "." {
		return path
	}
	return filepath.Join("reports", path)
}

func writeReports(flags scanFlags, findings []*core.Finding, cbResult core.CBAnalysisResult, meta report.ReportMeta) {
	ts := time.Now().Format("20060102_150405")

	if flags.outputJSON != "" {
		p := inReportsDir(flags.outputJSON)
		if err := report.WriteJSON(findings, cbResult, meta, p); err != nil {
			pterm.Error.Printf("Failed to write JSON report: %v\n", err)
		} else {
			pterm.Success.Printf("JSON  → %s\n", p)
		}
	}

	if flags.outputHTML != "" {
		p := inReportsDir(flags.outputHTML)
		if err := report.WriteHTML(findings, cbResult, meta, p); err != nil {
			pterm.Error.Printf("Failed to write HTML report: %v\n", err)
		} else {
			abs, _ := filepath.Abs(p)
			pterm.Success.Printf("HTML  → %s\n", abs)
		}
	}

	if flags.outputSARIF != "" {
		p := inReportsDir(flags.outputSARIF)
		if err := report.WriteSARIF(findings, meta, p); err != nil {
			pterm.Error.Printf("Failed to write SARIF report: %v\n", err)
		} else {
			pterm.Success.Printf("SARIF → %s  (upload to GitHub Advanced Security)\n", p)
		}
	}

	if flags.outputMD != "" {
		p := inReportsDir(flags.outputMD)
		if err := report.WriteMarkdown(findings, meta, p); err != nil {
			pterm.Error.Printf("Failed to write Markdown report: %v\n", err)
		} else {
			pterm.Success.Printf("MD    → %s\n", p)
		}
	}

	// Always auto-archive timestamped HTML + JSON so every scan has a persistent record.
	archiveHTML := filepath.Join("reports", fmt.Sprintf("report_%s.html", ts))
	if err := report.WriteHTML(findings, cbResult, meta, archiveHTML); err != nil {
		pterm.Warning.Printf("Failed to write archive HTML: %v\n", err)
	} else {
		pterm.Success.Printf("HTML  → %s\n", archiveHTML)
	}

	archiveJSON := filepath.Join("reports", fmt.Sprintf("report_%s.json", ts))
	if err := report.WriteJSON(findings, cbResult, meta, archiveJSON); err != nil {
		pterm.Warning.Printf("Failed to write archive JSON: %v\n", err)
	} else {
		pterm.Success.Printf("JSON  → %s\n", archiveJSON)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func severityPrefix(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return pterm.Red("[CRITICAL]")
	case core.SeverityHigh:
		return pterm.LightRed("[HIGH]    ")
	case core.SeverityMedium:
		return pterm.Yellow("[MEDIUM]  ")
	case core.SeverityLow:
		return pterm.Blue("[LOW]     ")
	default:
		return pterm.Gray("[INFO]    ")
	}
}

func isChainFinding(f *core.Finding) bool {
	return f.Category == "attack-chain"
}

func parallelLabel(parallel bool) string {
	if parallel {
		return " (parallel)"
	}
	return ""
}

// ─── Scanner registry ─────────────────────────────────────────────────────────

// buildScanners returns the full scanner set. Category filtering is applied at
// the finding level by the orchestrator (a single scanner emits findings across
// multiple categories — e.g. ResourceScanner produces container, workload, and
// image findings — so a scanner-level filter would silently drop legitimate
// findings). Performance impact is negligible because each scanner does a
// single List call against the API server.
func buildScanners(_ []string) []core.Scanner {
	return []core.Scanner{
		scanners.PodScanner{},
		scanners.SecretScanner{},
		scanners.ConfigMapScanner{},
		scanners.RBACScanner{},
		scanners.NetworkScanner{},
		scanners.ResourceScanner{},
		scanners.ImageScanner{},
		scanners.ControlPlaneScanner{},
		scanners.KubeletScanner{},
	}
}

// ─── Lint command ─────────────────────────────────────────────────────────────

type lintFlags struct {
	helm        string
	helmValues  []string
	kustomize   string
	outputJSON  string
	outputHTML  string
	outputSARIF string
	outputMD    string
	failOn      string
	noExploits  bool
	cisReport   bool
	recursive   bool
	ignoreFile  string
}

func lintCmd() *cobra.Command {
	var flags lintFlags

	cmd := &cobra.Command{
		Use:   "lint [paths...]",
		Short: "Statically analyse YAML/Helm/Kustomize manifests without a live cluster",
		Long: `lint performs security checks on Kubernetes YAML manifests without connecting
to a cluster. Pass file paths, directory paths, or - to read from stdin.

Examples:
  k8scan lint deployment.yaml
  k8scan lint ./manifests/ --recursive
  k8scan lint ./charts/myapp/ --helm ./charts/myapp/ -f values-prod.yaml
  cat deploy.yaml | k8scan lint -
  k8scan lint ./k8s/ --output-sarif results.sarif --fail-on HIGH`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLint(flags, args)
		},
	}

	cmd.Flags().StringVar(&flags.helm, "helm", "", "Helm chart path — runs `helm template` instead of reading YAML directly")
	cmd.Flags().StringArrayVarP(&flags.helmValues, "helm-values", "f", nil, "Additional Helm values files (used with --helm)")
	cmd.Flags().StringVar(&flags.kustomize, "kustomize", "", "Kustomize path — runs `kubectl kustomize` instead of reading YAML")
	cmd.Flags().BoolVar(&flags.recursive, "recursive", true, "Recurse into subdirectories when loading YAML paths (default: true)")
	cmd.Flags().StringVar(&flags.outputJSON, "output-json", "", "Write JSON report to file")
	cmd.Flags().StringVar(&flags.outputHTML, "output-html", "", "Write HTML report to file")
	cmd.Flags().StringVar(&flags.outputSARIF, "output-sarif", "", "Write SARIF 2.1.0 report to file")
	cmd.Flags().StringVar(&flags.outputMD, "output-md", "", "Write Markdown report to file")
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "", "Exit with code 2 if findings at this severity or above exist")
	cmd.Flags().BoolVar(&flags.noExploits, "no-exploits", false, "Skip PoC/exploitation enrichment")
	cmd.Flags().BoolVar(&flags.cisReport, "cis-report", false, "Print CIS Benchmark compliance summary")
	cmd.Flags().StringVar(&flags.ignoreFile, "ignore-file", ".k8scan-ignore.yaml", "Suppression rules file")

	return cmd
}

func runLint(flags lintFlags, args []string) error {
	ctx := context.Background()
	printBanner()

	// Load manifests
	var store *lint.ManifestStore
	var err error

	switch {
	case flags.helm != "":
		pterm.Info.Printf("Running helm template on %s...\n", flags.helm)
		store, err = lint.LoadHelm(flags.helm, flags.helmValues)
		if err != nil {
			return fmt.Errorf("helm: %w", err)
		}
	case flags.kustomize != "":
		pterm.Info.Printf("Running kubectl kustomize on %s...\n", flags.kustomize)
		store, err = lint.LoadKustomize(flags.kustomize)
		if err != nil {
			return fmt.Errorf("kustomize: %w", err)
		}
	case len(args) == 1 && args[0] == "-":
		pterm.Info.Println("Reading manifests from stdin...")
		store, err = lint.LoadStdin()
		if err != nil {
			return fmt.Errorf("stdin: %w", err)
		}
	default:
		if len(args) == 0 {
			return fmt.Errorf("specify one or more YAML paths, or - for stdin; see --helm / --kustomize for rendered manifests")
		}
		pterm.Info.Printf("Loading %d path(s)...\n", len(args))
		store, err = lint.LoadPaths(args)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
	}

	staticClient := lint.NewStaticClient(store)

	// Run all scanners against the static client
	allScanners := buildScanners(nil)
	pterm.DefaultSection.Printf("Running %d scanner(s) in static mode...\n", len(allScanners))
	start := time.Now()

	opts := core.OrchestratorOptions{Parallel: false}
	findings, results := core.RunScanners(ctx, staticClient, allScanners, opts)

	for _, r := range results {
		if r.Err != nil {
			pterm.Warning.Printf("Scanner '%s' error: %v\n", r.ScannerName, r.Err)
		}
	}
	elapsed := time.Since(start)
	pterm.Success.Printf("Lint completed in %.2fs — %d finding(s)\n", elapsed.Seconds(), len(findings))

	// Populate SourceFile/SourceLine from the manifest store
	for _, f := range findings {
		if sf := staticClient.SourceFile(f.ResourceType, f.Namespace, f.ResourceName); sf != "" {
			f.SourceFile = sf
			f.SourceLine = staticClient.SourceLine(f.ResourceType, f.Namespace, f.ResourceName)
		}
	}

	// Enrich
	if !flags.noExploits {
		findings = exploits.EnrichFindings(findings)
	}
	compliance.Enrich(findings)

	// Capability Break analysis — lint mode uses INFER (no live client)
	cbResult := capbreaks.Analyze(findings, capbreaks.AnalyzeOptions{
		BlastMode: core.BlastModeInfer,
	})
	if len(cbResult.CapabilityBreaks) > 0 {
		pterm.Warning.Printf("Capability break analysis: %d break(s) detected, %d compound path(s)\n",
			len(cbResult.CapabilityBreaks), len(cbResult.CompoundBreaks))
	}

	// Apply suppression rules (same .k8scan-ignore.yaml format as scan mode) after
	// chain analysis so suppressed findings don't distort CB detection.
	if sm, err := utils.NewSuppressionManager(flags.ignoreFile); err == nil {
		if sm.ActiveRuleCount() > 0 {
			pterm.Info.Printf("Loaded %d suppression rule(s) from %s\n", sm.ActiveRuleCount(), flags.ignoreFile)
		}
		findings = sm.Filter(findings)
	}

	// Print
	printLintFindings(findings)

	if flags.cisReport {
		printCISReport(findings)
	}

	// Write reports
	meta := report.ReportMeta{
		K8scanVersion:  version,
		ScanDurationMS: elapsed.Milliseconds(),
	}
	writeLintReports(flags, findings, cbResult, meta)

	if flags.failOn != "" {
		return checkFailOn(findings, flags.failOn)
	}
	return nil
}

func printLintFindings(findings []*core.Finding) {
	summary := core.BuildSummary(findings)
	score, grade := summary.SecurityScore()

	fmt.Println()
	pterm.DefaultSection.Println("Security Score")
	printScoreBar(score, grade)

	fmt.Println()
	pterm.DefaultSection.Println("Findings by Severity")
	printSeverityBars(summary)

	if summary.Total == 0 {
		fmt.Println()
		pterm.Success.Println("No security issues found!")
		return
	}

	fmt.Println()
	pterm.DefaultSection.Println("Findings")

	for _, f := range findings {
		prefix := severityPrefix(f.Severity)
		cisTag := ""
		if f.CISControl != "" {
			cisTag = pterm.Gray(fmt.Sprintf("  CIS %s · L%d", f.CISControl, f.CISLevel))
		}
		loc := ""
		if f.SourceFile != "" {
			loc = pterm.Gray(fmt.Sprintf("  (%s:%d)", f.SourceFile, f.SourceLine))
		}
		if isChainFinding(f) {
			fmt.Println(pterm.Red("  ╔══════════════════════════════════════════════════════════════╗"))
			fmt.Printf(pterm.Red("  ║ ATTACK CHAIN DETECTED: %s\n"), f.Title)
			fmt.Println(pterm.Red("  ╚══════════════════════════════════════════════════════════════╝"))
			if f.Namespace != "" {
				fmt.Printf("          Namespace:    %s\n", f.Namespace)
			}
			if f.Impact != "" {
				fmt.Printf("          Impact:       %s\n", f.Impact)
			}
			if f.Remediation != "" {
				fmt.Printf("          Remediation:  %s\n", f.Remediation)
			}
			if f.SourceFile != "" {
				fmt.Printf("          Source:       %s\n", loc)
			}
			fmt.Println()
			continue
		}
		fmt.Printf("%s [%s/%s] %s%s%s\n",
			prefix,
			f.ResourceType, f.ResourceName,
			f.Title, cisTag, loc,
		)
		if f.Remediation != "" {
			fmt.Printf("          Remediation:  %s\n", f.Remediation)
		}
		fmt.Println()
	}
}

func writeLintReports(flags lintFlags, findings []*core.Finding, cbResult core.CBAnalysisResult, meta report.ReportMeta) {
	sf := scanFlags{
		outputJSON:  flags.outputJSON,
		outputHTML:  flags.outputHTML,
		outputSARIF: flags.outputSARIF,
		outputMD:    flags.outputMD,
	}
	writeReports(sf, findings, cbResult, meta)
}

// ─── Other commands ───────────────────────────────────────────────────────────

func categoriesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "categories",
		Short: "List available scan categories",
		Run: func(cmd *cobra.Command, args []string) {
			pterm.DefaultSection.Println("Available Scan Categories")
			data := pterm.TableData{
				{"Category", "Scanners", "Description"},
				{"container", "PodScanner", "Privileged containers, host namespaces, capabilities, seccomp, crypto miners, DIND"},
				{"secrets", "SecretScanner, ConfigMapScanner", "Credentials in secrets, ConfigMaps, env vars"},
				{"rbac", "RBACScanner", "Wildcard permissions, pod exec, secrets read, SA token creation, bindings"},
				{"network", "NetworkScanner", "Network policies, NodePort, LoadBalancer, Ingress TLS, cloud metadata"},
				{"workload", "ResourceScanner", "Resource limits, probes, image tags, replica count, CronJobs"},
				{"control-plane", "ControlPlaneScanner, KubeletScanner", "API server, etcd, Tiller, Dashboard, PSA, Kubelet, runtime monitoring"},
			}
			_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()

			fmt.Println()
			pterm.DefaultSection.Println("Output Formats")
			formats := pterm.TableData{
				{"Flag", "Format", "Use case"},
				{"--output-json", "JSON", "Machine-readable, API integration"},
				{"--output-html", "HTML", "Dark-theme interactive report"},
				{"--output-sarif", "SARIF 2.1.0", "GitHub Advanced Security / GitLab"},
				{"--output-md", "Markdown", "GitHub issues, PR comments, README"},
			}
			_ = pterm.DefaultTable.WithHasHeader().WithData(formats).Render()

			fmt.Println()
			pterm.DefaultSection.Println("CI/CD Integration")
			pterm.Info.Println("Exit code 2 when findings meet threshold:")
			fmt.Println("  k8scan scan --fail-on CRITICAL     # Fail pipeline on any CRITICAL")
			fmt.Println("  k8scan scan --fail-on HIGH          # Fail on CRITICAL or HIGH")
			fmt.Println("  k8scan scan --output-sarif out.sarif  # Upload to GitHub Security tab")
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("k8scan %s — Kubernetes Security Scanner\n", version)
			fmt.Println("Built with Go · Read-only · Zero cluster-side components")
		},
	}
}
