package scanners

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/alperenkeskin/k8scan/internal/core"
)

// ImageScanner inspects container image references for security hygiene issues.
// It focuses on registry trust, image pinning, and known dangerous base images.
type ImageScanner struct{}

func (ImageScanner) Name() string { return "Image Security" }

func (ImageScanner) Scan(ctx context.Context, client core.KubeReader) ([]*core.Finding, error) {
	deployments, err := client.GetAllDeployments(ctx)
	if err != nil {
		return nil, err
	}
	statefulSets, err := client.GetAllStatefulSets(ctx)
	if err != nil {
		return nil, err
	}
	daemonSets, err := client.GetAllDaemonSets(ctx)
	if err != nil {
		return nil, err
	}

	var findings []*core.Finding
	seen := make(map[string]struct{}) // deduplicate same image in same workload

	emit := func(containers []corev1.Container, rt, rn, ns string) {
		for _, c := range containers {
			key := rt + "/" + rn + "/" + c.Image
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, checkImage(c.Image, c.Name, rt, rn, ns)...)
		}
	}

	for _, d := range deployments {
		if isSystemNamespace(d.Namespace) {
			continue
		}
		emit(d.Spec.Template.Spec.Containers, "Deployment", d.Name, d.Namespace)
		emit(d.Spec.Template.Spec.InitContainers, "Deployment", d.Name, d.Namespace)
	}
	for _, ss := range statefulSets {
		if isSystemNamespace(ss.Namespace) {
			continue
		}
		emit(ss.Spec.Template.Spec.Containers, "StatefulSet", ss.Name, ss.Namespace)
		emit(ss.Spec.Template.Spec.InitContainers, "StatefulSet", ss.Name, ss.Namespace)
	}
	for _, ds := range daemonSets {
		if isSystemNamespace(ds.Namespace) {
			continue
		}
		emit(ds.Spec.Template.Spec.Containers, "DaemonSet", ds.Name, ds.Namespace)
		emit(ds.Spec.Template.Spec.InitContainers, "DaemonSet", ds.Name, ds.Namespace)
	}

	return findings, nil
}

// ─── Per-image checks ─────────────────────────────────────────────────────────

func checkImage(image, containerName, rt, rn, ns string) []*core.Finding {
	var findings []*core.Finding

	findings = append(findings, checkImageDigestPin(image, containerName, rt, rn, ns)...)
	findings = append(findings, checkUntrustedRegistry(image, containerName, rt, rn, ns)...)
	findings = append(findings, checkKnownVulnerableBaseImage(image, containerName, rt, rn, ns)...)

	return findings
}

// ─── I-01: Tag instead of digest ─────────────────────────────────────────────
// Images pinned with tags (even specific versions) can be overridden.
// Only @sha256: digests guarantee immutability.

func checkImageDigestPin(image, containerName, rt, rn, ns string) []*core.Finding {
	if strings.Contains(image, "@sha256:") {
		return nil // pinned with digest — immutable
	}
	return []*core.Finding{{
		Severity:     core.SeverityMedium,
		Category:     "image",
		Title:        "Image Not Pinned to Digest",
		Description:  fmt.Sprintf("Container '%s' in %s '%s' uses image '%s' with a tag (not a digest). Tags are mutable — a registry push can silently change what image is pulled, enabling supply-chain attacks.", containerName, rt, rn, image),
		ResourceType: rt, ResourceName: rn, Namespace: ns,
		Remediation: "Pin images to their SHA256 digest (e.g. nginx@sha256:abc123...). Use tools like Cosign or docker inspect to get the digest.",
		Metadata:    map[string]any{"image": image, "container": containerName},
	}}
}

// ─── I-03: Untrusted registry ─────────────────────────────────────────────────

var trustedRegistries = []string{
	"docker.io/",
	"index.docker.io/",
	"registry-1.docker.io/",
	"gcr.io/",
	"us.gcr.io/", "eu.gcr.io/", "asia.gcr.io/",
	"registry.k8s.io/",
	"k8s.gcr.io/",
	"quay.io/",
	"ghcr.io/",
	"public.ecr.aws/",
	"mcr.microsoft.com/",
	"nvcr.io/",
	"docker.elastic.co/",
	"registry.access.redhat.com/",
}

// Known public image name prefixes (no registry host, hosted on docker.io/library)
var dockerHubOfficialPrefixes = []string{
	"nginx", "redis", "postgres", "mysql", "mongo", "mariadb",
	"alpine", "ubuntu", "debian", "centos", "fedora",
	"python", "node", "golang", "ruby", "php", "java",
	"busybox", "scratch", "hello-world",
	"openjdk", "adoptopenjdk", "eclipse-temurin",
	"wordpress", "nextcloud", "drupal",
	"traefik", "caddy", "haproxy",
	"grafana/", "prom/", "elastic/",
}

func checkUntrustedRegistry(image, containerName, rt, rn, ns string) []*core.Finding {
	imgLower := strings.ToLower(image)

	// Trusted explicit registry prefix
	for _, reg := range trustedRegistries {
		if strings.HasPrefix(imgLower, reg) {
			return nil
		}
	}

	// Docker Hub official image (no host component)
	if !strings.Contains(strings.SplitN(imgLower, "/", 2)[0], ".") {
		for _, prefix := range dockerHubOfficialPrefixes {
			if strings.HasPrefix(imgLower, prefix) {
				return nil
			}
		}
		// docker.io implicit — single component or user/image format without a dot
		return nil
	}

	// Image has a hostname-like prefix (contains dot before first slash) — check if trusted
	parts := strings.SplitN(imgLower, "/", 2)
	host := parts[0]
	if !strings.Contains(host, ".") {
		return nil // not a hostname
	}

	return []*core.Finding{{
		Severity:     core.SeverityHigh,
		Category:     "image",
		Title:        "Image from Potentially Untrusted Registry",
		Description:  fmt.Sprintf("Container '%s' in %s '%s' pulls image '%s' from registry '%s' which is not in the known-trusted registry list. Images from unknown registries may contain malware or backdoors.", containerName, rt, rn, image, host),
		ResourceType: rt, ResourceName: rn, Namespace: ns,
		Remediation: "Pull from trusted registries only (docker.io, gcr.io, quay.io, ghcr.io, ECR). Mirror approved images to an internal registry and enforce via OPA/Kyverno image policy.",
		Metadata:    map[string]any{"image": image, "registry": host, "container": containerName},
	}}
}

// ─── I-02: Known vulnerable / large base images ───────────────────────────────

type baseImageRisk struct {
	keywords []string
	title    string
	reason   string
}

var riskyBaseImages = []baseImageRisk{
	{
		keywords: []string{"centos:6", "centos:7", "centos:8"},
		title:    "End-of-Life Base Image (CentOS)",
		reason:   "CentOS 6, 7, and 8 are end-of-life — no security patches. Known CVEs will never be fixed.",
	},
	{
		keywords: []string{"ubuntu:14.04", "ubuntu:16.04", "ubuntu:18.04"},
		title:    "End-of-Life Base Image (Ubuntu)",
		reason:   "Ubuntu 14.04/16.04/18.04 reached end-of-life — security patches no longer provided.",
	},
	{
		keywords: []string{"debian:jessie", "debian:stretch", "debian:buster"},
		title:    "End-of-Life Base Image (Debian)",
		reason:   "Debian Jessie/Stretch/Buster reached end-of-life — no security updates.",
	},
	{
		keywords: []string{"python:2", "python:2.7"},
		title:    "End-of-Life Python 2 Image",
		reason:   "Python 2 reached end-of-life in January 2020. No security patches available.",
	},
	{
		keywords: []string{"node:10", "node:12", "node:14"},
		title:    "End-of-Life Node.js Image",
		reason:   "Node.js 10/12/14 are end-of-life and no longer receive security patches.",
	},
}

func checkKnownVulnerableBaseImage(image, containerName, rt, rn, ns string) []*core.Finding {
	imgLower := strings.ToLower(image)
	// Strip registry prefix and digest/tag for comparison
	ref := imgLower
	if idx := strings.LastIndex(ref, "/"); idx >= 0 {
		ref = ref[idx+1:]
	}
	ref = strings.Split(ref, "@")[0] // strip digest

	var findings []*core.Finding
	for _, risk := range riskyBaseImages {
		for _, kw := range risk.keywords {
			if strings.HasPrefix(ref, kw) || strings.Contains(imgLower, kw) {
				findings = append(findings, &core.Finding{
					Severity:     core.SeverityHigh,
					Category:     "image",
					Title:        risk.title,
					Description:  fmt.Sprintf("Container '%s' in %s '%s' uses image '%s'. %s", containerName, rt, rn, image, risk.reason),
					ResourceType: rt, ResourceName: rn, Namespace: ns,
					Remediation: "Upgrade to a supported base image. Prefer minimal images (Alpine, Debian slim, or distroless) from a maintained major version.",
					Metadata:    map[string]any{"image": image, "container": containerName},
				})
				break
			}
		}
	}
	return findings
}

var _ core.Scanner = ImageScanner{}
