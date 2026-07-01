#!/usr/bin/env bash
set -euo pipefail

# k8scan-export.sh — export Kubernetes manifests for k8scan security analysis
# Usage: ./k8scan-export.sh [output-dir]

OUTPUT_DIR="${1:-k8scan-export-$(date +%Y%m%d-%H%M%S)}"
ZIP_FILE="${OUTPUT_DIR}.zip"

NAMESPACED_RESOURCES="deployments statefulsets daemonsets jobs cronjobs \
  services ingresses networkpolicies \
  rolebindings serviceaccounts configmaps \
  limitranges resourcequotas horizontalpodautoscalers \
  poddisruptionbudgets"

CLUSTER_RESOURCES="namespaces clusterroles clusterrolebindings \
  podsecuritypolicies ingressclasses storageclasses \
  persistentvolumes"

echo "[k8scan] Starting cluster export..."
echo "[k8scan] Output: ${OUTPUT_DIR}/"

# Check kubectl is available
if ! command -v kubectl &>/dev/null; then
  echo "Error: kubectl not found in PATH" >&2
  exit 1
fi

# Check cluster connectivity
if ! kubectl cluster-info &>/dev/null 2>&1; then
  echo "Error: cannot connect to cluster. Check your kubeconfig." >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# ── Cluster-scoped resources ────────────────────────────────────────────────
mkdir -p "${OUTPUT_DIR}/_cluster"
echo "[k8scan] Exporting cluster-scoped resources..."
for resource in $CLUSTER_RESOURCES; do
  kubectl get "$resource" -o yaml 2>/dev/null > "${OUTPUT_DIR}/_cluster/${resource}.yaml" || true
done

# ── Namespaced resources ─────────────────────────────────────────────────────
NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
echo "[k8scan] Namespaces found: ${NAMESPACES}"

for ns in $NAMESPACES; do
  mkdir -p "${OUTPUT_DIR}/${ns}"
  for resource in $NAMESPACED_RESOURCES; do
    kubectl get "$resource" -n "$ns" -o yaml 2>/dev/null > "${OUTPUT_DIR}/${ns}/${resource}.yaml" || true
  done
done

# ── Image list (for optional Trivy scan) ─────────────────────────────────────
echo "[k8scan] Collecting container image list..."
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{.spec.initContainers[*].image}{"\n"}{end}' \
  2>/dev/null | sort -u | grep -v '^$' > "${OUTPUT_DIR}/images.txt" || true

IMAGE_COUNT=$(wc -l < "${OUTPUT_DIR}/images.txt" | tr -d ' ')
echo "[k8scan] Found ${IMAGE_COUNT} unique images → images.txt"

# ── Context metadata ─────────────────────────────────────────────────────────
{
  echo "exported_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "context: $(kubectl config current-context 2>/dev/null || echo unknown)"
  echo "server: $(kubectl cluster-info 2>/dev/null | head -1 | sed 's/\x1B\[[0-9;]*m//g' || echo unknown)"
} > "${OUTPUT_DIR}/meta.yaml"

# ── Zip ──────────────────────────────────────────────────────────────────────
zip -r "${ZIP_FILE}" "${OUTPUT_DIR}" -x "*.DS_Store" > /dev/null
rm -rf "${OUTPUT_DIR}"

echo ""
echo "[k8scan] Export complete: ${ZIP_FILE}"
echo "[k8scan] Upload this file at https://k8scan.com to start your security scan."
