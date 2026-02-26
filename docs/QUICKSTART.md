# Quick Start Guide

## Prerequisites

1. Python 3.8 or higher
2. kubectl configured with cluster access
3. Appropriate RBAC permissions to read cluster resources

## Installation

```bash
pip install -r requirements.txt
```

## Quick Scan

Run a quick scan and view results in terminal:

```bash
k8scan scan
```

## Common Use Cases

### 1. Generate Full Report (All Formats)
```bash
k8scan scan --output all --output-file my-scan
```
This creates:
- `my-scan.json` - Machine-readable format
- `my-scan.html` - Human-readable HTML report

### 2. Find Critical Issues Only
```bash
k8scan scan --severity CRITICAL
```

### 3. Scan Specific Namespace
```bash
k8scan scan --namespace production
```

### 4. Check Container Security Only
```bash
k8scan scan --category "Container Security"
```

### 5. Export to JSON for CI/CD
```bash
k8scan scan --output json --output-file scan-results
```

## Understanding Output

### Severity Levels

- **CRITICAL**: Immediate action required
  - Privileged containers
  - Docker socket mounts
  - Wildcard RBAC permissions
  
- **HIGH**: Should be fixed soon
  - Host namespace access
  - Dangerous capabilities
  - Secrets in environment variables
  
- **MEDIUM**: Should be addressed
  - Missing resource limits
  - Missing security context
  - Missing network policies
  
- **LOW**: Nice to have
  - Missing health probes
  - Image pull policy issues

## KubeGoat Testing

To test against KubeGoat:

1. Deploy KubeGoat:
```bash
kubectl apply -f https://raw.githubusercontent.com/madhuakula/kubernetes-goat/master/platforms/k8s/kubegoat.yaml
```

2. Run scan:
```bash
k8scan scan --output all
```

Expected findings:
- Privileged containers
- Docker socket mounts
- RBAC misconfigurations
- Missing network policies
- Secrets exposure

## Troubleshooting

### "Unable to load kubeconfig"
```bash
export KUBECONFIG=~/.kube/config
kubectl cluster-info
```

### "Permission denied"
Your service account needs these permissions:
```yaml
- apiGroups: ["", "apps", "rbac.authorization.k8s.io", "networking.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list"]
```

### No findings but cluster has issues
Check if your user has read permissions:
```bash
kubectl auth can-i get pods --all-namespaces
kubectl auth can-i get secrets --all-namespaces
```

## Docker Usage

Build and run in container:
```bash
docker build -t k8scan .
docker run -v ~/.kube:/root/.kube:ro k8scan scan
```

## Next Steps

1. Review CRITICAL and HIGH findings first
2. Fix issues in development environment
3. Integrate into CI/CD pipeline
4. Schedule regular scans
5. Track metrics over time

## Need Help?

Run:
```bash
k8scan --help
k8scan scan --help
k8scan list-categories
```
