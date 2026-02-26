# Control Plane Scanner - Debug Guide

## K8s Architecture Fixes Applied

### 1. API Server Pod Name - FIXED ✅
**Problem:** API server pod name is NOT static
- Actual: `kube-apiserver-kubernetes-goat-cluster-control-plane`
- Wrong code: `if pod.metadata.name == 'kube-apiserver'`
- **Fixed:** `if 'kube-apiserver' in pod.metadata.name`

### 2. Kubelet Config - FIXED ✅
**Problem:** Kubelet is NOT a K8s object
- Kubelet is a systemd service on the node
- Cannot read with `kubectl get`
- **Fixed:** Added manual test guidance (INFO finding)

### 3. Dashboard Namespace Filter - FIXED ✅
**Problem:** Dashboard might be in any namespace
- Common namespaces: kubernetes-dashboard, kube-system, default
- **Fixed:** Scans ALL services in ALL namespaces

### 4. Filter Bypass - FIXED ✅
**Problem:** System namespace filter was blocking Control Plane
- **Fixed:** `_filter_system_findings` now ALWAYS includes Control Plane category

## Testing

```bash
# 1. Check if API server pod is found
kubectl get pods -n kube-system | grep apiserver
# Should see: kube-apiserver-<NODE_NAME>

# 2. Check pod args
kubectl get pod -n kube-system <API_SERVER_POD> -o yaml | grep anonymous-auth

# 3. Check dashboard services
kubectl get svc -A | grep dashboard

# 4. Test kubelet manually
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
curl -k https://$NODE_IP:10250/pods
# If returns data without auth = VULNERABLE
```

## Expected Findings

If vulnerabilities exist, scanner will report:
- ✅ API Server Anonymous Access (CRITICAL) - if --anonymous-auth=true
- ✅ Dashboard Exposed (HIGH) - if type=NodePort/LoadBalancer  
- ✅ Kubelet Manual Test (INFO) - guidance for manual testing

## Code Locations

- API Server check: `src/modules/internal/controlplane_scanner.py:45-75`
- Dashboard check: `src/modules/internal/controlplane_scanner.py:28-43`
- Filter bypass: `src/core/scanner.py:120-133`
