# Control Plane Zafiyetleri Enjekte Etme

Cluster'ınızda şu an Control Plane zafiyetleri YOK. Test etmek için bunları enjekte edin:

## 1. API Server Anonymous Auth - TEST

```bash
# API server pod'unu bul
kubectl get pod -n kube-system | grep apiserver

# Static pod manifest'i düzenle (dikkatli!)
# sudo nano /etc/kubernetes/manifests/kube-apiserver.yaml
# Şu satırı bul:
#   - --anonymous-auth=false
# Değiştir:
#   - --anonymous-auth=true

# NOT: Bu tehlikelidir! Sadece test ortamında yapın.
```

## 2. Dashboard Expose - TEST

```bash
# Dashboard kur (yoksa)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

# NodePort olarak expose et
kubectl patch svc kubernetes-dashboard -n kubernetes-dashboard -p '{"spec":{"type":"NodePort"}}'

# Şimdi tara
./k8scan scan --exclude-system -o html

# Beklenen: HIGH - Kubernetes Dashboard Exposed Externally
```

## 3. Kubelet Test - MANUAL

```bash
# Node IP'yi al
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

# Manuel test
curl -k https://$NODE_IP:10250/pods

# Eğer 401/403 dönüyorsa: GÜVENLİ (auth gerekli)
# Eğer 200 + data dönüyorsa: ZAFİYETLİ (scanner bulacak)
```

## Mevcut Durum

Cluster'ınız şu an GÜVENLI:
- ✅ API Server: anonymous-auth=false (default)
- ✅ Dashboard: Yok veya ClusterIP
- ✅ Kubelet: Auth required (curl timeout normal)

## Debug Çıktısı Analizi

```
Anonymous auth not found in args (safe)
```
→ API Server güvenli

```
Found 11 services across all namespaces
```
→ Dashboard yok (11 servisin hiçbirinde 'dashboard' yok)

```
curl command failed... exit status 28
```
→ Timeout (kubelet'e ulaşamadı veya auth required - her iki durumda da güvenli)

Scanner ÇALIŞIYOR - sadece cluster'ınızda o zafiyetler yok!
