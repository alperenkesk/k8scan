#!/bin/bash
echo "=== Control Plane Zafiyet Test Script ==="

# 1. Dashboard kur ve NodePort olarak expose et
echo ""
echo "1. Dashboard kuruluyor..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

echo ""
echo "2. 10 saniye bekleniyor..."
sleep 10

echo ""
echo "3. Dashboard NodePort'a çevriliyor..."
kubectl patch svc kubernetes-dashboard -n kubernetes-dashboard -p '{"spec":{"type":"NodePort"}}'

echo ""
echo "4. Dashboard durumu:"
kubectl get svc kubernetes-dashboard -n kubernetes-dashboard

echo ""
echo "5. Şimdi k8scan'i çalıştır:"
echo "   ./k8scan scan --exclude-system -o html"
echo ""
echo "Beklenen: HIGH - Kubernetes Dashboard Exposed Externally"
