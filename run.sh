#!/bin/bash

echo "k8scan - Kubernetes Security Scanner"
echo "======================================"
echo ""

if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found. Please install kubectl first."
    exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
    echo "Error: Cannot connect to Kubernetes cluster."
    echo "Please configure kubectl to connect to your cluster."
    exit 1
fi

echo "✓ kubectl found and connected to cluster"
echo ""

echo "Current cluster context:"
kubectl config current-context
echo ""

read -p "Do you want to proceed with the security scan? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Scan cancelled."
    exit 0
fi

echo ""
echo "Starting security scan..."
echo ""

./k8scan scan --output all --output-file k8scan-report

echo ""
echo "Scan completed!"
echo "Reports generated:"
echo "  - reports/k8scan-report.json"
echo "  - reports/k8scan-report.html"
