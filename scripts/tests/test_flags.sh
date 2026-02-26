#!/bin/bash
set -e
echo "Test 1: categories"
./k8scan categories > /dev/null
echo "Test 2: severity"
./k8scan scan --severity CRITICAL > /dev/null
echo "Test 3: top"
./k8scan scan --top 10 > /dev/null
echo "Test 4: namespace"
./k8scan scan --namespace default > /dev/null
echo "Test 5: category"
./k8scan scan --category "Container Security" > /dev/null
echo "Test 6: version"
./k8scan --version > /dev/null
echo "Test 7: custom file"
./k8scan scan -f reports/my_custom_report > /dev/null
if [ ! -f reports/my_custom_report.html ]; then
  echo "CUSTOM FILE NOT FOUND"
  exit 1
fi
rm -f reports/my_custom_report.*
echo "ALL PASSED"
