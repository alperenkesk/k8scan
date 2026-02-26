#!/usr/bin/env python3
"""
Test Control Plane Scanner independently
"""
import sys
sys.path.insert(0, '/home/claude/k8scan')

from src.modules.internal.controlplane_scanner import ControlPlaneScanner

# Mock objects for testing
class MockMetadata:
    def __init__(self, name, namespace):
        self.name = name
        self.namespace = namespace

class MockSpec:
    def __init__(self, svc_type='ClusterIP', ports=None, containers=None):
        self.type = svc_type
        self.ports = ports or []
        self.containers = containers or []

class MockPort:
    def __init__(self, port, node_port=None):
        self.port = port
        self.node_port = node_port

class MockContainer:
    def __init__(self, name, command=None, args=None):
        self.name = name
        self.command = command or []
        self.args = args or []

class MockService:
    def __init__(self, name, namespace, svc_type='ClusterIP', ports=None):
        self.metadata = MockMetadata(name, namespace)
        self.spec = MockSpec(svc_type, ports)

class MockPod:
    def __init__(self, name, namespace, containers):
        self.metadata = MockMetadata(name, namespace)
        self.spec = MockSpec(containers=containers)

# Test scenarios
print("=== Testing Control Plane Scanner ===\n")

scanner = ControlPlaneScanner()

# Test 1: Dashboard exposed
print("Test 1: Dashboard Exposed")
dashboard_svc = MockService(
    'kubernetes-dashboard',
    'kubernetes-dashboard',
    'NodePort',
    [MockPort(443, 30443)]
)
findings = scanner._check_exposed_dashboard([dashboard_svc])
print(f"Found {len(scanner.findings)} dashboard findings")
if scanner.findings:
    print(f"  - {scanner.findings[-1].title}")
scanner.findings = []

# Test 2: API Server with anonymous auth
print("\nTest 2: API Server Anonymous Auth")
apiserver_pod = MockPod(
    'kube-apiserver-kind-control-plane',
    'kube-system',
    [MockContainer(
        'kube-apiserver',
        command=['kube-apiserver'],
        args=['--anonymous-auth=true', '--authorization-mode=Node,RBAC']
    )]
)
findings = scanner._check_api_server_config([apiserver_pod])
print(f"Found {len(scanner.findings)} API server findings")
if scanner.findings:
    print(f"  - {scanner.findings[-1].title}")
scanner.findings = []

# Test 3: API Server without anonymous auth (should not find)
print("\nTest 3: API Server WITHOUT Anonymous Auth")
safe_apiserver = MockPod(
    'kube-apiserver-minikube',
    'kube-system',
    [MockContainer(
        'kube-apiserver',
        args=['--anonymous-auth=false']
    )]
)
findings = scanner._check_api_server_config([safe_apiserver])
print(f"Found {len(scanner.findings)} findings (should be 0)")

print("\n=== Test Complete ===")
