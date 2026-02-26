"""
Control Plane Security Scanner - Production Ready
Detects API Server, Dashboard, Kubelet, etcd, and Tiller vulnerabilities
Uses in-cluster ephemeral pods for network-level checks (Kubelet, etcd)
"""

import subprocess
import json
import traceback
from src.core.finding import Finding


class ControlPlaneScanner:
    def __init__(self):
        self.findings = []
    
    def scan(self, services=None, pods=None, config_maps=None):
        """Scan control plane security"""
        self.findings = []
        
        try:
            self._check_api_server_anonymous_auth()
        except Exception:
            pass
            
        try:
            self._check_exposed_dashboard()
        except Exception:
            pass
            
        try:
            self._check_kubelet_anonymous_access()
        except Exception:
            pass
            
        try:
            self._check_exposed_etcd()
        except Exception:
            pass
            
        try:
            self._check_tiller_exposed()
        except Exception:
            pass
            
        return self.findings
    
    def _run_incluster_curl(self, url, test_name="incluster-test"):
        """
        Run a curl command from INSIDE the cluster using an ephemeral pod.
        This bypasses host-level network isolation to reach Node IPs.
        Returns (http_status_code, response_body) or (None, None) on failure.
        """
        try:
            result = subprocess.run(
                [
                    'kubectl', 'run', test_name,
                    '--rm', '-i', '--restart=Never',
                    '--image=curlimages/curl',
                    '--request-timeout=30s',
                    '--', 'curl', '-k', '-s', '-o', '/dev/null',
                    '-w', '%{http_code}', '-m', '5', url
                ],
                capture_output=True,
                text=True,
                timeout=45,
                check=False
            )
            
            output = result.stdout.strip()
            # kubectl run output may contain pod lifecycle messages, extract HTTP code
            lines = output.split('\n')
            http_code = None
            for line in reversed(lines):
                line = line.strip()
                if line.isdigit() and len(line) == 3:
                    http_code = line
                    break
            
            if http_code:
                return http_code, output
            else:
                return None, output
                
        except subprocess.TimeoutExpired:
            subprocess.run(['kubectl', 'delete', 'pod', test_name, '--ignore-not-found', '--force', '--grace-period=0'],
                          capture_output=True, text=True, timeout=10, check=False)
            return None, None
        except Exception:
            subprocess.run(['kubectl', 'delete', 'pod', test_name, '--ignore-not-found', '--force', '--grace-period=0'],
                          capture_output=True, text=True, timeout=10, check=False)
            return None, None
    
    def _get_node_ips(self):
        """Get internal IP addresses of all nodes"""
        result = subprocess.run(
            ['kubectl', 'get', 'nodes', '-o',
             'jsonpath={.items[*].status.addresses[?(@.type=="InternalIP")].address}'],
            capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode != 0:
            return []
        
        ips = [ip.strip() for ip in result.stdout.strip().split() if ip.strip()]
        return ips
    
    def _check_api_server_anonymous_auth(self):
        """
        Check API Server for anonymous auth using LABEL selector.
        Works regardless of pod naming convention.
        """
        result = subprocess.run(
            ['kubectl', 'get', 'pods', '-n', 'kube-system',
             '-l', 'component=kube-apiserver',
             '-o', 'json'],
            capture_output=True, text=True, timeout=10, check=False
        )
        
        if result.returncode != 0 or not result.stdout.strip():
            result = subprocess.run(
                ['kubectl', 'get', 'pods', '-n', 'kube-system', '-o', 'json'],
                capture_output=True, text=True, timeout=10, check=False
            )
        
        if result.returncode != 0:
            return
        
        try:
            pods_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return
        
        items = pods_data.get('items', [])
        if not items:
            return
        
        for pod in items:
            try:
                pod_name = pod.get('metadata', {}).get('name', '')
                labels = pod.get('metadata', {}).get('labels', {})
                
                is_apiserver = (labels.get('component') == 'kube-apiserver' or
                               'kube-apiserver' in pod_name or
                               'apiserver' in pod_name)
                
                if not is_apiserver:
                    continue
                
                containers = pod.get('spec', {}).get('containers', [])
                for container in containers:
                    cmds = container.get('command', []) or []
                    args = container.get('args', []) or []
                    full_cmd = " ".join(cmds + args)
                    
                    if '--anonymous-auth=true' in full_cmd:
                        self.findings.append(Finding(
                            severity='CRITICAL',
                            category='Control Plane',
                            title='API Server Anonymous Access Enabled',
                            description=f'API server pod "{pod_name}" allows anonymous authentication (--anonymous-auth=true). Unauthenticated users can access the Kubernetes API.',
                            resource_type='Pod',
                            resource_name=pod_name,
                            namespace='kube-system',
                            remediation='Set --anonymous-auth=false in kube-apiserver startup flags',
                            metadata={'anonymous_auth': 'true', 'pod': pod_name},
                            target_os='linux'
                        ))
                        break
            except Exception:
                continue
    
    def _check_exposed_dashboard(self):
        """Check if Dashboard is exposed"""
        result = subprocess.run(
            ['kubectl', 'get', 'svc', '-A', '-o', 'json'],
            capture_output=True, text=True, timeout=10, check=False
        )
        
        if result.returncode != 0:
            return
        
        try:
            svc_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return
        
        for svc in svc_data.get('items', []):
            try:
                svc_name = svc.get('metadata', {}).get('name', '')
                svc_namespace = svc.get('metadata', {}).get('namespace', 'default')
                
                if 'dashboard' not in svc_name.lower():
                    continue
                
                svc_type = svc.get('spec', {}).get('type', '')
                if svc_type in ['NodePort', 'LoadBalancer']:
                    ports = []
                    for port in svc.get('spec', {}).get('ports', []):
                        if svc_type == 'NodePort' and port.get('nodePort'):
                            ports.append(port.get('nodePort'))
                        elif port.get('port'):
                            ports.append(port.get('port'))
                    
                    self.findings.append(Finding(
                        severity='HIGH',
                        category='Control Plane',
                        title='Kubernetes Dashboard Exposed Externally',
                        description=f'Dashboard service "{svc_name}" in namespace "{svc_namespace}" is exposed as {svc_type}.',
                        resource_type='Service',
                        resource_name=svc_name,
                        namespace=svc_namespace,
                        remediation=f'Change to ClusterIP: kubectl patch svc {svc_name} -n {svc_namespace} -p \'{{"spec":{{"type":"ClusterIP"}}}}\'',
                        metadata={'service_type': svc_type, 'ports': ports},
                        target_os='linux'
                    ))
            except Exception:
                continue
    
    def _check_kubelet_anonymous_access(self):
        """
        Check Kubelet for anonymous access using IN-CLUSTER ephemeral curl pod.
        This reaches Node IPs from inside the cluster network.
        """
        node_ips = self._get_node_ips()
        if not node_ips:
            return
        
        for i, ip in enumerate(node_ips):
            pod_name = f"kubelet-check-{i}"
            url = f"https://{ip}:10250/pods"
            
            http_code, _ = self._run_incluster_curl(url, test_name=pod_name)
            
            if http_code == '200':
                self.findings.append(Finding(
                    severity='CRITICAL',
                    category='Control Plane',
                    title='Kubelet Anonymous Access Enabled',
                    description=f'Kubelet on node {ip} port 10250 allows anonymous access (HTTP 200). Attackers can execute commands in any pod on this node without authentication.',
                    resource_type='Node',
                    resource_name=ip,
                    namespace='kube-system',
                    remediation='Set --anonymous-auth=false in kubelet configuration (/var/lib/kubelet/config.yaml) and restart kubelet.',
                    metadata={'node_ip': ip, 'http_code': http_code, 'port': '10250'},
                    target_os='linux'
                ))
    
    def _check_exposed_etcd(self):
        """
        Check if etcd is accessible without authentication using IN-CLUSTER curl pod.
        Tests port 2379 on all node IPs from inside the cluster.
        """
        node_ips = self._get_node_ips()
        if not node_ips:
            return
        
        for i, ip in enumerate(node_ips):
            pod_name = f"etcd-check-{i}"
            url = f"https://{ip}:2379/version"
            
            http_code, body = self._run_incluster_curl(url, test_name=pod_name)
            
            if http_code == '200':
                self.findings.append(Finding(
                    severity='CRITICAL',
                    category='Control Plane',
                    title='Exposed etcd Without Authentication',
                    description=f'etcd on node {ip} port 2379 is accessible without client certificate authentication (HTTP 200). etcd stores ALL Kubernetes state including every secret, token, and cluster config.',
                    resource_type='Node',
                    resource_name=ip,
                    namespace='kube-system',
                    remediation='Enable client certificate authentication: --client-cert-auth=true. Firewall port 2379 to only kube-apiserver.',
                    metadata={'node_ip': ip, 'http_code': http_code, 'port': '2379'},
                    target_os='linux'
                ))
    
    def _check_tiller_exposed(self):
        """Check for Tiller (Helm v2) deployment - RCE risk"""
        result = subprocess.run(
            ['kubectl', 'get', 'pods', '-A', '-o', 'json'],
            capture_output=True, text=True, timeout=10, check=False
        )
        
        if result.returncode != 0:
            return
        
        try:
            pods_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return
        
        tiller_found = False
        for pod in pods_data.get('items', []):
            try:
                pod_name = pod.get('metadata', {}).get('name', '')
                pod_namespace = pod.get('metadata', {}).get('namespace', 'kube-system')
                
                if 'tiller' in pod_name.lower():
                    self.findings.append(Finding(
                        severity='HIGH',
                        category='Control Plane',
                        title='Tiller (Helm v2) Deployed',
                        description=f'Tiller pod "{pod_name}" detected in namespace "{pod_namespace}". Helm v2 Tiller has cluster-admin privileges and accepts unauthenticated gRPC on port 44134, enabling RCE.',
                        resource_type='Pod',
                        resource_name=pod_name,
                        namespace=pod_namespace,
                        remediation='Upgrade to Helm v3 (tillerless). Remove Tiller: kubectl delete deployment tiller-deploy -n kube-system',
                        metadata={'tiller_pod': pod_name, 'port': '44134'},
                        target_os='linux'
                    ))
                    tiller_found = True
                    break
            except:
                continue
        
        if tiller_found:
            return
        
        # Also check for tiller service on port 44134
        svc_result = subprocess.run(
            ['kubectl', 'get', 'svc', '-A', '-o', 'json'],
            capture_output=True, text=True, timeout=10, check=False
        )
        
        if svc_result.returncode != 0:
            return
        
        try:
            svc_data = json.loads(svc_result.stdout)
        except json.JSONDecodeError:
            return
        
        for svc in svc_data.get('items', []):
            try:
                svc_name = svc.get('metadata', {}).get('name', '')
                svc_namespace = svc.get('metadata', {}).get('namespace', 'kube-system')
                
                ports = svc.get('spec', {}).get('ports', [])
                has_tiller_port = any(p.get('port') == 44134 for p in ports)
                
                if 'tiller' in svc_name.lower() or has_tiller_port:
                    self.findings.append(Finding(
                        severity='HIGH',
                        category='Control Plane',
                        title='Tiller (Helm v2) Service Exposed',
                        description=f'Tiller service "{svc_name}" in namespace "{svc_namespace}" exposes port 44134 for unauthenticated gRPC.',
                        resource_type='Service',
                        resource_name=svc_name,
                        namespace=svc_namespace,
                        remediation='Upgrade to Helm v3 (tillerless). Remove Tiller service and deployment.',
                        metadata={'service': svc_name, 'port': '44134'},
                        target_os='linux'
                    ))
            except:
                continue
