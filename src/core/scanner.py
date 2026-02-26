from src.core.k8s_client import K8sClient
from src.modules.internal.pod_scanner import PodScanner
from src.modules.internal.secret_scanner import SecretScanner, ConfigMapScanner
from src.modules.internal.rbac_scanner import RBACScanner
from src.modules.internal.network_scanner import NetworkScanner
from src.modules.internal.resource_scanner import ResourceScanner
from src.modules.internal.controlplane_scanner import ControlPlaneScanner
from src.exploits.exploit_mapper import ExploitMapper


class Scanner:
    def __init__(self, exclude_system=False):
        self.client = K8sClient()
        self.findings = []
        self.exclude_system = exclude_system
    
    def run_internal_scan(self):
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        
        self.findings = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            
            task1 = progress.add_task("[cyan]Scanning pods...", total=100)
            pods = self.client.get_all_pods()
            pod_scanner = PodScanner()
            self.findings.extend(pod_scanner.scan(pods))
            progress.update(task1, completed=100)
            
            task2 = progress.add_task("[cyan]Scanning secrets...", total=100)
            secrets = self.client.get_all_secrets()
            secret_scanner = SecretScanner()
            self.findings.extend(secret_scanner.scan(secrets))
            progress.update(task2, completed=100)
            
            task3 = progress.add_task("[cyan]Scanning configmaps...", total=100)
            configmaps = self.client.get_all_configmaps()
            cm_scanner = ConfigMapScanner()
            self.findings.extend(cm_scanner.scan(configmaps))
            progress.update(task3, completed=100)
            
            task4 = progress.add_task("[cyan]Scanning RBAC...", total=100)
            rbac_scanner = RBACScanner()
            
            # WHITEBOX FIX: Only scan bindings (roles without bindings are not a vulnerability)
            # Standalone roles/clusterroles are just definitions - only bindings create actual risk
            
            role_bindings = self.client.get_all_role_bindings()
            self.findings.extend(rbac_scanner.scan_role_bindings(role_bindings))
            progress.update(task4, advance=25)
            
            cluster_role_bindings = self.client.get_all_cluster_role_bindings()
            self.findings.extend(rbac_scanner.scan_cluster_role_bindings(cluster_role_bindings))
            progress.update(task4, advance=25)
            
            # Identify actively bound roles to scan them for dangerous permissions
            bound_roles = set()
            bound_clusterroles = set()
            
            for rb in role_bindings:
                if getattr(rb, 'role_ref', None):
                    if rb.role_ref.kind == 'Role':
                        bound_roles.add(f"{rb.metadata.namespace}/{rb.role_ref.name}")
                    elif rb.role_ref.kind == 'ClusterRole':
                        bound_clusterroles.add(rb.role_ref.name)
            
            for crb in cluster_role_bindings:
                if getattr(crb, 'role_ref', None) and crb.role_ref.kind == 'ClusterRole':
                    bound_clusterroles.add(crb.role_ref.name)
            
            roles = self.client.get_all_roles()
            active_roles = [r for r in roles if getattr(r.metadata, 'namespace', '') and f"{r.metadata.namespace}/{r.metadata.name}" in bound_roles]
            self.findings.extend(rbac_scanner.scan_roles(active_roles))
            progress.update(task4, advance=25)
            
            cluster_roles = self.client.get_all_cluster_roles()
            active_clusterroles = [cr for cr in cluster_roles if cr.metadata.name in bound_clusterroles]
            self.findings.extend(rbac_scanner.scan_cluster_roles(active_clusterroles))
            progress.update(task4, completed=100)
            
            task5 = progress.add_task("[cyan]Scanning network policies...", total=100)
            network_scanner = NetworkScanner()
            namespaces = self.client.get_all_namespaces()
            network_policies = self.client.get_all_network_policies()
            services = self.client.get_all_services()
            ingresses = self.client.get_all_ingresses()
            self.findings.extend(network_scanner.scan(namespaces, network_policies, pods, services, ingresses))
            progress.update(task5, completed=100)
            
            task6 = progress.add_task("[cyan]Scanning workloads...", total=100)
            resource_scanner = ResourceScanner()
            deployments = self.client.get_all_deployments()
            statefulsets = self.client.get_all_statefulsets()
            daemonsets = self.client.get_all_daemonsets()
            self.findings.extend(resource_scanner.scan(deployments, statefulsets, daemonsets))
            progress.update(task6, completed=100)
            
            task7 = progress.add_task("[cyan]Scanning control plane...", total=100)
            controlplane_scanner = ControlPlaneScanner()
            self.findings.extend(controlplane_scanner.scan())
            progress.update(task7, completed=100)
            
            if self.exclude_system:
                self.findings = self._filter_system_findings(self.findings)
            
            # Sort by severity (no dedup — each finding gets its own card)
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            self.findings = sorted(self.findings, key=lambda x: (severity_order.get(x.severity, 5), x.title))
            
            task8 = progress.add_task("[cyan]Enriching findings...", total=100)
            self.findings = [ExploitMapper.enrich_finding(f) for f in self.findings]
            progress.update(task8, completed=100)
            
            for i, finding in enumerate(self.findings, 1):
                finding.finding_id = i
        
        return self.findings
    


    def _filter_system_findings(self, findings):
        """Filter out system namespace findings EXCEPT Control Plane findings"""
        system_namespaces = ['kube-system', 'kube-public', 'kube-node-lease']
        
        filtered = []
        for f in findings:
            # ALWAYS include Control Plane findings (even from kube-system)
            if f.category == 'Control Plane':
                filtered.append(f)
            # Filter out other findings from system namespaces
            elif f.namespace not in system_namespaces:
                filtered.append(f)
        
        return filtered
    
    def get_summary(self):
        summary = {
            'total': len(self.findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def get_executive_summary(self):
        """Generate executive summary with key metrics"""
        summary = self.get_summary()
        exploitable = len([f for f in self.findings if f.exploitation])
        
        # Find highest risk
        critical_findings = [f for f in self.findings if f.severity == 'CRITICAL']
        highest_risk = critical_findings[0] if critical_findings else None
        
        # Calculate attack surface
        attack_surface = len([f for f in self.findings if f.severity in ['CRITICAL', 'HIGH']])
        
        return {
            'total': summary['total'],
            'exploitable': exploitable,
            'exploitable_percent': (exploitable / summary['total'] * 100) if summary['total'] > 0 else 0,
            'highest_risk': highest_risk,
            'attack_surface': attack_surface,
            'critical': summary['critical'],
            'high': summary['high'],
            'medium': summary['medium'],
            'low': summary['low']
        }
    
    def calculate_risk_score(self):
        """Calculate overall cluster security score (0-100)"""
        if not self.findings:
            return 100
        
        # Weighted scoring
        total_score = 0
        max_score = len(self.findings) * 10  # Each finding can cost up to 10 points
        
        for finding in self.findings:
            if finding.severity == 'CRITICAL':
                total_score += 10
            elif finding.severity == 'HIGH':
                total_score += 7
            elif finding.severity == 'MEDIUM':
                total_score += 4
            elif finding.severity == 'LOW':
                total_score += 2
        
        # Calculate score (100 = perfect, 0 = worst)
        score = max(0, 100 - int((total_score / max_score) * 100))
        
        return score
    
    def get_category_scores(self):
        """Calculate security scores by category"""
        categories = {
            'Container Security': [],
            'RBAC': [],
            'Secret Management': [],
            'Network Security': [],
            'Resource Management': []
        }
        
        for finding in self.findings:
            if finding.category in categories:
                categories[finding.category].append(finding)
        
        scores = {}
        for category, findings in categories.items():
            if not findings:
                scores[category] = 100
            else:
                total = 0
                for f in findings:
                    if f.severity == 'CRITICAL':
                        total += 10
                    elif f.severity == 'HIGH':
                        total += 7
                    elif f.severity == 'MEDIUM':
                        total += 4
                    elif f.severity == 'LOW':
                        total += 2
                
                max_score = len(findings) * 10
                scores[category] = max(0, 100 - int((total / max_score) * 100))
        
        return scores
    
    def get_attack_paths(self):
        """Identify high-risk attack paths"""
        paths = []
        
        # Attack Path 1: Privileged Container → Host Escape
        privileged_pods = [f for f in self.findings if 'Privileged Container' in f.title]
        if privileged_pods:
            paths.append({
                'name': 'Container Escape to Host',
                'steps': [
                    'Exploit privileged container',
                    'Use nsenter for host access',
                    'Mount host filesystem',
                    'Extract SSH keys/secrets',
                    'Lateral movement to other nodes'
                ],
                'risk': 'CRITICAL',
                'entry_points': len(privileged_pods),
                'time_to_compromise': '<5 minutes',
                'cvss': 9.8
            })
        
        # Attack Path 2: RBAC Wildcard → Full Cluster Access
        rbac_wildcards = [f for f in self.findings if 'Wildcard' in f.title and f.category == 'RBAC']
        if rbac_wildcards:
            paths.append({
                'name': 'RBAC Privilege Escalation',
                'steps': [
                    'Obtain service account token',
                    'Test wildcard permissions',
                    'List all cluster secrets',
                    'Create privileged pods',
                    'Complete cluster takeover'
                ],
                'risk': 'CRITICAL',
                'entry_points': len(rbac_wildcards),
                'time_to_compromise': '<2 minutes',
                'cvss': 10.0
            })
        
        # Attack Path 3: Secret Exposure → Cloud Compromise
        secret_findings = [f for f in self.findings if f.category == 'Secret Management' and f.severity in ['CRITICAL', 'HIGH']]
        if secret_findings:
            paths.append({
                'name': 'Secret Theft to Cloud Takeover',
                'steps': [
                    'Access pod with secrets',
                    'Extract environment variables',
                    'Obtain AWS/cloud credentials',
                    'Access cloud infrastructure',
                    'Lateral movement in cloud'
                ],
                'risk': 'HIGH',
                'entry_points': len(secret_findings),
                'time_to_compromise': '<10 minutes',
                'cvss': 8.5
            })
        
        # Attack Path 4: Network Policy Missing → Lateral Movement
        no_netpol = [f for f in self.findings if 'Network Policy' in f.title]
        if no_netpol:
            paths.append({
                'name': 'Unrestricted Lateral Movement',
                'steps': [
                    'Compromise any pod',
                    'Scan internal network',
                    'Access databases directly',
                    'Bypass application layer security',
                    'Data exfiltration'
                ],
                'risk': 'MEDIUM',
                'entry_points': len(no_netpol),
                'time_to_compromise': '<15 minutes',
                'cvss': 6.5
            })
        
        return sorted(paths, key=lambda x: -x['cvss'])
