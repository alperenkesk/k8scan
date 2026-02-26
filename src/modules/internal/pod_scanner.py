from src.core.finding import Finding
from src.utils.os_detector import detect_target_os, should_skip_linux_kernel_checks, get_os_specific_note
import base64
import re


class PodScanner:
    SYSTEM_NAMESPACES = ['kube-system', 'kube-public', 'kube-node-lease', 'default']
    MONITORING_PATTERNS = ['prometheus', 'grafana', 'datadog', 'node-exporter', 'metrics']
    SENSITIVE_PATHS = ['/var/run/docker.sock', '/etc', '/root', '/var/run', '/proc', '/sys', '/host']
    DANGEROUS_CAPABILITIES = ['SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'NET_ADMIN', 'NET_RAW']
    
    def __init__(self):
        self.findings = []
    
    def scan(self, pods):
        self.findings = []
        for pod in pods:
            # CRITICAL FIX: Skip pods managed by controllers entirely
            # These are scanned via Deployment/StatefulSet/DaemonSet templates by ResourceScanner
            # This prevents double counting of the same issue
            if self._is_managed_pod(pod):
                continue  # SKIP this pod completely
            
            # Skip scanner-generated test/check pods
            pod_name = pod.metadata.name or ''
            if 'check' in pod_name.lower() or 'test' in pod_name.lower():
                continue
            
            # OS DETECTION: Detect if pod is Linux or Windows
            target_os = detect_target_os(pod.spec)
            skip_linux_checks = should_skip_linux_kernel_checks(target_os)
            
            # Only scan standalone pods (no ownerReferences)
            # Linux-specific checks are skipped for Windows pods
            if not skip_linux_checks:
                self._check_privileged_containers(pod, target_os)
                self._check_capabilities(pod, target_os)
                self._check_privilege_escalation(pod, target_os)
                self._check_capabilities_drop(pod, target_os)
                self._check_seccomp_profile(pod, target_os)
            
            # OS-agnostic checks (apply to both Linux and Windows)
            self._check_host_namespaces(pod, target_os)
            self._check_host_path_mounts(pod, target_os)
            self._check_security_context(pod, target_os)
            self._check_secrets_in_env(pod, target_os)
            self._check_service_account_token(pod, target_os)
            self._check_image_pull_policy(pod, target_os)
            self._check_image_tags(pod, target_os)
            self._check_resource_limits(pod, target_os)
        
        return self.findings
    
    def _is_managed_pod(self, pod):
        """
        Check if pod is managed by a controller (Deployment, StatefulSet, etc.)
        If managed, we SKIP it entirely to avoid double counting
        """
        if not pod.metadata.owner_references:
            return False  # Independent pod, should be scanned
        
        # If ownerReferences exists and is not empty, pod is managed
        # These pods are scanned via their controller templates
        return len(pod.metadata.owner_references) > 0
    
    def _is_monitoring_pod(self, pod):
        pod_name = pod.metadata.name.lower()
        return any(pattern in pod_name for pattern in self.MONITORING_PATTERNS)
    
    def _check_privileged_containers(self, pod, target_os="linux"):
        for container in pod.spec.containers:
            if container.security_context and container.security_context.privileged:
                if self._is_monitoring_pod(pod):
                    continue
                
                self.findings.append(Finding(target_os=target_os, 
                    severity='CRITICAL',
                    category='Container Security',
                    title='Privileged Container Detected',
                    description=f'Container {container.name} is running in privileged mode',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Set privileged: false in securityContext',
                    metadata={'container': container.name}
                ))
    
    def _check_host_namespaces(self, pod, target_os="linux"):
        if pod.spec.host_pid:
            self.findings.append(Finding(target_os=target_os, 
                severity='HIGH',
                category='Container Security',
                title='hostPID Enabled',
                description='Pod has access to host process namespace',
                resource_type='Pod',
                resource_name=pod.metadata.name,
                namespace=pod.metadata.namespace,
                remediation='Set hostPID: false',
                metadata={}
            ))
        
        if pod.spec.host_ipc:
            self.findings.append(Finding(target_os=target_os, 
                severity='HIGH',
                category='Container Security',
                title='hostIPC Enabled',
                description='Pod has access to host IPC namespace',
                resource_type='Pod',
                resource_name=pod.metadata.name,
                namespace=pod.metadata.namespace,
                remediation='Set hostIPC: false',
                metadata={}
            ))
        
        if pod.spec.host_network:
            if self._is_monitoring_pod(pod):
                return
            
            self.findings.append(Finding(target_os=target_os, 
                severity='HIGH',
                category='Container Security',
                title='hostNetwork Enabled',
                description='Pod has access to host network namespace',
                resource_type='Pod',
                resource_name=pod.metadata.name,
                namespace=pod.metadata.namespace,
                remediation='Set hostNetwork: false',
                metadata={}
            ))
    
    def _check_host_path_mounts(self, pod, target_os="linux"):
        """
        Advanced HostPath Analysis - Directory-based risk assessment
        Critical paths: docker.sock, containerd.sock, /etc/kubernetes, /var/lib/kubelet, /root
        """
        if not pod.spec.volumes:
            return
        
        # Define critical paths with specific risks
        CRITICAL_PATHS = {
            '/var/run/docker.sock': {
                'severity': 'CRITICAL',
                'risk': 'Full Docker daemon access - Container escape to host',
                'title': 'Docker Socket Mount Detected'
            },
            '/run/containerd/containerd.sock': {
                'severity': 'CRITICAL',
                'risk': 'Full Containerd access - Container escape to host',
                'title': 'Containerd Socket Mount Detected'
            },
            '/etc/kubernetes': {
                'severity': 'CRITICAL',
                'risk': 'Access to K8s certificates and configs - Cluster takeover',
                'title': 'Kubernetes Config Directory Mount'
            },
            '/var/lib/kubelet': {
                'severity': 'CRITICAL',
                'risk': 'Access to kubelet data and kubeconfig - Node compromise',
                'title': 'Kubelet Directory Mount'
            },
            '/root': {
                'severity': 'CRITICAL',
                'risk': 'Access to root home directory - SSH keys and secrets',
                'title': 'Root Directory Mount'
            },
            '/etc': {
                'severity': 'HIGH',
                'risk': 'Access to system configuration - Password hashes in /etc/shadow',
                'title': 'System /etc Directory Mount'
            },
            '/var/run': {
                'severity': 'HIGH',
                'risk': 'Access to runtime data - Potential socket access',
                'title': 'Runtime /var/run Directory Mount'
            },
            '/proc': {
                'severity': 'HIGH',
                'risk': 'Access to process information - Secret extraction from memory',
                'title': 'Process /proc Directory Mount'
            },
            '/sys': {
                'severity': 'HIGH',
                'risk': 'Access to system kernel interfaces',
                'title': 'System /sys Directory Mount'
            },
            '/host': {
                'severity': 'HIGH',
                'risk': 'Entire host filesystem accessible',
                'title': 'Full Host Filesystem Mount'
            }
        }
        
        for volume in pod.spec.volumes:
            if volume.host_path:
                path = volume.host_path.path
                
                # Check for exact matches or if path starts with critical path
                detected_risk = None
                for critical_path, risk_info in CRITICAL_PATHS.items():
                    if path == critical_path or path.startswith(critical_path + '/'):
                        detected_risk = risk_info
                        break
                
                if detected_risk:
                    self.findings.append(Finding(target_os=target_os, 
                        severity=detected_risk['severity'],
                        category='Container Security',
                        title=detected_risk['title'],
                        description=f'Volume "{volume.name}" mounts critical host path: {path}. Risk: {detected_risk["risk"]}',
                        resource_type='Pod',
                        resource_name=pod.metadata.name,
                        namespace=pod.metadata.namespace,
                        remediation=f'Remove hostPath mount for {path}. Use Kubernetes Secrets, ConfigMaps, or PersistentVolumes instead.',
                        metadata={
                            'volume': volume.name, 
                            'path': path,
                            'risk_level': detected_risk['severity'],
                            'risk_description': detected_risk['risk']
                        }
                    ))
                elif any(sensitive in path for sensitive in self.SENSITIVE_PATHS):
                    # Generic sensitive path
                    self.findings.append(Finding(target_os=target_os, 
                        severity='HIGH',
                        category='Container Security',
                        title='Sensitive HostPath Mount',
                        description=f'Volume {volume.name} mounts potentially sensitive path: {path}',
                        resource_type='Pod',
                        resource_name=pod.metadata.name,
                        namespace=pod.metadata.namespace,
                        remediation='Avoid mounting host paths. Use Kubernetes-native storage.',
                        metadata={'volume': volume.name, 'path': path}
                    ))
    
    def _check_capabilities(self, pod, target_os="linux"):
        """
        Advanced Capabilities Analysis - CIS Benchmark compliant
        Checks for dangerous added capabilities and missing DROP ALL
        """
        for container in pod.spec.containers:
            # Check if capabilities are defined at all
            if not container.security_context:
                # Will be caught by _check_security_context
                continue
            
            caps = container.security_context.capabilities if container.security_context.capabilities else None
            
            # Critical/High: Check for dangerous added capabilities
            if caps and caps.add:
                for cap in caps.add:
                    # Determine severity based on capability
                    severity = 'CRITICAL' if cap in ['SYS_ADMIN', 'BPF'] else 'HIGH'
                    
                    if cap in self.DANGEROUS_CAPABILITIES:
                        self.findings.append(Finding(target_os=target_os, 
                            severity=severity,
                            category='Container Security',
                            title='Dangerous Capability Granted',
                            description=f'Container {container.name} has been granted dangerous Linux capability "{cap}" which can lead to container escape, host compromise, or privilege escalation.',
                            resource_type='Pod',
                            resource_name=pod.metadata.name,
                            namespace=pod.metadata.namespace,
                            remediation=f'Remove "{cap}" from securityContext.capabilities.add. Only add capabilities that are absolutely necessary. Follow principle of least privilege.',
                            metadata={'container': container.name, 'capability': cap}
                        ))
            
            # Note: capabilities.drop: ["ALL"] check is now in _check_capabilities_drop()
            # to avoid duplicate findings
    
    def _check_security_context(self, pod, target_os="linux"):
        for container in pod.spec.containers:
            if not container.security_context:
                self.findings.append(Finding(target_os=target_os, 
                    severity='LOW',
                    category='Container Security',
                    title='Missing Security Context',
                    description=f'Container {container.name} has no security context defined',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Define securityContext with runAsNonRoot and readOnlyRootFilesystem',
                    metadata={'container': container.name}
                ))
                continue
            
            sc = container.security_context
            
            if not sc.run_as_non_root:
                self.findings.append(Finding(target_os=target_os, 
                    severity='MEDIUM',
                    category='Container Security',
                    title='Container Can Run as Root',
                    description=f'Container {container.name} is not restricted from running as root',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Set runAsNonRoot: true',
                    metadata={'container': container.name}
                ))
            
            if not sc.read_only_root_filesystem:
                self.findings.append(Finding(target_os=target_os, 
                    severity='LOW',
                    category='Container Security',
                    title='Writable Root Filesystem',
                    description=f'Container {container.name} has writable root filesystem',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Set readOnlyRootFilesystem: true',
                    metadata={'container': container.name}
                ))
    
    def _check_resource_limits(self, pod, target_os="linux"):
        """
        Resource limits are now checked by ResourceScanner for Deployments/StatefulSets/DaemonSets
        This function only checks standalone pods (not managed by controllers)
        """
        # Only check standalone pods for resource limits
        for container in pod.spec.containers:
            if not container.resources or not container.resources.limits:
                self.findings.append(Finding(target_os=target_os, 
                    severity='LOW',
                    category='Resource Management',
                    title='Missing Resource Limits',
                    description=f'Standalone pod {pod.metadata.name} container {container.name} has no resource limits',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Define CPU and memory limits to prevent resource exhaustion',
                    metadata={'container': container.name}
                ))
    
    def _check_privilege_escalation(self, pod, target_os="linux"):
        """Check for allowPrivilegeEscalation setting"""
        for container in pod.spec.containers:
            # If securityContext is missing or allowPrivilegeEscalation is not set to false
            if not container.security_context:
                self.findings.append(Finding(target_os=target_os, 
                    severity='MEDIUM',
                    category='Container Security',
                    title='Privilege Escalation Not Disabled',
                    description=f'Container {container.name} does not explicitly disable privilege escalation. Default allows escalation.',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Set securityContext.allowPrivilegeEscalation: false',
                    metadata={'container': container.name}
                ))
            elif container.security_context.allow_privilege_escalation is None or container.security_context.allow_privilege_escalation:
                self.findings.append(Finding(target_os=target_os, 
                    severity='MEDIUM',
                    category='Container Security',
                    title='Privilege Escalation Allowed',
                    description=f'Container {container.name} has allowPrivilegeEscalation set to true or not set (defaults to true)',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Set securityContext.allowPrivilegeEscalation: false to prevent privilege escalation',
                    metadata={'container': container.name}
                ))
    
    def _check_capabilities_drop(self, pod, target_os="linux"):
        """
        Check if ALL capabilities are dropped - CIS Benchmark recommendation
        Single, consistent finding title
        """
        for container in pod.spec.containers:
            drop_all_missing = True
            
            # Check if capabilities are defined
            if container.security_context and container.security_context.capabilities:
                if container.security_context.capabilities.drop:
                    if 'ALL' in container.security_context.capabilities.drop:
                        drop_all_missing = False
            
            # Single finding with consistent title
            if drop_all_missing:
                self.findings.append(Finding(target_os=target_os, 
                    severity='INFO',
                    category='Container Security',
                    title='Missing Capabilities Drop ALL',
                    description=f'Container {container.name} does not drop all capabilities. CIS Benchmark recommends: drop ALL capabilities first, then add only required ones.',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Add capabilities: {{ drop: ["ALL"] }} to securityContext, then add only necessary capabilities with capabilities.add',
                    metadata={'container': container.name, 'cis_benchmark': True}
                ))
    
    def _check_seccomp_profile(self, pod, target_os="linux"):
        """
        Check for Seccomp profile - Pod Security Standards (PSS) requirement
        RuntimeDefault is required for Restricted profile
        """
        for container in pod.spec.containers:
            has_seccomp = False
            
            # Check container-level seccomp
            if container.security_context and container.security_context.seccomp_profile:
                if container.security_context.seccomp_profile.type == 'RuntimeDefault':
                    has_seccomp = True
            
            # Check pod-level seccomp
            if pod.spec.security_context and pod.spec.security_context.seccomp_profile:
                if pod.spec.security_context.seccomp_profile.type == 'RuntimeDefault':
                    has_seccomp = True
            
            if not has_seccomp:
                self.findings.append(Finding(target_os=target_os, 
                    severity='LOW',
                    category='Container Security',
                    title='Seccomp Profile Not Set to RuntimeDefault',
                    description=f'Container {container.name} does not use seccompProfile.type: RuntimeDefault. Pod Security Standards (Restricted) requires Seccomp to restrict system calls and reduce attack surface.',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Add "securityContext: {{ seccompProfile: {{ type: RuntimeDefault }} }}" at pod or container level.',
                    metadata={'container': container.name, 'pss_violation': True}
                ))
    
    def _check_image_tags(self, pod, target_os="linux"):
        """Check for latest tag or missing tag in images"""
        for container in pod.spec.containers:
            image = container.image
            
            # Check if using :latest or no tag
            if ':' not in image or image.endswith(':latest'):
                self.findings.append(Finding(target_os=target_os, 
                    severity='INFO',
                    category='Image Security',
                    title='Image Using Latest Tag',
                    description=f'Container {container.name} uses :latest tag or no tag. This is unpredictable and insecure.',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Use specific image tags (e.g., nginx:1.21.0) instead of :latest',
                    metadata={'container': container.name, 'image': image}
                ))
    
    def _check_secrets_in_env(self, pod, target_os="linux"):
        secret_patterns = [
            r'password', r'passwd', r'pwd', r'secret', r'token', r'api[_-]?key',
            r'access[_-]?key', r'private[_-]?key', r'credentials', r'auth', r'jwt'
        ]
        
        # Patterns for actual secret values (not just names)
        value_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
            'github_token': r'gh[ps]_[A-Za-z0-9]{36}',
            'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,32}',
            'private_key': r'-----BEGIN.*PRIVATE KEY-----',
            'jwt_token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'generic_api_key': r'[A-Za-z0-9]{32,}',
        }
        
        for container in pod.spec.containers:
            if not container.env:
                continue
            
            for env in container.env:
                env_name = env.name.lower()
                env_value = env.value or ''
                
                # Check if env name suggests it's a secret
                name_is_suspicious = any(re.search(pattern, env_name) for pattern in secret_patterns)
                
                # Check if value matches known secret patterns
                detected_type = None
                for secret_type, pattern in value_patterns.items():
                    if re.search(pattern, env_value):
                        detected_type = secret_type
                        break
                
                if env.value and (name_is_suspicious or detected_type):
                    severity = 'CRITICAL' if detected_type in ['aws_access_key', 'private_key', 'github_token'] else 'HIGH'
                    
                    description = f'Container {container.name} has plaintext secret in env var: {env.name}'
                    if detected_type:
                        description += f' (detected as {detected_type.replace("_", " ")})'
                    
                    self.findings.append(Finding(target_os=target_os, 
                        severity=severity,
                        category='Secret Management',
                        title='Plaintext Secret in Environment Variable',
                        description=description,
                        resource_type='Pod',
                        resource_name=pod.metadata.name,
                        namespace=pod.metadata.namespace,
                        remediation='Use Kubernetes Secrets with secretKeyRef instead of plain values. Never commit secrets to code or configs.',
                        metadata={
                            'container': container.name, 
                            'env_var': env.name,
                            'secret_type': detected_type or 'generic',
                            'value_preview': env_value[:20] + '...' if len(env_value) > 20 else 'REDACTED'
                        }
                    ))
    
    def _check_service_account_token(self, pod, target_os="linux"):
        if pod.spec.automount_service_account_token is None or pod.spec.automount_service_account_token:
            if pod.spec.service_account_name != 'default':
                self.findings.append(Finding(target_os=target_os, 
                    severity='MEDIUM',
                    category='RBAC',
                    title='Service Account Token Auto-mounted',
                    description='Pod automatically mounts service account token',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Set automountServiceAccountToken: false if not needed',
                    metadata={'service_account': pod.spec.service_account_name}
                ))
    
    def _check_image_pull_policy(self, pod, target_os="linux"):
        for container in pod.spec.containers:
            if container.image_pull_policy == 'Always':
                continue
            
            if ':latest' in container.image or ':' not in container.image:
                self.findings.append(Finding(target_os=target_os, 
                    severity='LOW',
                    category='Container Security',
                    title='Latest Image Tag Used',
                    description=f'Container {container.name} uses latest tag',
                    resource_type='Pod',
                    resource_name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    remediation='Use specific image tags and imagePullPolicy: Always',
                    metadata={'container': container.name, 'image': container.image}
                ))
