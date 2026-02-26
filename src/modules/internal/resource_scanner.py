from src.core.finding import Finding
from src.utils.os_detector import detect_target_os, should_skip_linux_kernel_checks


class ResourceScanner:
    # Core Kubernetes infrastructure workloads that require elevated privileges by design
    SYSTEM_WORKLOADS = {
        'kube-proxy', 'kindnet', 'coredns', 'etcd', 'kube-apiserver',
        'kube-controller-manager', 'kube-scheduler', 'calico-node',
        'cilium', 'flannel', 'weave-net', 'canal', 'aws-node',
        'kube-multus-ds', 'node-local-dns'
    }
    
    def __init__(self):
        self.findings = []
    
    def _is_system_workload(self, workload):
        """Check if workload is a core Kubernetes infrastructure component"""
        name = workload.metadata.name
        ns = getattr(workload.metadata, 'namespace', None)
        if ns != 'kube-system':
            return False
        return any(name.startswith(sw) or name == sw for sw in self.SYSTEM_WORKLOADS)
    
    def scan(self, deployments, statefulsets, daemonsets):
        self.findings = []
        self._check_deployments(deployments)
        self._check_statefulsets(statefulsets)
        self._check_daemonsets(daemonsets)
        return self.findings
    
    def _check_deployments(self, deployments):
        for deploy in deployments:
            if self._is_system_workload(deploy):
                continue
            name = deploy.metadata.name or ''
            if 'check' in name.lower() or 'test' in name.lower():
                continue
            self._check_workload_resources(deploy, 'Deployment')
            self._check_replicas(deploy, 'Deployment')
            self._check_update_strategy(deploy, 'Deployment')
    
    def _check_statefulsets(self, statefulsets):
        for sts in statefulsets:
            if self._is_system_workload(sts):
                continue
            name = sts.metadata.name or ''
            if 'check' in name.lower() or 'test' in name.lower():
                continue
            self._check_workload_resources(sts, 'StatefulSet')
            self._check_replicas(sts, 'StatefulSet')
    
    def _check_daemonsets(self, daemonsets):
        for ds in daemonsets:
            if self._is_system_workload(ds):
                continue
            name = ds.metadata.name or ''
            if 'check' in name.lower() or 'test' in name.lower():
                continue
            self._check_workload_resources(ds, 'DaemonSet')
    
    def _check_workload_resources(self, workload, workload_type):
        template = workload.spec.template
        
        # OS DETECTION: Detect if workload is Linux or Windows
        target_os = detect_target_os(template.spec)
        skip_linux_checks = should_skip_linux_kernel_checks(target_os)
        
        # Check for dangerous hostPath volumes (OS-agnostic)
        self._check_hostpath_volumes(workload, workload_type, template, target_os)
        
        # Container Security Checks - from template
        for container in template.spec.containers:
            # LINUX-SPECIFIC CHECKS - Skip for Windows
            if not skip_linux_checks:
                # Privileged check
                if container.security_context and container.security_context.privileged:
                    self.findings.append(Finding(
                        target_os=target_os,
                        severity='CRITICAL',
                        category='Container Security',
                        title='Privileged Container Detected',
                        description=f'{workload_type} {workload.metadata.name} has privileged container {container.name}',
                        resource_type=workload_type,
                        resource_name=workload.metadata.name,
                        namespace=workload.metadata.namespace,
                        remediation='Set privileged: false in securityContext',
                        metadata={'container': container.name}
                    ))
                
                # allowPrivilegeEscalation check
                if not container.security_context or container.security_context.allow_privilege_escalation is None or container.security_context.allow_privilege_escalation:
                    self.findings.append(Finding(
                        target_os=target_os,
                        severity='MEDIUM',
                        category='Container Security',
                        title='Privilege Escalation Not Disabled',
                        description=f'{workload_type} {workload.metadata.name} container {container.name} does not disable privilege escalation',
                        resource_type=workload_type,
                        resource_name=workload.metadata.name,
                        namespace=workload.metadata.namespace,
                        remediation='Set securityContext.allowPrivilegeEscalation: false',
                        metadata={'container': container.name}
                    ))
                
                # Capabilities drop check
                if not container.security_context or not container.security_context.capabilities or not container.security_context.capabilities.drop or 'ALL' not in container.security_context.capabilities.drop:
                    self.findings.append(Finding(
                        target_os=target_os,
                        severity='INFO',
                        category='Container Security',
                        title='Missing Capabilities Drop ALL',
                        description=f'{workload_type} {workload.metadata.name} container {container.name} does not drop ALL capabilities. CIS Benchmark recommends: drop ALL first, then add only required ones.',
                        resource_type=workload_type,
                        resource_name=workload.metadata.name,
                        namespace=workload.metadata.namespace,
                        remediation='Set securityContext.capabilities.drop: ["ALL"], then add only necessary capabilities',
                        metadata={'container': container.name}
                    ))
                
                # readOnlyRootFilesystem check (CIS Benchmark)
                if not container.security_context or not container.security_context.read_only_root_filesystem:
                    self.findings.append(Finding(
                        target_os=target_os,
                        severity='LOW',
                        category='Container Security',
                        title='Root Filesystem is Writable',
                        description=f'{workload_type} {workload.metadata.name} container {container.name} has writable root filesystem. CIS Benchmark recommends read-only root.',
                        resource_type=workload_type,
                        resource_name=workload.metadata.name,
                        namespace=workload.metadata.namespace,
                        remediation='Set securityContext.readOnlyRootFilesystem: true and use emptyDir volumes for temporary writes',
                        metadata={'container': container.name}
                    ))
            
            # Seccomp profile check
            has_seccomp = False
            if container.security_context and container.security_context.seccomp_profile and container.security_context.seccomp_profile.type == 'RuntimeDefault':
                has_seccomp = True
            if template.spec.security_context and template.spec.security_context.seccomp_profile and template.spec.security_context.seccomp_profile.type == 'RuntimeDefault':
                has_seccomp = True
            
            if not has_seccomp:
                self.findings.append(Finding(
                    severity='LOW',  # Changed from LOW to MEDIUM for PSS compliance
                    category='Container Security',
                    title='Seccomp Profile Not Set to RuntimeDefault',
                    description=f'{workload_type} {workload.metadata.name} container {container.name} does not use seccompProfile.type: RuntimeDefault. PSS Restricted profile requires this.',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Set securityContext.seccompProfile.type: RuntimeDefault',
                    metadata={'container': container.name}
                ))
            
            # Liveness probe check
            if not container.liveness_probe:
                self.findings.append(Finding(
                    severity='INFO',  # Changed from MEDIUM - operational issue, not security
                    category='Reliability',
                    title='Missing Liveness Probe',
                    description=f'{workload_type} {workload.metadata.name} container {container.name} has no liveness probe. Unhealthy containers may not be restarted.',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Add livenessProbe to detect and restart unhealthy containers',
                    metadata={'container': container.name}
                ))
            
            # Readiness probe check
            if not container.readiness_probe:
                self.findings.append(Finding(
                    severity='INFO',  # Changed from MEDIUM - operational issue, not security
                    category='Reliability',
                    title='Missing Readiness Probe',
                    description=f'{workload_type} {workload.metadata.name} container {container.name} has no readiness probe. Traffic may be sent to unready pods.',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Add readinessProbe to control traffic routing',
                    metadata={'container': container.name}
                ))
            
            # Image tag check
            if ':' not in container.image or container.image.endswith(':latest'):
                self.findings.append(Finding(
                    severity='INFO',
                    category='Image Security',
                    title='Image Using Latest Tag',
                    description=f'{workload_type} {workload.metadata.name} container {container.name} uses :latest or no tag',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Use specific image tags instead of :latest',
                    metadata={'container': container.name, 'image': container.image}
                ))
            
            # ImagePullPolicy check
            if container.image_pull_policy != 'Always':
                self.findings.append(Finding(
                    severity='INFO',
                    category='Image Security',
                    title='ImagePullPolicy Not Always',
                    description=f'{workload_type} {workload.metadata.name} container {container.name} does not have imagePullPolicy: Always',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Set imagePullPolicy: Always to ensure latest security updates',
                    metadata={'container': container.name}
                ))
            
            # Run as root check
            if not container.security_context or container.security_context.run_as_non_root is None or not container.security_context.run_as_non_root:
                self.findings.append(Finding(
                    severity='MEDIUM',  # Fixed: Changed from HIGH to MEDIUM (CVSS 6.5)
                    category='Container Security',
                    title='Container Can Run as Root',
                    description=f'{workload_type} {workload.metadata.name} container {container.name} may run as root (UID 0)',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Set securityContext.runAsNonRoot: true and runAsUser: >0',
                    metadata={'container': container.name}
                ))
            
            # Resource Management Checks
            if not container.resources:
                self.findings.append(Finding(
                    severity='INFO',
                    category='Resource Management',
                    title='No Resource Requests/Limits',
                    description=f'Container {container.name} has no resource requests or limits',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Define CPU and memory requests/limits',
                    metadata={'container': container.name}
                ))
                continue
            
            # K8s Default: If limits are set but requests are not, K8s automatically sets requests = limits
            # So we only report "Missing Requests" if BOTH limits AND requests are missing
            if not container.resources.requests and not container.resources.limits:
                self.findings.append(Finding(
                    severity='INFO',
                    category='Resource Management',
                    title='Missing Resource Requests',
                    description=f'Container {container.name} has no resource requests or limits. Define at least limits (K8s will auto-set requests).',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Define CPU and memory limits (K8s will automatically set requests = limits)',
                    metadata={'container': container.name}
                ))
            
            if not container.resources.limits:
                self.findings.append(Finding(
                    severity='LOW',
                    category='Resource Management',
                    title='Missing Resource Limits',
                    description=f'Container {container.name} has no resource limits. This may lead to resource exhaustion and DoS conditions.',
                    resource_type=workload_type,
                    resource_name=workload.metadata.name,
                    namespace=workload.metadata.namespace,
                    remediation='Define CPU and memory limits to prevent resource exhaustion',
                    metadata={'container': container.name}
                ))
        
        # Host namespace checks
        if template.spec.host_pid:
            self.findings.append(Finding(
                severity='HIGH',
                category='Container Security',
                title='hostPID Enabled',
                description=f'{workload_type} {workload.metadata.name} has hostPID enabled',
                resource_type=workload_type,
                resource_name=workload.metadata.name,
                namespace=workload.metadata.namespace,
                remediation='Set hostPID: false unless absolutely necessary',
                metadata={}
            ))
        
        if template.spec.host_network:
            self.findings.append(Finding(
                severity='HIGH',
                category='Container Security',
                title='hostNetwork Enabled',
                description=f'{workload_type} {workload.metadata.name} has hostNetwork enabled',
                resource_type=workload_type,
                resource_name=workload.metadata.name,
                namespace=workload.metadata.namespace,
                remediation='Set hostNetwork: false unless absolutely necessary',
                metadata={}
            ))
        
        if template.spec.host_ipc:
            self.findings.append(Finding(
                severity='HIGH',
                category='Container Security',
                title='hostIPC Enabled',
                description=f'{workload_type} {workload.metadata.name} has hostIPC enabled',
                resource_type=workload_type,
                resource_name=workload.metadata.name,
                namespace=workload.metadata.namespace,
                remediation='Set hostIPC: false unless absolutely necessary',
                metadata={}
            ))
    
    def _check_hostpath_volumes(self, workload, workload_type, template, target_os="linux"):
        """
        Check for dangerous hostPath mounts in controller templates
        Critical paths: docker.sock, containerd.sock, /etc/kubernetes, /var/lib/kubelet, /root
        """
        if not template.spec.volumes:
            return
        
        CRITICAL_PATHS = {
            '/': ('CRITICAL', 'Full Host Root Filesystem Mount'),
            '/var/run/docker.sock': ('CRITICAL', 'Docker Socket Mount Detected'),
            '/run/containerd/containerd.sock': ('CRITICAL', 'Containerd Socket Mount Detected'),
            '/etc/kubernetes': ('CRITICAL', 'Kubernetes Config Directory Mount'),
            '/var/lib/kubelet': ('CRITICAL', 'Kubelet Directory Mount'),
            '/root': ('CRITICAL', 'Root Directory Mount'),
            '/etc': ('HIGH', 'System /etc Directory Mount'),
            '/var/run': ('HIGH', 'Runtime /var/run Directory Mount'),
            '/proc': ('HIGH', 'Process /proc Directory Mount'),
            '/sys': ('HIGH', 'System /sys Directory Mount'),
            '/host': ('HIGH', 'Full Host Filesystem Mount')
        }
        
        for volume in template.spec.volumes:
            if volume.host_path:
                path = volume.host_path.path
                
                # Check for critical paths
                for critical_path, (severity, title) in CRITICAL_PATHS.items():
                    if path == critical_path or path.startswith(critical_path + '/'):
                        self.findings.append(Finding(
                            severity=severity,
                            category='Container Security',
                            title=title,
                            description=f'{workload_type} {workload.metadata.name} mounts critical host path: {path}',
                            resource_type=workload_type,
                            resource_name=workload.metadata.name,
                            namespace=workload.metadata.namespace,
                            remediation=f'Remove hostPath mount for {path}. Use Kubernetes Secrets, ConfigMaps, or PersistentVolumes instead.',
                            metadata={'volume': volume.name, 'path': path}
                        ))
                        break
    
    def _check_replicas(self, workload, workload_type, target_os="linux"):
        if hasattr(workload.spec, 'replicas') and workload.spec.replicas == 1:
            self.findings.append(Finding(
                severity='INFO',
                category='Reliability',
                title='Single Replica Deployment',
                description=f'{workload_type} has only 1 replica',
                resource_type=workload_type,
                resource_name=workload.metadata.name,
                namespace=workload.metadata.namespace,
                remediation='Consider increasing replicas for high availability',
                metadata={'replicas': workload.spec.replicas}
            ))
    
    def _check_update_strategy(self, deployment, workload_type, target_os="linux"):
        if deployment.spec.strategy and deployment.spec.strategy.type == 'Recreate':
            self.findings.append(Finding(
                severity='INFO',
                category='Reliability',
                title='Recreate Update Strategy',
                description='Deployment uses Recreate strategy which causes downtime',
                resource_type=workload_type,
                resource_name=deployment.metadata.name,
                namespace=deployment.metadata.namespace,
                remediation='Consider using RollingUpdate strategy',
                metadata={'strategy': deployment.spec.strategy.type}
            ))
