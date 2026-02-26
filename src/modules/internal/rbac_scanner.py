from src.core.finding import Finding


class RBACScanner:
    DANGEROUS_VERBS = ['*', 'create', 'update', 'patch', 'delete', 'deletecollection', 'escalate', 'bind', 'impersonate']
    DANGEROUS_RESOURCES = ['secrets', 'pods', 'pods/exec', 'pods/attach', 'pods/portforward', 
                           'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings',
                           'serviceaccounts', 'persistentvolumes', 'nodes']
    
    def __init__(self):
        self.findings = []
    
    def scan_roles(self, roles):
        self.findings = []
        for role in roles:
            self._check_role_permissions(role, 'Role')
        return self.findings
    
    # Built-in Kubernetes ClusterRoles that should not be flagged
    BUILTIN_CLUSTERROLES = {'cluster-admin', 'admin', 'edit', 'view', 'local-path-provisioner-role'}
    
    def scan_cluster_roles(self, cluster_roles):
        findings = []
        for role in cluster_roles:
            if role.metadata.name.startswith('system:'):
                continue
            # Skip built-in K8s ClusterRoles — they are expected and not vulnerabilities
            if role.metadata.name in self.BUILTIN_CLUSTERROLES:
                continue
            findings.extend(self._check_role_permissions(role, 'ClusterRole'))
        return findings
    
    def scan_role_bindings(self, role_bindings):
        findings = []
        for rb in role_bindings:
            # Skip kubeadm and system bindings — they are standard K8s infrastructure
            if rb.metadata.name.startswith('system:') or rb.metadata.name.startswith('kubeadm:'):
                continue
            findings.extend(self._check_role_binding(rb, 'RoleBinding'))
        return findings
    
    def scan_cluster_role_bindings(self, cluster_role_bindings):
        findings = []
        for crb in cluster_role_bindings:
            if crb.metadata.name.startswith('system:'):
                continue
            findings.extend(self._check_role_binding(crb, 'ClusterRoleBinding'))
        return findings
    
    def _check_role_permissions(self, role, role_type):
        findings = []
        
        if not role.rules:
            return findings
        
        for rule in role.rules:
            if not rule.verbs:
                continue
            
            if '*' in rule.verbs:
                severity = 'CRITICAL' if '*' in (rule.resources or []) else 'HIGH'
                
                findings.append(Finding(
                    severity=severity,
                    category='RBAC',
                    title='Wildcard Permissions Granted',
                    description=f'{role_type} grants wildcard (*) verb permissions',
                    resource_type=role_type,
                    resource_name=role.metadata.name,
                    namespace=role.metadata.namespace if hasattr(role.metadata, 'namespace') else None,
                    remediation='Use specific verbs instead of wildcard',
                    metadata={'verbs': rule.verbs, 'resources': rule.resources}
                ))
            
            if rule.resources and '*' in rule.resources:
                findings.append(Finding(
                    severity='CRITICAL',
                    category='RBAC',
                    title='Wildcard Resource Access',
                    description=f'{role_type} grants access to all resources (*)',
                    resource_type=role_type,
                    resource_name=role.metadata.name,
                    namespace=role.metadata.namespace if hasattr(role.metadata, 'namespace') else None,
                    remediation='Specify exact resources instead of wildcard',
                    metadata={'verbs': rule.verbs, 'resources': rule.resources}
                ))
            
            dangerous_combos = []
            for verb in rule.verbs:
                if verb in self.DANGEROUS_VERBS:
                    for resource in (rule.resources or []):
                        if resource in self.DANGEROUS_RESOURCES:
                            dangerous_combos.append(f'{verb}:{resource}')
            
            if dangerous_combos:
                # Create detailed description with specific permissions
                perms_list = ', '.join(dangerous_combos)
                findings.append(Finding(
                    severity='HIGH',
                    category='RBAC',
                    title='Dangerous Permission Combination',
                    description=f'{role_type} "{role.metadata.name}" has dangerous verb/resource combinations: {perms_list}. These permissions can lead to privilege escalation, pod creation with host access, or secret theft.',
                    resource_type=role_type,
                    resource_name=role.metadata.name,
                    namespace=role.metadata.namespace if hasattr(role.metadata, 'namespace') else None,
                    remediation=f'Review and restrict these dangerous permissions: {perms_list}. Apply principle of least privilege.',
                    metadata={'dangerous_combos': dangerous_combos}
                ))
            
            if rule.resources and 'secrets' in rule.resources:
                if any(verb in ['get', 'list', 'watch', '*'] for verb in rule.verbs):
                    findings.append(Finding(
                        severity='HIGH',
                        category='RBAC',
                        title='Secrets Read Access Granted',
                        description=f'{role_type} can read secrets',
                        resource_type=role_type,
                        resource_name=role.metadata.name,
                        namespace=role.metadata.namespace if hasattr(role.metadata, 'namespace') else None,
                        remediation='Restrict secret access to only necessary service accounts',
                        metadata={'verbs': rule.verbs}
                    ))
            
            if rule.resources and 'pods/exec' in rule.resources:
                findings.append(Finding(
                    severity='CRITICAL',
                    category='RBAC',
                    title='Pod Exec Permission Granted',
                    description=f'{role_type} can execute commands in pods',
                    resource_type=role_type,
                    resource_name=role.metadata.name,
                    namespace=role.metadata.namespace if hasattr(role.metadata, 'namespace') else None,
                    remediation='Remove pods/exec permission unless absolutely necessary',
                    metadata={'verbs': rule.verbs}
                ))
        
        return findings
    
    def _check_role_binding(self, binding, binding_type):
        """
        Check RoleBindings and ClusterRoleBindings
        Special focus on 'default' ServiceAccount with dangerous permissions
        """
        findings = []
        
        if not binding.subjects:
            return findings
        
        # Get role name to check for dangerous permissions
        role_name = binding.role_ref.name if binding.role_ref else None
        
        for subject in binding.subjects:
            # Check for anonymous user or unauthenticated groups
            if subject.kind == 'User' and subject.name == 'system:anonymous':
                findings.append(Finding(
                    severity='CRITICAL',
                    category='RBAC',
                    title='Anonymous User Granted Permissions',
                    description=f'{binding_type} grants permissions to system:anonymous user - allows unauthenticated access!',
                    resource_type=binding_type,
                    resource_name=binding.metadata.name,
                    namespace=binding.metadata.namespace if hasattr(binding.metadata, 'namespace') else None,
                    remediation='Remove system:anonymous from role binding subjects',
                    metadata={'subject': subject.name}
                ))
            
            # NEW: Check for 'default' ServiceAccount with dangerous permissions
            if subject.kind == 'ServiceAccount' and subject.name == 'default':
                # Check if role has dangerous permissions
                dangerous_role_patterns = ['admin', 'edit', 'cluster-admin', 'exec', 'secret']
                is_dangerous = any(pattern in role_name.lower() for pattern in dangerous_role_patterns) if role_name else False
                
                # Also check if role grants wildcard or exec permissions
                if role_name in ['cluster-admin', 'admin', 'edit'] or is_dangerous:
                    severity = 'CRITICAL' if role_name == 'cluster-admin' else 'HIGH'
                    
                    findings.append(Finding(
                        severity=severity,
                        category='RBAC',
                        title='Default ServiceAccount with Dangerous Permissions',
                        description=f'{binding_type} "{binding.metadata.name}" grants role "{role_name}" to default ServiceAccount. Default SA is auto-mounted in every pod, providing these permissions to ALL pods in namespace.',
                        resource_type=binding_type,
                        resource_name=binding.metadata.name,
                        namespace=binding.metadata.namespace if hasattr(binding.metadata, 'namespace') else None,
                        remediation=f'Create a dedicated ServiceAccount with minimal permissions instead of using "default". Remove this binding or change subject to a non-default SA.',
                        metadata={
                            'subject': 'default',
                            'subject_kind': 'ServiceAccount',
                            'subject_namespace': subject.namespace if hasattr(subject, 'namespace') else binding.metadata.namespace,
                            'role': role_name,
                            'binding_name': binding.metadata.name,
                            'risk': 'All pods inherit these permissions'
                        }
                    ))
            
            # Check for overly permissive group bindings
            if subject.kind == 'Group':
                dangerous_groups = ['system:authenticated', 'system:unauthenticated']
                if subject.name in dangerous_groups:
                    findings.append(Finding(
                        severity='HIGH',
                        category='RBAC',
                        title='Overly Permissive Role Binding',
                        description=f'{binding_type} grants permissions to {subject.name} group - affects all authenticated/unauthenticated users',
                        resource_type=binding_type,
                        resource_name=binding.metadata.name,
                        namespace=binding.metadata.namespace if hasattr(binding.metadata, 'namespace') else None,
                        remediation=f'Remove binding to {subject.name} group. Grant permissions to specific users or service accounts instead.',
                        metadata={'subject': subject.name, 'role': binding.role_ref.name if binding.role_ref else 'unknown'}
                    ))
            
            if subject.kind == 'ServiceAccount' and subject.name == 'default':
                findings.append(Finding(
                    severity='MEDIUM',
                    category='RBAC',
                    title='Default Service Account Used',
                    description=f'{binding_type} binds permissions to default service account',
                    resource_type=binding_type,
                    resource_name=binding.metadata.name,
                    namespace=binding.metadata.namespace if hasattr(binding.metadata, 'namespace') else None,
                    remediation='Create dedicated service accounts for workloads',
                    metadata={'role': binding.role_ref.name}
                ))
        
        return findings
