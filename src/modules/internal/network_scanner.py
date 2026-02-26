from src.core.finding import Finding


class NetworkScanner:
    def __init__(self):
        self.findings = []
    
    def scan(self, namespaces, network_policies, pods, services, ingresses):
        self.findings = []
        self._check_missing_network_policies(namespaces, network_policies)
        self._check_permissive_policies(network_policies)
        
        # Advanced Network Security Checks
        self._check_egress_policies(namespaces, network_policies)
        self._check_cloud_metadata_exposure(namespaces, network_policies)
        
        self._check_exposed_services(services)
        
        # LoadBalancer and Ingress checks
        self._check_loadbalancer_source_ranges(services)
        self._check_ingress_tls(ingresses)
        
        # NEW: Advanced checks
        self._check_insecure_ingress(ingresses)
        self._check_exposed_databases(services)
        
        return self.findings
    
    def _check_missing_network_policies(self, namespaces, network_policies):
        system_namespaces = ['kube-system', 'kube-public', 'kube-node-lease']
        
        policy_namespaces = set()
        for policy in network_policies:
            policy_namespaces.add(policy.metadata.namespace)
        
        for ns in namespaces:
            if ns.metadata.name in system_namespaces:
                continue
            
            if ns.metadata.name not in policy_namespaces:
                self.findings.append(Finding(
                    severity='MEDIUM',
                    category='Network Security',
                    title='Missing Network Policy',
                    description=f'Namespace has no network policies defined',
                    resource_type='Namespace',
                    resource_name=ns.metadata.name,
                    namespace=ns.metadata.name,
                    remediation='Define network policies to restrict pod-to-pod communication',
                    metadata={}
                ))
    
    def _check_permissive_policies(self, network_policies):
        for policy in network_policies:
            if not policy.spec.ingress and not policy.spec.egress:
                continue
            
            if policy.spec.ingress:
                for rule in policy.spec.ingress:
                    if not rule._from:
                        self.findings.append(Finding(
                            severity='HIGH',
                            category='Network Security',
                            title='Permissive Ingress Rule',
                            description='Network policy allows ingress from all sources',
                            resource_type='NetworkPolicy',
                            resource_name=policy.metadata.name,
                            namespace=policy.metadata.namespace,
                            remediation='Specify source pod/namespace selectors',
                            metadata={}
                        ))
                    else:
                        for source in rule._from:
                            if hasattr(source, 'namespace_selector') and source.namespace_selector and not source.namespace_selector.match_labels:
                                self.findings.append(Finding(
                                    severity='MEDIUM',
                                    category='Network Security',
                                    title='Broad Namespace Selector',
                                    description='Network policy allows traffic from all namespaces',
                                    resource_type='NetworkPolicy',
                                    resource_name=policy.metadata.name,
                                    namespace=policy.metadata.namespace,
                                    remediation='Add specific namespace labels to selector',
                                    metadata={}
                                ))
            
            if policy.spec.egress:
                for rule in policy.spec.egress:
                    if not rule.to:
                        self.findings.append(Finding(
                            severity='MEDIUM',
                            category='Network Security',
                            title='Permissive Egress Rule',
                            description='Network policy allows egress to all destinations',
                            resource_type='NetworkPolicy',
                            resource_name=policy.metadata.name,
                            namespace=policy.metadata.namespace,
                            remediation='Specify destination pod/namespace selectors',
                            metadata={}
                        ))
    
    def _check_exposed_services(self, services):
        for service in services:
            if service.spec.type == 'NodePort':
                self.findings.append(Finding(
                    severity='MEDIUM',
                    category='Network Security',
                    title='NodePort Service Exposed',
                    description='Service is exposed on all nodes',
                    resource_type='Service',
                    resource_name=service.metadata.name,
                    namespace=service.metadata.namespace,
                    remediation='Consider using LoadBalancer or Ingress instead',
                    metadata={'ports': [port.node_port for port in service.spec.ports if port.node_port]}
                ))
            
            if service.spec.type == 'LoadBalancer':
                if not service.spec.load_balancer_source_ranges:
                    self.findings.append(Finding(
                        severity='HIGH',
                        category='Network Security',
                        title='LoadBalancer Without Source Ranges',
                        description='LoadBalancer service allows access from any IP',
                        resource_type='Service',
                        resource_name=service.metadata.name,
                        namespace=service.metadata.namespace,
                        remediation='Add loadBalancerSourceRanges to restrict access',
                        metadata={}
                    ))
            
            if service.spec.external_i_ps:
                self.findings.append(Finding(
                    severity='HIGH',
                    category='Network Security',
                    title='ExternalIPs MITM / Hijacking Risk',
                    description=f'Service "{service.metadata.name}" has externalIPs configured: {", ".join(service.spec.external_i_ps)}. Any pod in the cluster can claim these IPs via ARP spoofing for traffic hijacking.',
                    resource_type='Service',
                    resource_name=service.metadata.name,
                    namespace=service.metadata.namespace,
                    remediation='Remove externalIPs if not required. Use LoadBalancer type instead. If externalIPs needed, restrict with admission controller.',
                    metadata={'external_ips': service.spec.external_i_ps}
                ))
            
            if service.spec.ports:
                for port in service.spec.ports:
                    port_num = port.port if hasattr(port, 'port') else None
                    if port_num == 5000:
                        cluster_ip = service.spec.cluster_ip or '<CLUSTER-IP>'
                        node_port = port.node_port if hasattr(port, 'node_port') and port.node_port else None
                        if service.spec.type == 'NodePort' and node_port:
                            poc_cmd = f'curl -s http://<NODE-IP>:{node_port}/v2/_catalog'
                        else:
                            poc_cmd = f'curl -s http://{cluster_ip}:5000/v2/_catalog'
                        self.findings.append(Finding(
                            severity='HIGH',
                            category='Container Security',
                            title='Insecure Private Container Registry Exposed',
                            description=(
                                f'The service {service.metadata.name} exposes an unauthenticated Private Container Registry on port 5000. '
                                'Attackers accessing this port can pull sensitive internal images to extract source code and secrets, or '
                                'push maliciously backdoored images to achieve internal Remote Code Execution (Supply Chain Attack).'
                            ),
                            resource_type='Service',
                            resource_name=service.metadata.name,
                            namespace=service.metadata.namespace,
                            remediation='Enable TLS and basic authentication on the registry container. Restrict access using Network Policies.',
                            metadata={'port': 5000, 'node_port': node_port, 'cluster_ip': cluster_ip, 'poc_cmd': poc_cmd}
                        ))
                        break
    
    def _check_egress_policies(self, namespaces, network_policies):
        """Advanced Egress Policy Control"""
        system_namespaces = ['kube-system', 'kube-public', 'kube-node-lease']
        
        namespaces_with_egress = {}
        for policy in network_policies:
            ns = policy.metadata.namespace
            if ns not in namespaces_with_egress:
                namespaces_with_egress[ns] = []
            
            if policy.spec.egress:
                for egress_rule in policy.spec.egress:
                    if egress_rule.to:
                        for to_rule in egress_rule.to:
                            if hasattr(to_rule, 'ip_block') and to_rule.ip_block:
                                if to_rule.ip_block.cidr == '0.0.0.0/0':
                                    self.findings.append(Finding(
                                        severity='HIGH',
                                        category='Network Security',
                                        title='Unrestricted Egress Traffic',
                                        description=f'NetworkPolicy "{policy.metadata.name}" allows egress to 0.0.0.0/0 (entire internet)',
                                        resource_type='NetworkPolicy',
                                        resource_name=policy.metadata.name,
                                        namespace=ns,
                                        remediation='Restrict egress to specific IPs/CIDRs.',
                                        metadata={'cidr': '0.0.0.0/0'}
                                    ))
                    else:
                        self.findings.append(Finding(
                            severity='HIGH',
                            category='Network Security',
                            title='Unrestricted Egress Traffic',
                            description=f'NetworkPolicy "{policy.metadata.name}" has egress rule without destination restrictions',
                            resource_type='NetworkPolicy',
                            resource_name=policy.metadata.name,
                            namespace=ns,
                            remediation='Add specific destination IPs/namespaces to egress rules',
                            metadata={}
                        ))
                
                namespaces_with_egress[ns].append(policy.metadata.name)
        
        for ns in namespaces:
            if ns.metadata.name in system_namespaces:
                continue
            
            if ns.metadata.name not in namespaces_with_egress or not namespaces_with_egress[ns.metadata.name]:
                self.findings.append(Finding(
                    severity='MEDIUM',
                    category='Network Security',
                    title='No Egress Policy Defined',
                    description=f'Namespace "{ns.metadata.name}" has no egress network policies. Pods can access any external endpoint.',
                    resource_type='Namespace',
                    resource_name=ns.metadata.name,
                    namespace=ns.metadata.name,
                    remediation='Create NetworkPolicy with egress rules to restrict outbound traffic',
                    metadata={}
                ))
    
    def _check_cloud_metadata_exposure(self, namespaces, network_policies):
        """Cloud Metadata API Isolation"""
        system_namespaces = ['kube-system', 'kube-public', 'kube-node-lease']
        METADATA_IP = '169.254.169.254'
        
        namespaces_blocking_metadata = set()
        
        for policy in network_policies:
            ns = policy.metadata.namespace
            if policy.spec.egress:
                for egress_rule in policy.spec.egress:
                    if egress_rule.to:
                        for to_rule in egress_rule.to:
                            if hasattr(to_rule, 'ip_block') and to_rule.ip_block:
                                if to_rule.ip_block.except_:
                                    for except_cidr in to_rule.ip_block.except_:
                                        if METADATA_IP in except_cidr or except_cidr == f'{METADATA_IP}/32':
                                            namespaces_blocking_metadata.add(ns)
        
        for ns in namespaces:
            if ns.metadata.name in system_namespaces:
                continue
            
            if ns.metadata.name not in namespaces_blocking_metadata:
                self.findings.append(Finding(
                    severity='LOW',
                    category='Network Security',
                    title='Cloud Metadata API Exposed',
                    description=f'Namespace "{ns.metadata.name}" does not actively block access to cloud metadata API (169.254.169.254). If this is a Cloud Provider environment, Pods may steal cloud credentials via SSRF.',
                    resource_type='Namespace',
                    resource_name=ns.metadata.name,
                    namespace=ns.metadata.name,
                    remediation=f'Add NetworkPolicy egress rule to block {METADATA_IP}. Use "except: [169.254.169.254/32]" in ipBlock.',
                    metadata={'metadata_ip': METADATA_IP, 'risk': 'Cloud credential theft'}
                ))
    
    def _check_loadbalancer_source_ranges(self, services):
        """LoadBalancer Source Range Check"""
        for svc in services:
            if svc.spec.type != 'LoadBalancer':
                continue
            
            if not svc.spec.load_balancer_source_ranges:
                self.findings.append(Finding(
                    severity='HIGH',
                    category='Network Security',
                    title='Unrestricted LoadBalancer Exposure',
                    description=f'LoadBalancer service "{svc.metadata.name}" has no source IP restrictions. Accessible from entire internet.',
                    resource_type='Service',
                    resource_name=svc.metadata.name,
                    namespace=svc.metadata.namespace,
                    remediation='Add spec.loadBalancerSourceRanges with specific allowed IP ranges.',
                    metadata={'type': 'LoadBalancer', 'risk': 'Public internet exposure'}
                ))
            else:
                for cidr in svc.spec.load_balancer_source_ranges:
                    if cidr == '0.0.0.0/0':
                        self.findings.append(Finding(
                            severity='HIGH',
                            category='Network Security',
                            title='Unrestricted LoadBalancer Exposure',
                            description=f'LoadBalancer service "{svc.metadata.name}" explicitly allows 0.0.0.0/0 (entire internet).',
                            resource_type='Service',
                            resource_name=svc.metadata.name,
                            namespace=svc.metadata.namespace,
                            remediation='Remove 0.0.0.0/0 from loadBalancerSourceRanges.',
                            metadata={'source_ranges': svc.spec.load_balancer_source_ranges}
                        ))
                        break
    
    def _check_ingress_tls(self, ingresses):
        """Ingress TLS Configuration Check"""
        for ingress in ingresses:
            if not ingress.spec.tls or len(ingress.spec.tls) == 0:
                hosts = []
                if ingress.spec.rules:
                    for rule in ingress.spec.rules:
                        if rule.host:
                            hosts.append(rule.host)
                
                hosts_str = ', '.join(hosts) if hosts else 'all hosts'
                
                self.findings.append(Finding(
                    severity='MEDIUM',
                    category='Network Security',
                    title='Missing TLS in Ingress',
                    description=f'Ingress "{ingress.metadata.name}" exposes {hosts_str} without TLS encryption. Traffic is sent in plaintext.',
                    resource_type='Ingress',
                    resource_name=ingress.metadata.name,
                    namespace=ingress.metadata.namespace,
                    remediation='Add spec.tls configuration with valid certificates. Use cert-manager for automated certificate management.',
                    metadata={'hosts': hosts, 'risk': 'Plaintext traffic, credential exposure'}
                ))
            else:
                tls_hosts = set()
                for tls_config in ingress.spec.tls:
                    if tls_config.hosts:
                        tls_hosts.update(tls_config.hosts)
                
                if ingress.spec.rules:
                    for rule in ingress.spec.rules:
                        if rule.host and rule.host not in tls_hosts:
                            self.findings.append(Finding(
                                severity='MEDIUM',
                                category='Network Security',
                                title='Partial TLS Coverage in Ingress',
                                description=f'Ingress "{ingress.metadata.name}" host "{rule.host}" is not covered by TLS configuration.',
                                resource_type='Ingress',
                                resource_name=ingress.metadata.name,
                                namespace=ingress.metadata.namespace,
                                remediation=f'Add "{rule.host}" to spec.tls.hosts array',
                                metadata={'uncovered_host': rule.host}
                            ))
    
    # ========== NEW: 3 Advanced Network Modules ==========
    
    def _check_insecure_ingress(self, ingresses):
        """
        Insecure Ingress / Public Exposure
        Wildcard hosts, missing auth annotations
        """
        AUTH_ANNOTATIONS = [
            'nginx.ingress.kubernetes.io/auth-url',
            'nginx.ingress.kubernetes.io/auth-signin',
            'nginx.ingress.kubernetes.io/auth-type',
            'nginx.ingress.kubernetes.io/whitelist-source-range',
        ]
        
        for ingress in ingresses:
            annotations = ingress.metadata.annotations or {}
            
            if ingress.spec.rules:
                for rule in ingress.spec.rules:
                    # Check for wildcard host
                    if not rule.host or rule.host == '*':
                        self.findings.append(Finding(
                            severity='LOW',
                            category='Network Security',
                            title='Insecure Ingress: Wildcard Host',
                            description=f'Ingress "{ingress.metadata.name}" uses a wildcard or empty host, meaning it accepts requests from ANY domain. This can lead to SNI routing issues or MITM if TLS is missing.',
                            resource_type='Ingress',
                            resource_name=ingress.metadata.name,
                            namespace=ingress.metadata.namespace,
                            remediation='Set a specific hostname in spec.rules[].host instead of wildcard.',
                            metadata={'host': rule.host or '*'}
                        ))
            
            # Check for missing authentication annotations
            has_auth = any(ann in annotations for ann in AUTH_ANNOTATIONS)
            if not has_auth:
                hosts = []
                if ingress.spec.rules:
                    for rule in ingress.spec.rules:
                        if rule.host:
                            hosts.append(rule.host)
                hosts_str = ', '.join(hosts) if hosts else 'all hosts'
                
                self.findings.append(Finding(
                    severity='INFO',
                    category='Network Security',
                    title='Public Ingress (No Authentication/Whitelist)',
                    description=f'Ingress "{ingress.metadata.name}" for {hosts_str} has no standard Nginx ingress authentication or IP whitelist annotations. It is fully accessible from the public internet.',
                    resource_type='Ingress',
                    resource_name=ingress.metadata.name,
                    namespace=ingress.metadata.namespace,
                    remediation='Add nginx.ingress.kubernetes.io/auth-url or whitelist-source-range annotation for access control.',
                    metadata={'hosts': hosts}
                ))
    
    def _check_exposed_databases(self, services):
        """
        Exposed Sensitive Database Check (CRITICAL)
        Redis, MySQL, PostgreSQL, MongoDB, Elasticsearch exposed as NodePort/LB
        """
        DB_PATTERNS = {
            'redis': {'port': 6379, 'risk': 'In-memory data store, often no auth'},
            'mysql': {'port': 3306, 'risk': 'Relational database, direct SQL access'},
            'postgres': {'port': 5432, 'risk': 'PostgreSQL database, direct SQL access'},
            'mongo': {'port': 27017, 'risk': 'NoSQL database, direct access'},
            'elastic': {'port': 9200, 'risk': 'Search engine, direct API access'},
            'memcache': {'port': 11211, 'risk': 'Cache store, data extraction'},
            'cassandra': {'port': 9042, 'risk': 'Wide-column database, direct CQL access'},
        }
        
        for svc in services:
            svc_name = svc.metadata.name.lower()
            svc_type = svc.spec.type
            
            if svc_type not in ['NodePort', 'LoadBalancer']:
                continue
            
            for db_pattern, db_info in DB_PATTERNS.items():
                if db_pattern in svc_name:
                    ports_info = []
                    for port in svc.spec.ports:
                        if svc_type == 'NodePort' and port.node_port:
                            ports_info.append({'port': port.port, 'node_port': port.node_port})
                        else:
                            ports_info.append({'port': port.port})
                    
                    node_port_str = ''
                    if svc_type == 'NodePort' and ports_info:
                        np = ports_info[0].get('node_port', '')
                        node_port_str = f' NodePort: {np}' if np else ''
                    
                    self.findings.append(Finding(
                        severity='CRITICAL',
                        category='Network Security',
                        title='Exposed Sensitive Database',
                        description=f'Database service "{svc.metadata.name}" ({db_pattern}) is exposed as {svc_type}.{node_port_str} {db_info["risk"]}. Direct external access to production data.',
                        resource_type='Service',
                        resource_name=svc.metadata.name,
                        namespace=svc.metadata.namespace,
                        remediation=f'Change service type to ClusterIP: kubectl patch svc {svc.metadata.name} -n {svc.metadata.namespace} -p \'{{"spec":{{"type":"ClusterIP"}}}}\'',
                        metadata={'db_type': db_pattern, 'service_type': svc_type, 'ports': ports_info}
                    ))
                    break
