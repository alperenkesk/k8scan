from src.core.finding import Finding
import base64
import re


class SecretScanner:
    SECRET_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)aws(.{0,20})?["\'][0-9a-zA-Z\/+]{40}["\']',
        'github_token': r'gh[pousr]_[0-9a-zA-Z]{36}',
        'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'private_key': r'-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----',
        'generic_api_key': r'(?i)(api[_-]?key|apikey)[\s]*[:=][\s]*["\']?[0-9a-zA-Z\-_]{20,}["\']?',
        'generic_secret': r'(?i)(secret|password|passwd|pwd)[\s]*[:=][\s]*["\']?[0-9a-zA-Z\-_@!#$%^&*]{8,}["\']?',
    }
    # Secret types/names that should be skipped (standard K8s infrastructure)
    SKIP_SECRET_TYPES = {
        'kubernetes.io/service-account-token',
        'bootstrap.kubernetes.io/token',
    }
    
    def __init__(self):
        self.findings = []
    
    def scan(self, secrets):
        self.findings = []
        for secret in secrets:
            # Skip standard Kubernetes infrastructure secrets
            if secret.type in self.SKIP_SECRET_TYPES:
                continue
            # Skip bootstrap token secrets by name pattern
            if secret.metadata.name.startswith('bootstrap-token-'):
                continue
            self._check_secret_data(secret)
            self._check_secret_type(secret)
        return self.findings
    
    def _check_secret_data(self, secret):
        if not secret.data:
            return
        
        for key, value in secret.data.items():
            try:
                decoded = base64.b64decode(value).decode('utf-8')
                
                for pattern_name, pattern in self.SECRET_PATTERNS.items():
                    matches = re.findall(pattern, decoded)
                    if matches:
                        self.findings.append(Finding(
                            severity='HIGH',
                            category='Secret Management',
                            title=f'Potential {pattern_name.replace("_", " ").title()} Found',
                            description=f'Secret key "{key}" contains pattern matching {pattern_name}',
                            resource_type='Secret',
                            resource_name=secret.metadata.name,
                            namespace=secret.metadata.namespace,
                            remediation='Review and rotate this secret if it is legitimate',
                            metadata={'key': key, 'pattern': pattern_name}
                        ))
                
                if len(decoded) < 8:
                    self.findings.append(Finding(
                        severity='MEDIUM',
                        category='Secret Management',
                        title='Weak Secret Detected',
                        description=f'Secret key "{key}" has a value shorter than 8 characters',
                        resource_type='Secret',
                        resource_name=secret.metadata.name,
                        namespace=secret.metadata.namespace,
                        remediation='Use stronger secrets with minimum 16 characters',
                        metadata={'key': key, 'length': len(decoded)}
                    ))
                
            except Exception:
                pass
    
    def _check_secret_type(self, secret):
        if secret.type == 'Opaque':
            if not secret.data:
                self.findings.append(Finding(
                    severity='LOW',
                    category='Secret Management',
                    title='Empty Secret',
                    description='Secret exists but contains no data',
                    resource_type='Secret',
                    resource_name=secret.metadata.name,
                    namespace=secret.metadata.namespace,
                    remediation='Remove unused secrets',
                    metadata={}
                ))


class ConfigMapScanner:
    SECRET_KEYWORDS = ['password', 'secret', 'token', 'api_key', 'apikey', 'private_key', 'access_key']
    
    def __init__(self):
        self.findings = []
    
    def scan(self, configmaps):
        self.findings = []
        for cm in configmaps:
            self._check_sensitive_data(cm)
        return self.findings
    
    def _check_sensitive_data(self, cm):
        if not cm.data:
            return
        
        for key, value in cm.data.items():
            key_lower = key.lower()
            
            if any(keyword in key_lower for keyword in self.SECRET_KEYWORDS):
                self.findings.append(Finding(
                    severity='HIGH',
                    category='Secret Management',
                    title='Sensitive Data in ConfigMap',
                    description=f'ConfigMap key "{key}" suggests it contains sensitive data',
                    resource_type='ConfigMap',
                    resource_name=cm.metadata.name,
                    namespace=cm.metadata.namespace,
                    remediation='Move sensitive data to Secrets instead of ConfigMaps',
                    metadata={'key': key}
                ))
            
            for pattern_name, pattern in SecretScanner.SECRET_PATTERNS.items():
                matches = re.findall(pattern, value)
                if matches:
                    self.findings.append(Finding(
                        severity='HIGH',
                        category='Secret Management',
                        title=f'Potential {pattern_name.replace("_", " ").title()} in ConfigMap',
                        description=f'ConfigMap key "{key}" contains pattern matching {pattern_name}',
                        resource_type='ConfigMap',
                        resource_name=cm.metadata.name,
                        namespace=cm.metadata.namespace,
                        remediation='Move this to a Secret and rotate the credential',
                        metadata={'key': key, 'pattern': pattern_name}
                    ))
