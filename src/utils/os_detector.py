"""
OS Detection for Kubernetes Workloads
Detects if a pod/workload is running on Linux or Windows
"""

def detect_target_os(spec):
    """
    Detect target OS from pod/workload spec
    
    Checks:
    1. spec.os.name (K8s 1.25+)
    2. nodeSelector with kubernetes.io/os
    3. nodeAffinity with kubernetes.io/os
    4. Default to 'linux'
    
    Returns: 'linux' or 'windows'
    """
    # Method 1: Check spec.os.name (preferred, K8s 1.25+)
    if hasattr(spec, 'os') and spec.os:
        if hasattr(spec.os, 'name') and spec.os.name:
            os_name = spec.os.name.lower()
            if 'windows' in os_name:
                return 'windows'
            return 'linux'
    
    # Method 2: Check nodeSelector
    if hasattr(spec, 'node_selector') and spec.node_selector:
        os_label = spec.node_selector.get('kubernetes.io/os', '')
        if os_label.lower() == 'windows':
            return 'windows'
        if os_label.lower() == 'linux':
            return 'linux'
    
    # Method 3: Check nodeAffinity
    if hasattr(spec, 'affinity') and spec.affinity:
        if hasattr(spec.affinity, 'node_affinity') and spec.affinity.node_affinity:
            node_affinity = spec.affinity.node_affinity
            
            # Check required terms
            if hasattr(node_affinity, 'required_during_scheduling_ignored_during_execution'):
                required = node_affinity.required_during_scheduling_ignored_during_execution
                if hasattr(required, 'node_selector_terms') and required.node_selector_terms:
                    for term in required.node_selector_terms:
                        if hasattr(term, 'match_expressions') and term.match_expressions:
                            for expr in term.match_expressions:
                                if expr.key == 'kubernetes.io/os':
                                    if expr.values and 'windows' in [v.lower() for v in expr.values]:
                                        return 'windows'
    
    # Default to Linux (most common)
    return 'linux'


def should_skip_linux_kernel_checks(target_os):
    """
    Returns True if Linux kernel-specific checks should be skipped
    (e.g., for Windows containers)
    """
    return target_os == 'windows'


def get_os_specific_note(target_os, check_type):
    """
    Get OS-specific notes for checks that don't apply
    
    check_type: 'privileged', 'capabilities', 'runAsRoot', etc.
    """
    if target_os == 'windows':
        notes = {
            'privileged': 'Note: Privileged mode is a Linux kernel concept and does not apply to Windows containers.',
            'capabilities': 'Note: Linux capabilities are kernel-specific and not applicable to Windows containers.',
            'runAsRoot': 'Note: Windows containers use different user context mechanisms (ContainerUser, ContainerAdministrator). This Linux-specific check is informational only.',
            'seccomp': 'Note: Seccomp is a Linux kernel feature and is not available for Windows containers.',
            'apparmor': 'Note: AppArmor is a Linux security module and is not available for Windows containers.',
        }
        return notes.get(check_type, 'Note: This is a Linux-specific security feature.')
    
    return None
