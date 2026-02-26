from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    resource_type: str
    resource_name: str
    namespace: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    exploitation: Optional[list] = None
    attack_flow: Optional[list] = None
    impact: Optional[str] = None
    proof_of_concept: Optional[str] = None
    finding_id: Optional[int] = None
    target_os: Optional[str] = 'linux'  # NEW: 'linux' or 'windows'
    
    def to_dict(self):
        return {
            'id': self.finding_id,
            'severity': self.severity,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'resource_type': self.resource_type,
            'resource_name': self.resource_name,
            'namespace': self.namespace,
            'remediation': self.remediation,
            'metadata': self.metadata,
            'exploitation': self.exploitation,
            'attack_flow': self.attack_flow,
            'impact': self.impact,
            'proof_of_concept': self.proof_of_concept,
            'target_os': self.target_os
        }
    
    @property
    def severity_score(self):
        scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        return scores.get(self.severity, 0)
