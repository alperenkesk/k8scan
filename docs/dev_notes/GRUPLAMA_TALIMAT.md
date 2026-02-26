# Reporter Gruplama Fonksiyonu

Reporter.export_html metodunun BAŞINA şu fonksiyonu ekle:

```python
def _group_findings_by_title(self, findings):
    """Group identical findings for compact display"""
    from collections import defaultdict
    
    grouped = defaultdict(list)
    for finding in findings:
        # Group by title + severity + category
        key = (finding.title, finding.severity, finding.category)
        grouped[key].append(finding)
    
    # Convert to grouped findings
    result = []
    for (title, severity, category), finding_list in grouped.items():
        if len(finding_list) == 1:
            # Single finding - keep as-is
            result.append(finding_list[0])
        else:
            # Multiple findings - create grouped finding
            base = finding_list[0]
            base.metadata = base.metadata or {}
            base.metadata['is_grouped'] = True
            base.metadata['affected_count'] = len(finding_list)
            base.metadata['affected_resources'] = [
                {
                    'name': f.resource_name,
                    'namespace': f.namespace or 'N/A',
                    'type': f.resource_type
                }
                for f in finding_list
            ]
            # Use first finding's PoC but mark as grouped
            base.description = f"{base.description} (Affects {len(finding_list)} resources)"
            result.append(base)
    
    return sorted(result, key=lambda x: (
        {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(x.severity, 5),
        x.title
    ))
```

export_html metodunun EN BAŞINDA şu satırı ekle:
```python
findings = self._group_findings_by_title(findings)
```

HTML template'inde metadata'da affected_resources varsa şöyle göster:
```html
{% if finding.metadata and finding.metadata.get('is_grouped') %}
<div class="affected-resources">
    <h4>📦 Affected Resources ({finding.metadata.affected_count})</h4>
    <ul>
    {% for resource in finding.metadata.affected_resources %}
        <li>{resource.type}/{resource.name} (namespace: {resource.namespace})</li>
    {% endfor %}
    </ul>
</div>
{% endif %}
```
