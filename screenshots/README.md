# Screenshots Directory

Add your k8scan screenshots here!

## Required Screenshots

1. **executive-summary.png** - Terminal output showing executive summary and risk score
2. **exploit-list.png** - Terminal output showing `./k8scan exploit --list`
3. **html-report.png** - Browser screenshot of the HTML report

## How to Take Screenshots

### 1. Executive Summary
```bash
./k8scan scan --exclude-system
# Screenshot the executive summary + risk score section
```

### 2. Exploit List
```bash
./k8scan exploit --list
# Screenshot the table with exploitable findings
```

### 3. HTML Report
```bash
./k8scan scan --output html -f demo
open reports/demo.html
# Screenshot showing collapsible findings and attack paths
```

## Tips
- Use high resolution (at least 1280x720)
- Include terminal prompt/context
- Show k8scan banner in terminal shots
- Highlight interesting findings in HTML report
