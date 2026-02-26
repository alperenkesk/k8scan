from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import json


class Reporter:
    def __init__(self):
        self.console = Console()
    
    def print_summary(self, summary):
        self.console.print("\n[bold cyan]═══ Scan Summary ═══[/bold cyan]\n")
        
        summary_table = Table(show_header=False, box=box.SIMPLE)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        
        severity_colors = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'cyan'
        }
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary.get(severity, 0)
            color = severity_colors.get(severity, 'white')
            summary_table.add_row(
                f"[{color}]{severity.upper()}[/{color}]",
                f"[{color}]{count}[/{color}]"
            )
        
        summary_table.add_row("[bold]TOTAL[/bold]", f"[bold]{summary['total']}[/bold]")
        
        self.console.print(summary_table)
        self.console.print()
    
    def print_executive_summary(self, exec_summary):
        """Print executive summary box"""
        summary_text = f"""[bold cyan]Total Findings:[/bold cyan] {exec_summary['total']}
[bold green]Exploitable:[/bold green] {exec_summary['exploitable']} ({exec_summary['exploitable_percent']:.1f}%)
[bold red]Attack Surface:[/bold red] {exec_summary['attack_surface']} critical entry points

[bold yellow]Severity Breakdown:[/bold yellow]
├─ Critical: {exec_summary['critical']}
├─ High: {exec_summary['high']}
├─ Medium: {exec_summary['medium']}
└─ Low: {exec_summary['low']}"""

        if exec_summary['highest_risk']:
            hr = exec_summary['highest_risk']
            summary_text += f"\n\n[bold red]Highest Risk:[/bold red] {hr.title}"
        
        panel = Panel(
            summary_text,
            title="[bold white on blue] EXECUTIVE SUMMARY [/bold white on blue]",
            border_style="bold blue",
            box=box.DOUBLE
        )
        
        self.console.print(panel)
        self.console.print()
    
    def print_risk_score(self, overall_score, category_scores):
        """Print cluster security risk score"""
        
        # Determine score color and rating
        if overall_score >= 80:
            score_color = "green"
            rating = "GOOD"
        elif overall_score >= 60:
            score_color = "yellow"
            rating = "FAIR"
        elif overall_score >= 40:
            score_color = "orange1"
            rating = "POOR"
        else:
            score_color = "red"
            rating = "CRITICAL"
        
        score_text = f"[bold {score_color}]{overall_score}/100[/bold {score_color}] ({rating})"
        
        # Category breakdown
        categories_text = "\n[bold]Category Breakdown:[/bold]\n"
        for category, score in category_scores.items():
            if score >= 80:
                color = "green"
            elif score >= 60:
                color = "yellow"
            elif score >= 40:
                color = "orange1"
            else:
                color = "red"
            
            bar = "█" * (score // 5) + "░" * (20 - score // 5)
            categories_text += f"├─ {category:25s} [{color}]{bar}[/{color}] {score}/100\n"
        
        panel = Panel(
            f"[bold white]Cluster Security Score:[/bold white] {score_text}\n{categories_text}",
            title="[bold white on red] RISK SCORE [/bold white on red]" if overall_score < 40 else "[bold white on yellow] RISK SCORE [/bold white on yellow]" if overall_score < 80 else "[bold white on green] RISK SCORE [/bold white on green]",
            border_style=score_color,
            box=box.DOUBLE
        )
        
        self.console.print(panel)
        self.console.print()
    
    def print_attack_paths(self, paths):
        """Print identified attack paths"""
        if not paths:
            return
        
        self.console.print("\n[bold red]⚠️  HIGH-RISK ATTACK PATHS DETECTED[/bold red]\n")
        
        for idx, path in enumerate(paths[:3], 1):  # Show top 3
            risk_color = {
                'CRITICAL': 'red',
                'HIGH': 'yellow',
                'MEDIUM': 'blue'
            }.get(path['risk'], 'white')
            
            steps_text = "\n".join([f"  {i}. {step}" for i, step in enumerate(path['steps'], 1)])
            
            path_text = f"""[bold]Attack Vector:[/bold] {path['name']}
[bold]Risk Level:[/bold] [{risk_color}]{path['risk']}[/{risk_color}]
[bold]Entry Points:[/bold] {path['entry_points']} vulnerable resources
[bold]Time to Compromise:[/bold] {path['time_to_compromise']}

[bold yellow]Attack Steps:[/bold yellow]
{steps_text}"""
            
            panel = Panel(
                path_text,
                title=f"[bold white on {risk_color}] Attack Path #{idx} [/bold white on {risk_color}]",
                border_style=risk_color,
                box=box.HEAVY
            )
            
            self.console.print(panel)
            self.console.print()
    
    def print_findings(self, findings):
        if not findings:
            self.console.print("[green]✓ No security issues found![/green]\n")
            return
        
        findings_by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for finding in findings:
            findings_by_severity[finding.severity].append(finding)
        
        severity_colors = {
            'CRITICAL': 'bold red',
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'blue',
            'INFO': 'cyan'
        }
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if not findings_by_severity[severity]:
                continue
            
            color = severity_colors[severity]
            self.console.print(f"\n[{color}]{'─' * 80}[/{color}]")
            self.console.print(f"[{color} bold]{severity} FINDINGS ({len(findings_by_severity[severity])})[/{color} bold]")
            self.console.print(f"[{color}]{'─' * 80}[/{color}]\n")
            
            for finding in findings_by_severity[severity]:
                self._print_finding(finding, color)
    
    def _print_finding(self, finding, color):
        title = f"[{color} bold]{finding.title}[/{color} bold]"
        
        details = []
        details.append(f"[bold]Category:[/bold] {finding.category}")
        details.append(f"[bold]Resource:[/bold] {finding.resource_type}/{finding.resource_name}")
        
        if finding.namespace:
            details.append(f"[bold]Namespace:[/bold] {finding.namespace}")
        
        
        details.append(f"[bold]Description:[/bold] {finding.description}")
        
        if finding.exploitation:
            details.append("")
            details.append(f"[bold red]EXPLOITATION:[/bold red]")
            for i, exploit in enumerate(finding.exploitation, 1):
                details.append(f"  {i}. {exploit}")
        
        if finding.attack_flow:
            details.append("")
            details.append(f"[bold yellow]ATTACK FLOW:[/bold yellow]")
            for i, step in enumerate(finding.attack_flow, 1):
                details.append(f"  Step {i}: {step}")
        
        if finding.impact:
            details.append("")
            details.append(f"[bold magenta]IMPACT:[/bold magenta] {finding.impact}")
        
        if finding.remediation:
            details.append("")
            details.append(f"[bold green]REMEDIATION:[/bold green] {finding.remediation}")
        
        if finding.metadata:
            metadata_str = ", ".join([f"{k}={v}" for k, v in finding.metadata.items() if v])
            if metadata_str:
                details.append(f"[dim]Details: {metadata_str}[/dim]")
        
        panel = Panel(
            "\n".join(details),
            title=title,
            border_style=color,
            box=box.ROUNDED
        )
        
        self.console.print(panel)
        self.console.print()
    
    def export_json(self, findings, filename):
        data = {
            'findings': [f.to_dict() for f in findings],
            'summary': self._calculate_summary(findings)
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.console.print(f"[green]✓ Results exported to {filename}[/green]")
    
    def _build_html(self, findings, exploit_results=None):
        """Build the full HTML string for the report (used by both HTML and PDF export)."""
        html_template = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>K8s Security Scan Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        /* ===== CSS VARIABLES (THEME) ===== */
        :root {{
            --bg-body: #0b1120;
            --bg-container: #111827;
            --bg-card: #1e293b;
            --bg-card-hover: #263248;
            --bg-meta: #0f172a;
            --bg-header: linear-gradient(135deg, #0b1120 0%, #1e3a5f 50%, #0b1120 100%);
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border: #334155;
            --code-bg: #0d1117;
            --card-critical: rgba(239,68,68,0.07);
            --card-medium: rgba(234,179,8,0.07);
            --card-low: rgba(59,130,246,0.07);
            --card-info: rgba(6,182,212,0.07);
            --card-low: rgba(59,130,246,0.07);
        }}
        [data-theme="light"] {{
            --bg-body: #f1f5f9;
            --bg-container: #ffffff;
            --bg-card: #ffffff;
            --bg-card-hover: #f8fafc;
            --bg-meta: #f8fafc;
            --bg-header: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --text-muted: #94a3b8;
            --border: #e2e8f0;
            --code-bg: #1e293b;
            --card-critical: #fef2f2;
            --card-high: #fff7ed;
            --card-medium: #fffbeb;
            --card-low: #eff6ff;
            --card-info: #ecfeff;
        }}

        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-body);
            color: var(--text-primary);
            transition: background .3s, color .3s;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg-container);
            box-shadow: 0 20px 60px rgba(0,0,0,.4);
        }}

        /* ===== HEADER ===== */
        .header {{
            background: var(--bg-header);
            color: #fff;
            padding: 48px 40px;
            text-align: center;
            position: relative;
            border-bottom: 2px solid rgba(56,189,248,.25);
        }}
        .header h1 {{
            font-size: 3em; font-weight: 900; letter-spacing: -1px;
            background: linear-gradient(135deg, #38bdf8, #a78bfa, #f472b6);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}
        .header .subtitle {{ font-size:1.1em; opacity:.8; font-weight:500; letter-spacing:2px; text-transform:uppercase; margin-top:6px; }}
        .header .ts {{ margin-top:10px; font-size:.85em; opacity:.45; font-family:'JetBrains Mono',monospace; }}

        /* ===== THEME TOGGLE ===== */
        .theme-toggle {{
            position:fixed; top:18px; right:18px; z-index:1000;
            background:var(--bg-card); border:2px solid var(--border);
            color:var(--text-primary); width:46px; height:46px; border-radius:50%;
            cursor:pointer; font-size:1.3em; display:flex; align-items:center; justify-content:center;
            box-shadow:0 4px 14px rgba(0,0,0,.3); transition:all .3s;
        }}
        .theme-toggle:hover {{ transform:scale(1.12); box-shadow:0 0 18px rgba(56,189,248,.35); }}

        /* ===== DASHBOARD (DONUT + STATS) ===== */
        .dashboard {{
            padding:35px 40px; background:var(--bg-body); border-bottom:1px solid var(--border);
        }}
        .dashboard h2 {{
            font-size:1.2em; font-weight:800; margin-bottom:22px; color:var(--text-primary);
            text-transform:uppercase; letter-spacing:2px;
        }}
        .dashboard-grid {{ display:grid; grid-template-columns:220px 1fr; gap:30px; align-items:center; }}
        .donut-box {{ display:flex; justify-content:center; }}
        .donut-box svg {{ filter:drop-shadow(0 4px 12px rgba(0,0,0,.3)); }}
        .stat-cards {{ display:flex; gap:12px; flex-wrap:wrap; }}
        .stat-card {{
            flex:1; min-width:110px; border-radius:12px; padding:16px; text-align:center;
            border:1px solid; transition:transform .2s;
        }}
        .stat-card:hover {{ transform:translateY(-3px); }}
        .stat-card.c {{ background:rgba(239,68,68,.08); border-color:rgba(239,68,68,.3); }}
        .stat-card.h {{ background:rgba(249,115,22,.08); border-color:rgba(249,115,22,.3); }}
        .stat-card.m {{ background:rgba(234,179,8,.08); border-color:rgba(234,179,8,.3); }}
        .stat-card.l {{ background:rgba(59,130,246,.08); border-color:rgba(59,130,246,.3); }}
        .stat-card .num {{ font-size:2em; font-weight:900; }}
        .stat-card.c .num {{ color:#ef4444; }}
        .stat-card.h .num {{ color:#f97316; }}
        .stat-card.m .num {{ color:#eab308; }}
        .stat-card.l .num {{ color:#3b82f6; }}
        .stat-card .lbl {{ font-size:.7em; font-weight:700; text-transform:uppercase; letter-spacing:2px; color:var(--text-secondary); }}

        /* ===== TOOLBAR (SEARCH + FILTER) ===== */
        .toolbar {{
            padding:20px 40px; background:var(--bg-container); border-bottom:1px solid var(--border);
            position:sticky; top:0; z-index:100; backdrop-filter:blur(12px);
        }}
        .search-wrap {{ position:relative; margin-bottom:12px; }}
        .search-wrap .ico {{ position:absolute; left:14px; top:50%; transform:translateY(-50%); opacity:.45; }}
        .search-box {{
            width:100%; padding:12px 18px 12px 40px; border:2px solid var(--border); border-radius:10px;
            font-size:.95em; font-family:'Inter',sans-serif; background:var(--bg-card); color:var(--text-primary);
            transition:border-color .3s, box-shadow .3s;
        }}
        .search-box:focus {{ outline:none; border-color:#38bdf8; box-shadow:0 0 0 3px rgba(56,189,248,.15); }}
        .search-box::placeholder {{ color:var(--text-muted); }}
        .filter-row {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
        .fbtn {{
            padding:7px 16px; border:2px solid var(--border); border-radius:8px;
            background:var(--bg-card); color:var(--text-secondary); cursor:pointer;
            font-weight:700; font-size:.8em; font-family:'Inter',sans-serif; transition:all .2s;
        }}
        .fbtn:hover {{ transform:translateY(-1px); }}
        .fbtn.active {{ color:#fff !important; }}
        .fbtn.fa {{ border-color:#38bdf8; color:#38bdf8; }}
        .fbtn.fa.active {{ background:#38bdf8; }}
        .fbtn.fc {{ border-color:#ef4444; color:#ef4444; }}
        .fbtn.fc.active {{ background:#ef4444; }}
        .fbtn.fh {{ border-color:#f97316; color:#f97316; }}
        .fbtn.fh.active {{ background:#f97316; }}
        .fbtn.fm {{ border-color:#eab308; color:#eab308; }}
        .fbtn.fm.active {{ background:#eab308; }}
        .fbtn.fl {{ border-color:#3b82f6; color:#3b82f6; }}
        .fbtn.fl.active {{ background:#3b82f6; }}
        .fstatus {{ margin-left:auto; font-weight:600; font-size:.85em; color:var(--text-muted); }}
        .btn-grp {{ display:flex; gap:6px; margin-left:12px; }}
        .btn {{
            padding:7px 14px; border:none; border-radius:6px; cursor:pointer;
            font-weight:700; font-size:.78em; font-family:'Inter',sans-serif; transition:all .2s;
        }}
        .btn-exp {{ background:#3b82f6; color:#fff; }}
        .btn-col {{ background:#475569; color:#fff; }}
        .btn:hover {{ filter:brightness(1.15); }}

        /* ===== FINDINGS LIST ===== */
        .findings {{ padding:28px 40px; }}
        .finding-wrapper {{ margin-bottom:10px; }}
        .finding-collapsed {{
            background:var(--bg-card); border:1px solid var(--border); border-left:5px solid;
            border-radius:10px; padding:14px 18px; cursor:pointer; transition:all .25s;
        }}
        .finding-collapsed:hover {{ background:var(--bg-card-hover); transform:translateX(3px); box-shadow:0 4px 12px rgba(0,0,0,.15); }}
        .finding-collapsed.critical {{ border-left-color:#ef4444; }}
        .finding-collapsed.high {{ border-left-color:#f97316; }}
        .finding-collapsed.medium {{ border-left-color:#eab308; }}
        .finding-collapsed.low {{ border-left-color:#3b82f6; }}
        .fhdr {{ display:flex; align-items:center; gap:12px; }}
        .exp-ico {{ font-size:.85em; transition:transform .3s; color:var(--text-muted); flex-shrink:0; }}
        .exp-ico.expanded {{ transform:rotate(90deg); }}
        .fnum {{ font-weight:800; font-size:.9em; color:var(--text-muted); font-family:'JetBrains Mono',monospace; flex-shrink:0; }}
        .ftitle {{ flex:1; font-weight:700; font-size:1em; color:var(--text-primary); }}
        .severity-badge {{
            padding:4px 12px; border-radius:6px; font-weight:800; font-size:.7em;
            text-transform:uppercase; letter-spacing:1.5px; flex-shrink:0;
        }}
        .severity-badge.critical {{ background:#ef4444; color:#fff; }}
        .severity-badge.high {{ background:#f97316; color:#fff; }}
        .severity-badge.medium {{ background:#eab308; color:#1e293b; }}
        .severity-badge.low {{ background:#3b82f6; color:#fff; }}

        .finding-details {{ margin-top:4px; animation:slideDown .3s ease-out; }}
        .finding {{
            background:var(--bg-card); border:1px solid var(--border); border-left:5px solid;
            border-radius:10px; padding:22px;
        }}
        .finding.critical {{ border-left-color:#ef4444; background:var(--card-critical); }}
        .finding.high {{ border-left-color:#f97316; background:var(--card-high); }}
        .finding.medium {{ border-left-color:#eab308; background:var(--card-medium); }}
        .finding.low {{ border-left-color:#3b82f6; background:var(--card-low); }}

        .finding-meta {{
            display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
            gap:10px; margin:12px 0; padding:14px; background:var(--bg-meta);
            border-radius:8px; border:1px solid var(--border);
        }}
        .meta-label {{ font-size:.68em; color:var(--text-muted); text-transform:uppercase; letter-spacing:1.5px; font-weight:700; margin-bottom:3px; }}
        .meta-value {{ font-size:.9em; color:var(--text-primary); font-weight:600; font-family:'JetBrains Mono',monospace; }}

        /* ===== COLLAPSIBLE SECTIONS ===== */
        .collapsible-section {{ margin:10px 0; border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
        .collapsible-header {{
            padding:10px 14px; background:var(--bg-meta); cursor:pointer;
            display:flex; justify-content:space-between; align-items:center;
            user-select:none; transition:background .2s;
        }}
        .collapsible-header:hover {{ filter:brightness(1.1); }}
        .collapsible-header .section-title {{ margin:0; font-size:.88em; }}
        .collapsible-icon {{ font-size:.72em; transition:transform .2s; color:var(--text-muted); }}
        .collapsible-icon.expanded {{ transform:rotate(90deg); }}
        .collapsible-content {{ padding:14px; display:none; }}
        .collapsible-content.expanded {{ display:block; }}
        .section-title {{
            font-size:.9em; font-weight:800; padding-left:10px; border-left:3px solid #3b82f6;
            letter-spacing:1px; text-transform:uppercase;
        }}
        .section-title.exploitation {{ border-left-color:#ef4444; color:#f87171; }}
        .section-title.attack-flow {{ border-left-color:#f97316; color:#fb923c; }}
        .section-title.impact {{ border-left-color:#a855f7; color:#a78bfa; }}
        .section-title.remediation {{ border-left-color:#10b981; color:#4ade80; }}
        .section-content ul {{ list-style:none; padding:0; }}
        .section-content li {{
            padding:7px 0 7px 26px; position:relative; border-bottom:1px solid var(--border);
            color:var(--text-primary); font-size:.9em;
        }}
        .section-content li:last-child {{ border-bottom:none; }}
        .section-content li:before {{ content:"›"; position:absolute; left:8px; color:#38bdf8; font-weight:bold; }}
        .exploitation li:before {{ color:#f87171; }}
        .attack-flow li:before {{ color:#fb923c; }}
        .section-content {{ color:var(--text-primary); line-height:1.7; }}

        /* ===== CODE BLOCKS + COPY ===== */
        .code-wrap {{ position:relative; margin:10px 0; }}
        .copy-btn {{
            position:absolute; top:8px; right:8px;
            background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.15);
            color:#94a3b8; padding:4px 10px; border-radius:5px; cursor:pointer;
            font-size:.72em; font-family:'Inter',sans-serif; font-weight:600; transition:all .2s; z-index:5;
        }}
        .copy-btn:hover {{ background:rgba(56,189,248,.15); color:#38bdf8; border-color:#38bdf8; }}
        .copy-btn.copied {{ background:rgba(74,222,128,.15); color:#4ade80; border-color:#4ade80; }}
        .code-block {{
            background:var(--code-bg); color:#e2e8f0; padding:18px; padding-top:36px;
            border-radius:6px; font-family:'JetBrains Mono','Courier New',monospace;
            font-size:.82em; overflow-x:auto; white-space:pre-wrap; line-height:1.65;
            border:1px solid rgba(56,189,248,.12);
        }}
        .code-block .comment {{ color:#64748b; }}
        .code-block .command {{ color:#4ade80; }}
        .code-block .output {{ color:#60a5fa; }}

        /* ===== EXPLOIT RESULTS ===== */
        .exploit-result {{
            background:rgba(239,68,68,.07); border:1px solid #ef4444;
            border-radius:10px; padding:18px; margin:12px 0;
        }}
        .exploit-result h4 {{ color:#f87171; font-size:1.05em; margin-bottom:10px; display:flex; align-items:center; }}
        .exploit-result h4:before {{ content:"⚠"; margin-right:8px; font-size:1.2em; }}
        .evidence-item {{
            background:var(--bg-card); padding:10px; border-radius:6px; margin:6px 0;
            border-left:3px solid #ef4444;
        }}
        .evidence-label {{ font-weight:700; color:#f87171; margin-bottom:4px; }}
        .evidence-data {{
            font-family:'JetBrains Mono',monospace; background:var(--code-bg);
            padding:8px; border-radius:4px; font-size:.82em; white-space:pre-wrap;
            word-break:break-all; color:var(--text-primary);
        }}

        /* ===== FOOTER ===== */
        .footer {{
            background:var(--bg-body); color:var(--text-muted); padding:28px;
            text-align:center; border-top:1px solid var(--border); font-size:.88em;
        }}

        @keyframes slideDown {{ from {{ opacity:0; max-height:0; }} to {{ opacity:1; max-height:8000px; }} }}

        /* ===== RESPONSIVE ===== */
        @media (max-width:768px) {{
            .dashboard-grid {{ grid-template-columns:1fr; }}
            .stat-cards {{ flex-direction:column; }}
            .toolbar,.findings,.dashboard {{ padding-left:16px; padding-right:16px; }}
            .header {{ padding:28px 16px; }}
            .header h1 {{ font-size:2em; }}
            .fhdr {{ flex-wrap:wrap; }}
        }}

        /* ===== PRINT / PDF ===== */
        @media print {{
            body {{ background:#fff !important; color:#1e293b !important; }}
            .container {{ box-shadow:none !important; }}
            .theme-toggle, .copy-btn, .btn-grp, .search-wrap, .fbtn, .toolbar {{ display:none !important; }}
            .finding-details {{ display:block !important; }}
            .collapsible-content {{ display:block !important; }}
            .finding, .summary-box, .stat-card {{
                box-shadow:none !important; background:#fff !important; border:1px solid #ccc !important;
            }}
            .code-block {{ background:#f4f4f4 !important; color:#1e293b !important; border:1px solid #ccc !important; }}
            .severity-badge, .stat-card .num {{ -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; }}
            .finding-wrapper {{ break-inside:avoid; page-break-inside:avoid; }}
            .header {{ -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; }}
        }}
    </style>
    <script>
        /* Theme Toggle */
        function toggleTheme() {{
            var h = document.documentElement, b = document.getElementById('tbtn');
            if (h.getAttribute('data-theme')==='dark') {{ h.setAttribute('data-theme','light'); b.textContent='\U0001F319'; }}
            else {{ h.setAttribute('data-theme','dark'); b.textContent='\u2600\uFE0F'; }}
        }}

        /* Search + Filter */
        var curFilter='all', curSearch='';
        function applyFilters() {{
            var ws=document.querySelectorAll('.finding-wrapper'), v=0;
            ws.forEach(function(w) {{
                var sev=w.getAttribute('data-severity');
                var txt=(w.getAttribute('data-search')||'').toLowerCase();
                var sm=(curFilter==='all'||sev===curFilter);
                var xm=(!curSearch||txt.indexOf(curSearch)!==-1);
                if(sm&&xm){{ w.style.display='block'; v++; }} else {{ w.style.display='none'; }}
            }});
            document.getElementById('fcount').textContent=
                curFilter==='all'&&!curSearch ? 'Showing all '+ws.length+' findings' : 'Showing '+v+' of '+ws.length+' findings';
        }}
        function doFilter(sev,btn) {{
            curFilter=sev;
            document.querySelectorAll('.fbtn').forEach(function(b){{ b.classList.remove('active'); }});
            btn.classList.add('active');
            applyFilters();
        }}
        function doSearch(v) {{ curSearch=v.toLowerCase(); applyFilters(); }}

        /* Card Toggle */
        function toggleFinding(id) {{
            var d=document.getElementById('details-'+id), ic=document.getElementById('icon-'+id);
            if(d.style.display==='none'||d.style.display==='') {{ d.style.display='block'; ic.classList.add('expanded'); }}
            else {{ d.style.display='none'; ic.classList.remove('expanded'); }}
        }}
        function toggleSection(sid) {{
            var c=document.getElementById(sid), ic=c.previousElementSibling.querySelector('.collapsible-icon');
            if(c.style.display==='none'||c.style.display==='') {{ c.style.display='block'; if(ic) ic.classList.add('expanded'); }}
            else {{ c.style.display='none'; if(ic) ic.classList.remove('expanded'); }}
        }}
        function expandAll() {{
            document.querySelectorAll('.finding-details').forEach(function(e){{ e.style.display='block'; }});
            document.querySelectorAll('.exp-ico').forEach(function(e){{ e.classList.add('expanded'); }});
        }}
        function collapseAll() {{
            document.querySelectorAll('.finding-details').forEach(function(e){{ e.style.display='none'; }});
            document.querySelectorAll('.exp-ico').forEach(function(e){{ e.classList.remove('expanded'); }});
        }}

        /* Copy to Clipboard */
        function copyCode(btn,id) {{
            var code=document.getElementById(id).innerText;
            navigator.clipboard.writeText(code).then(function() {{
                btn.textContent='\u2713 Copied!'; btn.classList.add('copied');
                setTimeout(function(){{ btn.textContent='\u29C9 Copy'; btn.classList.remove('copied'); }},2000);
            }});
        }}

        window.onload=function(){{ applyFilters(); }};
    </script>
</head>
<body>
    <button class="theme-toggle" id="tbtn" onclick="toggleTheme()" title="Toggle Dark/Light Mode">&#9728;&#65039;</button>
    <div class="container">
        <div class="header">
            <h1>K8SCAN</h1>
            <p class="subtitle">Kubernetes Security Assessment Report</p>
            <p class="ts">{timestamp}</p>
        </div>

        <!-- EXECUTIVE DASHBOARD -->
        <div class="dashboard">
            <h2>Severity Distribution</h2>
            <div class="dashboard-grid">
                <div class="donut-box">
                    <svg viewBox="0 0 200 200" width="200" height="200">
                        <circle cx="100" cy="100" r="70" fill="none" stroke="#334155" stroke-width="28"/>
                        <circle cx="100" cy="100" r="70" fill="none" stroke="#ef4444" stroke-width="28"
                            stroke-dasharray="{d_crit} {d_crit_r}" stroke-dashoffset="0" transform="rotate(-90 100 100)"/>
                        <circle cx="100" cy="100" r="70" fill="none" stroke="#f97316" stroke-width="28"
                            stroke-dasharray="{d_high} {d_high_r}" stroke-dashoffset="-{d_off_h}" transform="rotate(-90 100 100)"/>
                        <circle cx="100" cy="100" r="70" fill="none" stroke="#eab308" stroke-width="28"
                            stroke-dasharray="{d_med} {d_med_r}" stroke-dashoffset="-{d_off_m}" transform="rotate(-90 100 100)"/>
                        <circle cx="100" cy="100" r="70" fill="none" stroke="#3b82f6" stroke-width="28"
                            stroke-dasharray="{d_low} {d_low_r}" stroke-dashoffset="-{d_off_l}" transform="rotate(-90 100 100)"/>
                        <circle cx="100" cy="100" r="70" fill="none" stroke="#06b6d4" stroke-width="28"
                            stroke-dasharray="{d_info} {d_info_r}" stroke-dashoffset="-{d_off_i}" transform="rotate(-90 100 100)"/>
                        <text x="100" y="93" text-anchor="middle" fill="currentColor" font-size="26" font-weight="900" font-family="Inter">{total}</text>
                        <text x="100" y="115" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600" font-family="Inter">FINDINGS</text>
                    </svg>
                </div>
                <div class="stat-cards">
                    <div class="stat-card c"><div class="num">{critical}</div><div class="lbl">Critical</div></div>
                    <div class="stat-card h"><div class="num">{high}</div><div class="lbl">High</div></div>
                    <div class="stat-card m"><div class="num">{medium}</div><div class="lbl">Medium</div></div>
                    <div class="stat-card l"><div class="num">{low}</div><div class="lbl">Low</div></div>
                    <div class="stat-card i"><div class="num">{info}</div><div class="lbl">Info</div></div>
                </div>
            </div>
        </div>

        <!-- TOOLBAR -->
        <div class="toolbar">
            <div class="search-wrap">
                <span class="ico">&#128269;</span>
                <input type="text" class="search-box" placeholder="Search by pod name, vulnerability title, namespace..." oninput="doSearch(this.value)"/>
            </div>
            <div class="filter-row">
                <button class="fbtn fa active" onclick="doFilter('all',this)">All</button>
                <button class="fbtn fc" onclick="doFilter('critical',this)">Critical</button>
                <button class="fbtn fh" onclick="doFilter('high',this)">High</button>
                <button class="fbtn fm" onclick="doFilter('medium',this)">Medium</button>
                <button class="fbtn fl" onclick="doFilter('low',this)">Low</button>
                <button class="fbtn fi" onclick="doFilter('info',this)">Info</button>
                <span class="fstatus" id="fcount"></span>
                <div class="btn-grp">
                    <button class="btn btn-exp" onclick="expandAll()">Expand All</button>
                    <button class="btn btn-col" onclick="collapseAll()">Collapse All</button>
                </div>
            </div>
        </div>

        <!-- FINDINGS -->
        <div class="findings">
            {findings_html}
        </div>

        <div class="footer">
            <p>Generated by K8SCAN &mdash; Kubernetes Security Scanner</p>
            <p style="margin-top:6px;">Total Findings: {total}</p>
        </div>
    </div>
</body>
</html>
"""
        
        from datetime import datetime
        summary = self._calculate_summary(findings)
        
        # Donut chart math (circumference = 2*pi*70 = 439.82)
        circ = 439.82
        t = summary['total'] or 1
        d_crit = round((summary['critical'] / t) * circ, 2)
        d_high = round((summary['high'] / t) * circ, 2)
        d_med  = round((summary['medium'] / t) * circ, 2)
        d_low  = round((summary['low'] / t) * circ, 2)
        d_info = round((summary['info'] / t) * circ, 2)
        
        findings_html = ""
        for i, finding in enumerate(sorted(findings, key=lambda x: x.severity_score, reverse=True), 1):
            severity_class = finding.severity.lower()
            search_data = f"{finding.title} {finding.resource_name} {finding.namespace or ''} {finding.category} {finding.description}".replace('"', '&quot;')
            
            # PROOF OF CONCEPT
            poc_html = ""
            if hasattr(finding, 'proof_of_concept') and finding.proof_of_concept:
                poc_html = f"""
                <div class="collapsible-section">
                    <div class="collapsible-header" onclick="toggleSection('poc-{i}')">
                        <div class="section-title">💻 PROOF OF CONCEPT</div>
                        <span class="collapsible-icon">▶</span>
                    </div>
                    <div class="collapsible-content" id="poc-{i}">
                        <div class="code-wrap">
                            <button class="copy-btn" onclick="event.stopPropagation();copyCode(this,'code-{i}')">⧉ Copy</button>
                            <div class="code-block" id="code-{i}">{finding.proof_of_concept.replace('<', '&lt;').replace('>', '&gt;')}</div>
                        </div>
                    </div>
                </div>
                """
            
            exploitation_html = ""
            if finding.exploitation:
                exploitation_html = f"""
                <div class="collapsible-section">
                    <div class="collapsible-header" onclick="toggleSection('exploit-{i}')">
                        <div class="section-title exploitation">🔓 EXPLOITATION</div>
                        <span class="collapsible-icon">▶</span>
                    </div>
                    <div class="collapsible-content" id="exploit-{i}">
                        <ul>
                            {"".join([f"<li>{exp}</li>" for exp in finding.exploitation])}
                        </ul>
                    </div>
                </div>
                """
            
            attack_flow_html = ""
            if finding.attack_flow:
                attack_flow_html = f"""
                <div class="collapsible-section">
                    <div class="collapsible-header" onclick="toggleSection('flow-{i}')">
                        <div class="section-title attack-flow">⚔️ ATTACK FLOW</div>
                        <span class="collapsible-icon">▶</span>
                    </div>
                    <div class="collapsible-content" id="flow-{i}">
                        <ul class="attack-flow">
                            {"".join([f"<li>{step}</li>" for step in finding.attack_flow])}
                        </ul>
                    </div>
                </div>
                """
            
            impact_html = ""
            if finding.impact:
                impact_html = f"""
                <div class="collapsible-section">
                    <div class="collapsible-header" onclick="toggleSection('impact-{i}')">
                        <div class="section-title impact">💥 IMPACT</div>
                        <span class="collapsible-icon">▶</span>
                    </div>
                    <div class="collapsible-content" id="impact-{i}">
                        {finding.impact}
                    </div>
                </div>
                """
            
            exploit_results_html = ""
            if exploit_results:
                for exploit_result in exploit_results:
                    if exploit_result.get('finding_id') == finding.finding_id and exploit_result.get('exploited'):
                        evidence_html = ""
                        for evidence in exploit_result.get('evidence', []):
                            evidence_html += f"""
                            <div class="evidence-item">
                                <div class="evidence-label">{evidence.get('type', 'Evidence')}</div>
                                <div class="evidence-data">{evidence.get('data', '')}</div>
                            </div>
                            """
                        
                        commands_html = ""
                        for cmd in exploit_result.get('commands_executed', []):
                            commands_html += f"""
                            <div class="code-block">
                                <div style="color:#4ade80;margin-bottom:8px;">$ {cmd.get('command', '')}</div>
                                <div style="color:#94a3b8;">{cmd.get('output', '')[:300]}</div>
                            </div>
                            """
                        
                        exploit_results_html = f"""
                        <div class="exploit-result">
                            <h4>EXPLOITATION SUCCESSFUL</h4>
                            {evidence_html}
                            <div style="margin-top:15px;">
                                <strong>Commands Executed:</strong>
                                {commands_html}
                            </div>
                        </div>
                        """
            
            findings_html += f"""
            <div class="finding-wrapper" data-severity="{severity_class}" data-search="{search_data}">
                <div class="finding-collapsed {severity_class}" onclick="toggleFinding({i})">
                    <div class="fhdr">
                        <span class="exp-ico" id="icon-{i}">▶</span>
                        <span class="fnum">#{i}</span>
                        <span class="ftitle">{finding.title}</span>
                        <span class="severity-badge {severity_class}">{finding.severity}</span>
                    </div>
                </div>
                
                <div class="finding-details" id="details-{i}" style="display: none;">
                    <div class="finding {severity_class}">
                        <div class="finding-meta">
                            <div class="meta-item">
                                <span class="meta-label">Category</span>
                                <span class="meta-value">{finding.category}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Resource</span>
                                <span class="meta-value">{finding.resource_type}/{finding.resource_name}</span>
                            </div>
                            {f'<div class="meta-item"><span class="meta-label">Namespace</span><span class="meta-value">{finding.namespace}</span></div>' if finding.namespace else ''}
                        </div>
                        
                        <div class="section-content" style="margin:15px 0;">
                            <strong>Description:</strong> {finding.description}
                        </div>
                        
                        {exploitation_html}
                        {poc_html}
                        {attack_flow_html}
                        {impact_html}
                        {exploit_results_html}
                        
                        <div class="collapsible-section">
                            <div class="collapsible-header" onclick="toggleSection('remediation-{i}')">
                                <div class="section-title remediation">🔧 REMEDIATION</div>
                                <span class="collapsible-icon">▶</span>
                            </div>
                            <div class="collapsible-content" id="remediation-{i}">
                                {finding.remediation}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            """
        
        html = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            critical=summary['critical'],
            high=summary['high'],
            medium=summary['medium'],
            low=summary['low'],
            info=summary['info'],
            total=summary['total'],
            findings_html=findings_html,
            d_crit=d_crit,
            d_crit_r=round(circ - d_crit, 2),
            d_high=d_high,
            d_high_r=round(circ - d_high, 2),
            d_med=d_med,
            d_med_r=round(circ - d_med, 2),
            d_low=d_low,
            d_low_r=round(circ - d_low, 2),
            d_info=d_info,
            d_info_r=round(circ - d_info, 2),
            d_off_h=d_crit,
            d_off_m=round(d_crit + d_high, 2),
            d_off_l=round(d_crit + d_high + d_med, 2),
            d_off_i=round(d_crit + d_high + d_med + d_low, 2),
        )
        
        return html
    
    def export_html(self, findings, filename, exploit_results=None):
        """Export findings as an HTML report."""
        html = self._build_html(findings, exploit_results)
        
        with open(filename, 'w') as f:
            f.write(html)
        
        self.console.print(f"[green]✓ HTML report exported to {filename}[/green]")
    
    def export_pdf(self, findings, filename, exploit_results=None):
        """Export findings as a PDF report. Requires weasyprint (pip install weasyprint)."""
        html = self._build_html(findings, exploit_results)
        
        # Force light theme + expand all + hide interactive elements for PDF
        html = html.replace('data-theme="dark"', 'data-theme="light"')
        
        try:
            import os
            import sys
            import logging
            import warnings
            
            # Suppress weasyprint python logs
            logging.getLogger('weasyprint').setLevel(logging.ERROR)
            
            # Save original stdout and stderr file descriptors
            original_stdout_fd = os.dup(1)
            original_stderr_fd = os.dup(2)
            
            # Open /dev/null to redirect C-level output
            devnull_fd = os.open(os.devnull, os.O_WRONLY)
            
            # Redirect stdout and stderr (fd 1 and 2) to devnull
            os.dup2(devnull_fd, 1)
            os.dup2(devnull_fd, 2)
            
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    
                    # Also redirect python-level sys.stdout and sys.stderr just in case
                    with open(os.devnull, 'w') as f:
                        old_out = sys.stdout
                        old_err = sys.stderr
                        sys.stdout = f
                        sys.stderr = f
                        try:
                            from weasyprint import HTML as WeasyHTML
                            WeasyHTML(string=html).write_pdf(filename)
                        finally:
                            sys.stdout = old_out
                            sys.stderr = old_err
                
                # Restore descriptors
                os.dup2(original_stdout_fd, 1)
                os.dup2(original_stderr_fd, 2)
                os.close(devnull_fd)
                os.close(original_stdout_fd)
                os.close(original_stderr_fd)
                
                self.console.print(f"[green]✓ PDF report exported to {filename}[/green]")
            except Exception:
                # Restore descriptors
                os.dup2(original_stdout_fd, 1)
                os.dup2(original_stderr_fd, 2)
                os.close(devnull_fd)
                os.close(original_stdout_fd)
                os.close(original_stderr_fd)
                raise ImportError("Forced fail for fallback")
                
        except (ImportError, OSError):
            pass
    
    def _calculate_summary(self, findings):
        summary = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
