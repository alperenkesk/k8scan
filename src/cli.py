#!/usr/bin/env python3

import click
import os
from rich.console import Console
from rich.panel import Panel
from rich import box
from src.core.scanner import Scanner
from src.utils.reporter import Reporter

console = Console()

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██╗  ██╗ █████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗      ║
║   ██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║      ║
║   █████╔╝ ╚█████╔╝███████╗██║     ███████║██╔██╗ ██║      ║
║   ██╔═██╗ ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║      ║
║   ██║  ██╗╚█████╔╝███████║╚██████╗██║  ██║██║ ╚████║      ║
║   ╚═╝  ╚═╝ ╚════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝      ║
║                                                           ║
║                Kubernetes Security Scanner                ║
║                       Version 1.0.0                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""


def print_banner():
    console.print(BANNER, style="bold cyan")


class K8sScanCLI(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        
        # User entered an invalid command
        print_banner()
        console.print(f"\n[bold red]❌ Error: Unknown command '{cmd_name}'[/bold red]")
        console.print("\n[yellow]💡 Suggestions:[/yellow]")
        console.print("  • To scan your cluster: [bold cyan]./k8scan scan[/bold cyan]")
        console.print("  • To view examples:     [bold cyan]./k8scan examples[/bold cyan]")
        console.print("  • To see all commands:  [bold cyan]./k8scan --help[/bold cyan]\n")
        import sys
        sys.exit(1)


@click.command(cls=K8sScanCLI, invoke_without_command=True)
@click.pass_context
@click.version_option(version='1.0.0', prog_name='k8scan')
@click.option('-h', '--help', is_flag=True, help='Show this message and exit')
def cli(ctx, help):
    if ctx.invoked_subcommand is None:
        print_banner()
        
        console.print("\n[bold cyan]Available Commands:[/bold cyan]\n")
        console.print("  [bold]scan[/bold]         Scan cluster and generate interactive reports")
        console.print("  [bold]serve[/bold]        Start a secure localized HTTP server for sharing reports")
        console.print("  [bold]categories[/bold]   List specific vulnerability domains covered by k8scan")
        console.print("  [bold]examples[/bold]     View common workflows and command examples")
        
        console.print("\n[yellow]💡 Quick Start:[/yellow]")
        console.print("  [cyan]./k8scan scan[/cyan]")
        console.print("  [cyan]./k8scan scan --exclude-system --serve[/cyan]")
        
        console.print("\n[dim]Need help with a specific command? Run:[/dim] [bold]./k8scan COMMAND --help[/bold]\n")


@cli.command(name='scan')
@click.option('--output-file', '-f',
              default=None,
              help='Output filename (without extension). Auto-generated if not provided.')
@click.option('--severity', '-s',
              type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'ALL']),
              default='ALL',
              help='Filter by severity level')
@click.option('--namespace', '-n',
              help='Filter by namespace')
@click.option('--category', '-c',
              help='Filter by category')
@click.option('--exclude-system',
              is_flag=True,
              help='Exclude system namespaces (kube-system, kube-public, kube-node-lease)')
@click.option('--top', '-t',
              type=int,
              help='Show only top N findings by severity')
@click.option('--serve',
              is_flag=True, default=False,
              help='Start secure server to download reports after scan')
@click.option('--port', '-p',
              default=8199, type=int,
              help='Port for report server (default: 8199)')
def scan(output_file, severity, namespace, category, exclude_system, top, serve, port):
    """
    Scan Kubernetes cluster and generate HTML + JSON reports.

    Examples:

      k8scan scan                                    # Basic scan
      k8scan scan --exclude-system                   # Skip system namespaces
      k8scan scan --severity CRITICAL                # Only critical findings
      k8scan scan --top 10                           # Top 10 findings
      k8scan scan --serve                            # Scan + start download server
      k8scan scan --serve --port 9000                # Custom port
      k8scan scan -f my-report                       # Custom filename
    """

    print_banner()

    console.print("[bold cyan]Starting Kubernetes Security Scan...[/bold cyan]\n")

    try:
        from datetime import datetime

        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

        # Auto-generate filename if not provided
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{reports_dir}/k8s-scan_{timestamp}"
        elif not output_file.startswith(reports_dir + "/"):
            output_file = f"{reports_dir}/{output_file}"

        scanner = Scanner(exclude_system=exclude_system)
        findings = scanner.run_internal_scan()

        if severity != 'ALL':
            findings = [f for f in findings if f.severity == severity]

        if namespace:
            findings = [f for f in findings if f.namespace == namespace]

        if category:
            findings = [f for f in findings if category.lower() in f.category.lower()]

        if top:
            findings = sorted(findings, key=lambda x: (-x.severity_score, -getattr(x, 'cvss_score', 0)))[:top]

        console.print()
        console.print(f"[bold green]✓ Scan completed! Found {len(findings)} issues.[/bold green]\n")

        reporter = Reporter()

        # Always generate HTML + JSON
        html_file = f"{output_file}.html"
        json_file = f"{output_file}.json"

        reporter.export_html(findings, html_file)
        reporter.export_json(findings, json_file)

        # Try PDF (optional — needs weasyprint)
        pdf_file = f"{output_file}.pdf"
        reporter.export_pdf(findings, pdf_file)

        console.print(f"\n[dim]All reports saved in: {reports_dir}/[/dim]")

        # Serve reports if requested
        if serve:
            report_files = [os.path.abspath(html_file), os.path.abspath(json_file)]
            if os.path.exists(pdf_file):
                report_files.append(os.path.abspath(pdf_file))

            from src.utils.server import serve_reports
            serve_reports(report_files, port=port)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise


@cli.command(name='serve')
@click.argument('files', nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--port', '-p', default=8199, type=int, help='Port (default: 8199)')
@click.option('--timeout', '-t', default=30, type=int, help='Auto-shutdown timeout in minutes (default: 30)')
def serve(files, port, timeout):
    """Serve existing report files via secure HTTP server.

    Requires a secret token to download. Auto-shuts down after
    30 minutes or after a file is downloaded.

    Usage: ./k8scan serve reports/scan.html reports/scan.json
    """
    print_banner()

    from src.utils.server import serve_reports

    report_files = [os.path.abspath(f) for f in files]
    serve_reports(report_files, port=port, timeout_minutes=timeout)


@cli.command(name='categories')
def list_categories():
    """List all available vulnerability categories"""

    print_banner()

    categories = [
        ('Container Security', 'Privileged containers, host access, capabilities'),
        ('Secret Management', 'Exposed credentials, weak secrets'),
        ('RBAC', 'Overly permissive roles and bindings'),
        ('Network Security', 'Network policies, exposed services'),
        ('Resource Management', 'Resource limits and health probes'),
        ('Reliability', 'High availability and deployment strategies')
    ]

    console.print("\n[bold cyan]Available Categories:[/bold cyan]\n")

    for cat, desc in categories:
        console.print(f"  [bold]{cat}[/bold]")
        console.print(f"    {desc}\n")


@cli.command(name='examples')
def show_examples():
    """Show usage examples"""

    print_banner()

    examples = """
[bold cyan]Quick Start:[/bold cyan]

  k8scan scan                    Scan entire cluster
  k8scan scan --exclude-system   Skip kube-system noise

[bold cyan]Filtering Results:[/bold cyan]

  k8scan scan --severity CRITICAL          Only show critical issues
  k8scan scan --namespace default          Scan specific namespace
  k8scan scan --category "Container Security"   Filter by category
  k8scan scan --exclude-system             Skip kube-system findings
  k8scan scan --top 10                     Top 10 most severe findings

[bold cyan]Report Server:[/bold cyan]

  k8scan scan --serve                      Scan + start secure download server
  k8scan scan --serve --port 9000          Custom port
  k8scan serve report.html report.json     Serve existing files

[bold cyan]Advanced Usage:[/bold cyan]

  k8scan scan --severity CRITICAL --top 5 --serve
  k8scan scan --exclude-system -f my-report
  k8scan scan --namespace production --severity HIGH

[bold cyan]Other Commands:[/bold cyan]

  k8scan categories              List vulnerability categories
  k8scan examples                Show this help
  k8scan --version               Show version
"""

    console.print(examples)


if __name__ == '__main__':
    cli()
