"""
Secure Report Server (HTTPS)
- Self-signed TLS certificate (auto-generated)
- Secret token authentication
- Auto-shuts down after 30 minutes OR after a successful download
"""

import http.server
import ssl
import threading
import secrets
import os
import sys
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs


def _generate_self_signed_cert(cert_dir):
    """Generate a self-signed TLS certificate using openssl CLI."""
    cert_file = os.path.join(cert_dir, 'k8scan.pem')
    key_file = os.path.join(cert_dir, 'k8scan-key.pem')

    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key_file,
        '-out', cert_file,
        '-days', '1',
        '-nodes',
        '-subj', '/CN=k8scan-report/O=k8scan',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], capture_output=True, check=True)

    return cert_file, key_file


class ReportHandler(http.server.BaseHTTPRequestHandler):
    """HTTPS handler that serves reports only with a valid secret token."""

    secret = None
    allowed_files = {}
    shutdown_event = None
    download_count = 0
    protocol = 'https'

    def log_message(self, format, *args):
        sys.stderr.write(f"[serve] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.strip('/')
        params = parse_qs(parsed.query)
        token = params.get('token', [None])[0]

        # Root → landing page
        if not path or path == '':
            self._serve_landing(token)
            return

        # Validate token
        if token != self.__class__.secret:
            self.send_error(403, "Invalid or missing token")
            self.log_message("BLOCKED: invalid token for %s", path)
            return

        # Check file
        if path not in self.__class__.allowed_files:
            self.send_error(404, "File not found")
            return

        filepath = self.__class__.allowed_files[path]
        if not os.path.exists(filepath):
            self.send_error(404, "Report file not found on disk")
            return

        # Content type
        ct_map = {
            '.html': ('text/html; charset=utf-8', 'inline'),
            '.json': ('application/json; charset=utf-8', 'attachment'),
            '.pdf':  ('application/pdf', 'attachment'),
        }
        ext = os.path.splitext(path)[1]
        content_type, disposition = ct_map.get(ext, ('application/octet-stream', 'attachment'))

        with open(filepath, 'rb') as f:
            data = f.read()

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Disposition', f'{disposition}; filename="{path}"')
        self.send_header('Cache-Control', 'no-store, no-cache')
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.end_headers()
        self.wfile.write(data)

        self.log_message("DOWNLOADED: %s (%d bytes)", path, len(data))

        self.__class__.download_count += 1
        self.log_message("Download %d complete. Scheduling shutdown...", self.__class__.download_count)
        threading.Timer(2.0, self._trigger_shutdown).start()

    def _trigger_shutdown(self):
        if self.__class__.shutdown_event:
            self.__class__.shutdown_event.set()

    def _serve_landing(self, token):
        proto = self.__class__.protocol

        if token != self.__class__.secret:
            html = """<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>K8SCAN Report Server</title>
            <style>
            body{font-family:-apple-system,sans-serif;background:#0b1120;color:#f1f5f9;display:flex;
            align-items:center;justify-content:center;min-height:100vh;margin:0;}
            .box{text-align:center;padding:40px;border:1px solid #334155;border-radius:16px;background:#1e293b;max-width:450px;}
            h1{color:#ef4444;margin-bottom:12px;font-size:1.5em;}
            p{color:#94a3b8;font-size:.9em;}
            code{background:#0f172a;padding:3px 8px;border-radius:4px;font-size:.85em;color:#38bdf8;}
            .lock{font-size:2.5em;margin-bottom:16px;}
            </style></head><body>
            <div class="box">
            <div class="lock">&#128274;</div>
            <h1>Access Denied</h1>
            <p>A valid secret token is required.</p>
            <p style="margin-top:16px;">Add <code>?token=YOUR_SECRET</code> to the URL</p>
            </div></body></html>"""
            self.send_response(403)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
            return

        # Valid token — download links
        files_html = ""
        for basename in sorted(self.__class__.allowed_files.keys()):
            icons = {'.html': '🌐', '.json': '📋', '.pdf': '📑'}
            ext = os.path.splitext(basename)[1]
            icon = icons.get(ext, '📄')

            size = os.path.getsize(self.__class__.allowed_files[basename])
            size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"

            files_html += f"""
            <a href="/{basename}?token={token}" class="file-link">
                <span class="icon">{icon}</span>
                <div class="info">
                    <span class="name">{basename}</span>
                    <span class="size">{size_str}</span>
                </div>
                <span class="dl">Download &#8595;</span>
            </a>"""

        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>K8SCAN Report Server</title>
        <style>
        body{{font-family:'Inter',-apple-system,sans-serif;background:#0b1120;color:#f1f5f9;
        display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}}
        .box{{padding:40px;border:1px solid #334155;border-radius:16px;background:#1e293b;
        min-width:400px;max-width:500px;}}
        h1{{font-size:1.5em;margin-bottom:6px;}}
        h1 span{{background:linear-gradient(135deg,#38bdf8,#a78bfa);-webkit-background-clip:text;
        -webkit-text-fill-color:transparent;}}
        .sub{{color:#64748b;font-size:.85em;margin-bottom:20px;}}
        .tls-badge{{display:inline-flex;align-items:center;gap:6px;background:rgba(74,222,128,.1);
        border:1px solid rgba(74,222,128,.3);border-radius:6px;padding:4px 10px;font-size:.75em;
        color:#4ade80;font-weight:700;letter-spacing:1px;margin-bottom:16px;}}
        .warn{{background:rgba(234,179,8,.1);border:1px solid rgba(234,179,8,.3);border-radius:8px;
        padding:10px 14px;margin-bottom:20px;font-size:.8em;color:#eab308;}}
        .file-link{{display:flex;align-items:center;gap:14px;padding:14px 16px;margin:8px 0;
        border:1px solid #334155;border-radius:10px;text-decoration:none;color:#f1f5f9;
        transition:all .2s;cursor:pointer;}}
        .file-link:hover{{background:#263248;border-color:#38bdf8;transform:translateX(4px);}}
        .icon{{font-size:1.5em;}}
        .info{{flex:1;display:flex;flex-direction:column;gap:2px;}}
        .name{{font-weight:700;font-size:.95em;}}
        .size{{font-size:.75em;color:#64748b;}}
        .dl{{font-size:.8em;color:#38bdf8;font-weight:600;}}
        </style></head><body>
        <div class="box">
            <h1>&#128274; <span>K8SCAN</span> Reports</h1>
            <p class="sub">Secure report download portal</p>
            <div class="tls-badge">&#128272; {'TLS ENCRYPTED' if proto == 'https' else 'HTTP'}</div>
            <div class="warn">&#9888; Server will shut down after download or in 30 minutes.</div>
            {files_html}
        </div></body></html>"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))


def serve_reports(report_files, host='0.0.0.0', port=8199, timeout_minutes=30):
    """
    Start a secure HTTPS server to serve report files.

    - Auto-generates a self-signed TLS certificate
    - Requires secret token to download
    - Shuts down after download or timeout
    """
    secret = secrets.token_urlsafe(24)

    # Build allowed files
    allowed = {}
    for filepath in report_files:
        if os.path.exists(filepath):
            allowed[os.path.basename(filepath)] = os.path.abspath(filepath)

    if not allowed:
        print("[!] No report files found to serve.")
        return None, None

    # Configure handler
    ReportHandler.secret = secret
    ReportHandler.allowed_files = allowed
    ReportHandler.download_count = 0

    shutdown_event = threading.Event()
    ReportHandler.shutdown_event = shutdown_event

    # Generate TLS certificate
    cert_dir = tempfile.mkdtemp(prefix='k8scan_tls_')
    use_https = True
    try:
        cert_file, key_file = _generate_self_signed_cert(cert_dir)
    except Exception as e:
        print(f"[!] Could not generate TLS certificate: {e}")
        print("[!] Falling back to HTTP (not encrypted)")
        use_https = False

    # Create server
    server = http.server.HTTPServer((host, port), ReportHandler)

    if use_https:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = 'https'
        ReportHandler.protocol = 'https'
    else:
        proto = 'http'
        ReportHandler.protocol = 'http'

    server.timeout = 1

    # Print access info
    url = f"{proto}://localhost:{port}/?token={secret}"
    print()
    print("=" * 64)
    print("  K8SCAN SECURE REPORT SERVER")
    print("=" * 64)
    print()
    if use_https:
        print("  TLS:     ENABLED (self-signed certificate)")
    else:
        print("  ⚠️  TLS:     DISABLED (HTTP fallback)")
    print()
    print(f"  URL:      {url}")
    print(f"  Secret:   {secret}")
    print()
    print(f"  Files:    {len(allowed)} report(s) available")
    for name in sorted(allowed.keys()):
        size = os.path.getsize(allowed[name])
        print(f"            - {name} ({size:,} bytes)")
    print()
    print(f"  Timeout:  {timeout_minutes} minutes auto-shutdown")
    print(f"  Security: Token-auth + auto-shutdown after download")
    print()
    if use_https:
        print("  NOTE:     Browser will show a certificate warning.")
        print("            This is normal for self-signed certificates.")
        print("            Click 'Advanced' → 'Proceed' to continue.")
    print()
    print("=" * 64)
    print()
    print("[*] Waiting for download... (Ctrl+C to stop)")
    print()

    # Timeout timer
    def timeout_shutdown():
        print(f"\n[!] Server timeout ({timeout_minutes} min). Shutting down...")
        shutdown_event.set()

    timer = threading.Timer(timeout_minutes * 60, timeout_shutdown)
    timer.daemon = True
    timer.start()

    # Serve
    try:
        while not shutdown_event.is_set():
            server.handle_request()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")
    finally:
        timer.cancel()
        server.server_close()
        # Cleanup TLS files
        for f in [cert_file, key_file] if use_https else []:
            try:
                os.unlink(f)
            except OSError:
                pass
        try:
            os.rmdir(cert_dir)
        except OSError:
            pass
        print("[*] Report server shut down. TLS certificates cleaned up.")

    return secret, url
