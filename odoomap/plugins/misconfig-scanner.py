import re
import time
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import MINIMAL, ROUNDED, HEAVY
from rich.columns import Columns
from .plugin_base import BasePlugin, PluginMetadata, PluginCategory

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold magenta",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}


class Finding:
    def __init__(self, name, severity, status, detail, reference="", sub_findings=None):
        self.name = name
        self.severity = severity
        self.status = status
        self.detail = detail
        self.reference = reference
        self.sub_findings = sub_findings or []


class Plugin(BasePlugin):
    """Checks for known Odoo misconfigurations documented in public security resources"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Misconfiguration Scanner",
            description="Checks for known Odoo misconfigurations based on public documentation",
            author="unclej4ck",
            version="1.1.0",
            category=PluginCategory.SECURITY,
            requires_auth=False,
            requires_connection=True,
            external_dependencies=["requests", "rich"]
        )

    def run(self, target_url, database=None, username=None, password=None, connection=None):
        if not connection:
            console.print("[red][-] Connection required")
            return "Error: Connection required"

        host = connection.host
        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold] {host}\n"
            f"[bold]Database:[/bold] {database or 'not specified'}\n"
            f"[bold]Auth:[/bold] {'provided' if username else 'none'}",
            title="[bold blue]Misconfiguration Scanner[/bold blue]",
            border_style="blue"
        ))

        findings = []

        findings.append(self._check_version_leak(connection))
        findings.append(self._check_db_listing(connection))
        findings.append(self._check_db_manager(connection))
        findings.append(self._check_default_master_password(connection))
        findings.append(self._check_debug_mode(connection))
        findings.append(self._check_registration(connection))
        findings.append(self._check_xmlrpc_exposed(connection))
        findings.append(self._check_default_creds(connection, database))
        findings.append(self._check_demo_user(connection, database))
        findings.append(self._check_ssrf_link_preview(connection))
        findings.append(self._check_ssrf_livechat(connection))
        findings.append(self._check_user_enum_timing(connection, database))

        if database and username and password:
            uid = connection.authenticate(database, username, password, verbose=False)
            if uid:
                findings.append(self._check_mail_template_access(connection))

        findings = [f for f in findings if f is not None]
        self._display_findings(findings)

        vuln_count = sum(1 for f in findings if f.status == "FINDING")
        info_count = sum(1 for f in findings if f.status == "INFO")
        return f"Scan complete. {vuln_count} finding(s), {info_count} info item(s)"

    def _check_version_leak(self, connection):
        try:
            result = connection.jsonrpc("/web/webclient/version_info")
            if result:
                ver = result.get("server_version", "unknown")
                serie = result.get("server_serie", "")
                return Finding(
                    "Version Information Disclosure",
                    "LOW",
                    "FINDING",
                    f"Server version: {ver} (serie: {serie}) exposed via /web/webclient/version_info",
                    "https://www.odoo.com/documentation/19.0/developer/reference/backend/security.html"
                )
        except Exception:
            pass
        return Finding("Version Information Disclosure", "LOW", "OK", "Version endpoint not accessible")

    def _check_db_listing(self, connection):
        try:
            dbs = connection.get_databases()
            if dbs:
                db_str = ", ".join(dbs[:5])
                extra = f" (+{len(dbs)-5} more)" if len(dbs) > 5 else ""
                return Finding(
                    "Database Listing Enabled",
                    "MEDIUM",
                    "FINDING",
                    f"Databases exposed: {db_str}{extra}",
                    "Odoo docs: set list_db=False in odoo.conf"
                )
        except Exception:
            pass
        return Finding("Database Listing Enabled", "MEDIUM", "OK", "Database listing is disabled or blocked")

    def _check_db_manager(self, connection):
        try:
            url = f"{connection.host}/web/database/manager"
            resp = connection.session.get(url, timeout=10)
            if resp.status_code == 200 and ("database" in resp.text.lower() and "manager" in resp.text.lower()):
                return Finding(
                    "Database Manager Exposed",
                    "HIGH",
                    "FINDING",
                    f"Database manager accessible — allows backup/restore/delete operations",
                    "CVE-2018-14885, Odoo docs: disable with list_db=False or block at reverse proxy"
                )
        except Exception:
            pass
        return Finding("Database Manager Exposed", "HIGH", "OK", "Database manager not accessible")

    def _check_default_master_password(self, connection):
        candidates = ["", "admin", "odoo", "master"]
        try:
            for pwd in candidates:
                try:
                    url = f"{connection.host}/web/database/list"
                    payload = {
                        "jsonrpc": "2.0",
                        "method": "call",
                        "params": {"master_pwd": pwd} if pwd else {}
                    }
                    resp = connection.session.post(url, json=payload, timeout=10)
                    if resp.status_code == 200:
                        body = resp.json()
                        if "result" in body and isinstance(body["result"], list):
                            pwd_display = f"'{pwd}'" if pwd else "(empty)"
                            return Finding(
                                "Default/Weak Master Password",
                                "CRITICAL",
                                "FINDING",
                                f"Master password accepted: {pwd_display}",
                                "Odoo docs: set strong admin_passwd in odoo.conf"
                            )
                except Exception:
                    continue
        except Exception:
            pass
        return Finding("Default/Weak Master Password", "CRITICAL", "OK",
                       "Default master passwords rejected or DB manager not accessible")

    def _check_debug_mode(self, connection):
        try:
            url = f"{connection.host}/web?debug=1"
            resp = connection.session.get(url, timeout=10, allow_redirects=True)
            if resp.status_code == 200 and "debug" in resp.url:
                return Finding(
                    "Debug Mode Accessible",
                    "LOW",
                    "INFO",
                    "Debug mode can be activated via ?debug=1",
                    "Odoo security best practices: disable debug in production"
                )
        except Exception:
            pass
        return Finding("Debug Mode Accessible", "LOW", "OK", "Debug mode check inconclusive")

    def _check_registration(self, connection):
        try:
            url = f"{connection.host}/web/signup"
            resp = connection.session.get(url, timeout=10)
            if resp.status_code == 200 and "name=\"login\"" in resp.text:
                return Finding(
                    "Open User Registration",
                    "MEDIUM",
                    "FINDING",
                    "Self-registration enabled — anyone can create portal accounts",
                    "auth_signup module: restrict or disable if not needed"
                )
        except Exception:
            pass
        return Finding("Open User Registration", "MEDIUM", "OK", "Self-registration not detected")

    def _check_xmlrpc_exposed(self, connection):
        try:
            version = connection.common.version()
            if version:
                return Finding(
                    "XML-RPC Externally Accessible",
                    "LOW",
                    "INFO",
                    "XML-RPC /xmlrpc/2/common responds — consider blocking at reverse proxy",
                    "Odoo deployment docs: restrict RPC access via reverse proxy"
                )
        except Exception:
            pass
        return Finding("XML-RPC Externally Accessible", "LOW", "OK", "XML-RPC not accessible")

    def _check_default_creds(self, connection, database):
        if not database:
            return Finding("Default Credentials", "HIGH", "OK", "No database specified, skipping")

        default_pairs = [
            ("admin", "admin"),
            ("admin", "odoo"),
            ("demo", "demo"),
            ("admin", "1234"),
        ]
        found = []
        for user, pwd in default_pairs:
            try:
                uid = connection.common.authenticate(database, user, pwd, {})
                if uid:
                    found.append(f"{user}:{pwd} (uid:{uid})")
            except Exception:
                continue

        if found:
            return Finding(
                "Default Credentials Found",
                "CRITICAL",
                "FINDING",
                f"Valid default credentials: {', '.join(found)}",
                "Odoo security: change default passwords after installation"
            )
        return Finding("Default Credentials Found", "CRITICAL", "OK",
                       "No default credentials accepted")

    def _check_demo_user(self, connection, database):
        if not database:
            return None
        try:
            uid = connection.common.authenticate(database, "demo", "demo", {})
            if uid:
                return Finding(
                    "Demo Data Loaded",
                    "MEDIUM",
                    "FINDING",
                    f"demo:demo account exists (uid:{uid}) — demo data loaded in production",
                    "CVE-2021-45111: demo data can be triggered by any authenticated user on Odoo <=15"
                )
        except Exception:
            pass
        return None

    def _check_ssrf_link_preview(self, connection):
        endpoints = [
            "/html_editor/link_preview_external",
            "/web_editor/link_preview_external",
        ]
        ssrf_endpoint = None
        for endpoint in endpoints:
            try:
                url = f"{connection.host}{endpoint}"
                payload = {
                    "jsonrpc": "2.0",
                    "method": "call",
                    "id": 1,
                    "params": {"preview_url": "http://example.com"}
                }
                resp = connection.session.post(url, json=payload, timeout=10)
                if resp.status_code == 200:
                    body = resp.json()
                    if "result" in body and body["result"]:
                        ssrf_endpoint = endpoint
                        break
                    if "error" in body:
                        err_msg = str(body.get("error", {}).get("message", ""))
                        if "denied" not in err_msg.lower() and "forbidden" not in err_msg.lower():
                            ssrf_endpoint = endpoint
                            break
            except Exception:
                continue

        if not ssrf_endpoint:
            return Finding("SSRF via Link Preview", "MEDIUM", "OK",
                           "Link preview endpoints not accessible")

        subs = []
        internal_probes = [
            ("Loopback", f"http://127.0.0.1:{connection.host.split(':')[-1]}/web/login"),
            ("0x7f000001", f"http://0x7f000001:{connection.host.split(':')[-1]}/web/login"),
            ("0.0.0.0", f"http://0.0.0.0:{connection.host.split(':')[-1]}/web/login"),
        ]
        for name, probe_url in internal_probes:
            try:
                payload = {
                    "jsonrpc": "2.0", "method": "call", "id": 1,
                    "params": {"preview_url": probe_url}
                }
                resp = connection.session.post(
                    f"{connection.host}{ssrf_endpoint}", json=payload, timeout=5)
                body = resp.json()
                result = body.get("result")
                if result and result.get("og_title"):
                    subs.append(f"  {name:20s} -> {result['og_title']}")
            except Exception:
                pass

        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
        port = connection.host.split(":")[-1]
        open_services = []
        for p in common_ports:
            try:
                payload = {
                    "jsonrpc": "2.0", "method": "call", "id": 1,
                    "params": {"preview_url": f"http://127.0.0.1:{p}/"}
                }
                resp = connection.session.post(
                    f"{connection.host}{ssrf_endpoint}", json=payload, timeout=3)
                body = resp.json()
                result = body.get("result")
                if result and result.get("og_title"):
                    open_services.append(f"  :{p:5d}  {result['og_title']}")
            except Exception:
                pass

        if open_services:
            subs.append("--- Internal services with HTML ---")
            subs.extend(open_services)

        schemes_blocked = []
        for scheme in ["file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO"]:
            try:
                payload = {
                    "jsonrpc": "2.0", "method": "call", "id": 1,
                    "params": {"preview_url": scheme}
                }
                resp = connection.session.post(
                    f"{connection.host}{ssrf_endpoint}", json=payload, timeout=5)
                body = resp.json()
                if body.get("result"):
                    subs.append(f"  [!!!] {scheme} returned data!")
                else:
                    schemes_blocked.append(scheme.split(":")[0])
            except Exception:
                schemes_blocked.append(scheme.split(":")[0])

        if schemes_blocked:
            subs.append(f"--- Blocked protocols: {', '.join(set(schemes_blocked))}")

        return Finding(
            "SSRF via Link Preview",
            "MEDIUM",
            "FINDING",
            f"Server-side request via {ssrf_endpoint} — fetches arbitrary URLs",
            "Odoo scope: SSRF out-of-scope unless file:// or cloud metadata proven",
            sub_findings=subs
        )

    def _check_ssrf_livechat(self, connection):
        try:
            url = f"{connection.host}/im_livechat/init"
            resp = connection.session.post(url, json={
                "jsonrpc": "2.0", "method": "call", "id": 1,
                "params": {}
            }, timeout=10)
            if resp.status_code == 200:
                body = resp.json()
                result = body.get("result", {})
                if result and result.get("available_for_me"):
                    return Finding(
                        "Livechat SSRF Chain",
                        "MEDIUM",
                        "FINDING",
                        "im_livechat is enabled — anonymous users can trigger server-side URL fetches via posted messages",
                        "Odoo scope: SSRF out-of-scope unless file:// or cloud metadata proven"
                    )
                elif result:
                    return Finding(
                        "Livechat SSRF Chain",
                        "LOW",
                        "INFO",
                        "im_livechat module loaded but not available (no operators online)",
                        "Odoo scope: SSRF out-of-scope unless file:// or cloud metadata proven"
                    )
        except Exception:
            pass
        return None

    def _check_user_enum_timing(self, connection, database):
        if not database:
            return None
        try:
            fake_user = "odoomap_nonexistent_user_timing_test_xyz"
            real_user = "admin"
            samples = 3

            fake_times = []
            for _ in range(samples):
                start = time.perf_counter()
                try:
                    connection.common.authenticate(database, fake_user, "wrong_pwd_12345", {})
                except Exception:
                    pass
                fake_times.append(time.perf_counter() - start)

            real_times = []
            for _ in range(samples):
                start = time.perf_counter()
                try:
                    connection.common.authenticate(database, real_user, "wrong_pwd_12345", {})
                except Exception:
                    pass
                real_times.append(time.perf_counter() - start)

            avg_fake = sum(fake_times) / len(fake_times)
            avg_real = sum(real_times) / len(real_times)

            if avg_real > avg_fake * 2 and avg_real > 0.05:
                ratio = avg_real / avg_fake if avg_fake > 0 else 999
                return Finding(
                    "User Enumeration via Timing",
                    "LOW",
                    "INFO",
                    f"Existing user: {avg_real:.3f}s vs non-existent: {avg_fake:.3f}s ({ratio:.0f}x difference, bcrypt)",
                    "Odoo scope: user enumeration explicitly not qualifying"
                )
        except Exception:
            pass
        return None

    def _check_mail_template_access(self, connection):
        try:
            result = connection.models.execute_kw(
                connection.db, connection.uid, connection.password,
                'mail.template', 'check_access_rights', ['write'], {'raise_exception': False}
            )
            if result:
                tpl_count = 0
                try:
                    tpl_count = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        'mail.template', 'search_count', [[]]
                    )
                except Exception:
                    pass
                detail = "Current user can write to mail.template"
                if tpl_count:
                    detail += f" ({tpl_count} templates available)"
                detail += " — relevant to SSTI on Odoo <=14 and Odoo 18"
                return Finding(
                    "mail.template Write Access",
                    "LOW",
                    "INFO",
                    detail,
                    "Orange Cyberdefense / vycioha SSTI research"
                )
        except Exception:
            pass
        return None

    def _display_findings(self, findings):
        console.print()

        vuln_findings = [f for f in findings if f.status == "FINDING"]
        info_findings = [f for f in findings if f.status == "INFO"]
        ok_findings = [f for f in findings if f.status == "OK"]

        if vuln_findings:
            console.print("[bold red]FINDINGS[/bold red]")
            console.print()
            for f in vuln_findings:
                sev_style = SEVERITY_STYLES.get(f.severity, "white")
                content = Text()
                content.append("Severity: ", style="bold")
                content.append(f.severity, style=sev_style)
                content.append("\n")
                content.append(f.detail)
                if f.reference:
                    content.append(f"\nRef: {f.reference}", style="dim")
                if f.sub_findings:
                    content.append("\n")
                    for sf in f.sub_findings:
                        content.append(f"\n{sf}", style="cyan")

                console.print(Panel(
                    content,
                    title=f"[bold red]!! {f.name}[/bold red]",
                    border_style="red",
                ))

        if info_findings:
            console.print("[bold cyan]INFORMATIONAL[/bold cyan]")
            console.print()
            for f in info_findings:
                sev_style = SEVERITY_STYLES.get(f.severity, "white")
                content = Text()
                content.append("Severity: ", style="bold")
                content.append(f.severity, style=sev_style)
                content.append(f"\n{f.detail}")
                if f.reference:
                    content.append(f"\nRef: {f.reference}", style="dim")

                console.print(Panel(
                    content,
                    title=f"[cyan]{f.name}[/cyan]",
                    border_style="cyan",
                ))

        if ok_findings:
            console.print("[bold green]PASSED[/bold green]")
            ok_table = Table(box=MINIMAL, show_header=False, padding=(0, 1))
            ok_table.add_column("Check", style="green", width=40)
            ok_table.add_column("Detail", style="dim")
            for f in ok_findings:
                ok_table.add_row(f.name, f.detail)
            console.print(ok_table)

        console.print()
        summary = Table(title="Summary", box=ROUNDED, show_lines=False, title_style="bold")
        summary.add_column("", width=3, justify="center")
        summary.add_column("Category", style="bold")
        summary.add_column("Count", justify="right", width=5)
        summary.add_row(Text("!!", style="bold red"), Text("FINDINGS", style="bold red"), str(len(vuln_findings)))
        summary.add_row(Text("i", style="cyan"), Text("INFO", style="cyan"), str(len(info_findings)))
        summary.add_row(Text("ok", style="green"), Text("PASSED", style="green"), str(len(ok_findings)))
        console.print(summary)
        console.print()
