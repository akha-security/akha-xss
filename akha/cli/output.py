"""
Console output helpers for AKHA CLI.

Centralises all Rich formatting so handlers stay clean.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional, Sequence

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich import box as rich_box

__all__ = [
    "console",
    "BANNER",
    "BANNER_PLAIN",
    "VERSION",
    "LINE",
    "print_banner",
    "print_welcome_screen",
    "print_root_short_help",
    "print_scan_config",
    "print_phase",
    "print_result",
    "print_detail",
    "print_vuln_alert",
    "print_error",
    "print_success",
    "print_warning",
    "print_info",
    "print_scan_summary",
    "print_scan_results",
    "print_multi_target_summary",
    "print_payload_table",
    "print_stats",
]


console = Console(stderr=True)   # status → stderr; data → stdout

VERSION = "1.0.0"


LINE = "─" * 80


_SYM_OK   = "✓"
_SYM_WARN = "⚠"
_SYM_ERR  = "✗"
_SYM_INFO = "ℹ"
_SYM_VULN = "⚡"
_SYM_PHASE = "◆"


_LOGO = r"""
  █████╗ ██╗  ██╗██╗  ██╗ █████╗        ██╗  ██╗███████╗███████╗
 ██╔══██╗██║ ██╔╝██║  ██║██╔══██╗       ╚██╗██╔╝██╔════╝██╔════╝
 ███████║█████╔╝ ███████║███████║ █████╗ ╚███╔╝ ███████╗███████╗
 ██╔══██║██╔═██╗ ██╔══██║██╔══██║ ╚════╝ ██╔██╗ ╚════██║╚════██║
 ██║  ██║██║  ██╗██║  ██║██║  ██║       ██╔╝ ██╗███████║███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝       ╚═╝  ╚═╝╚══════╝╚══════╝
""".strip('\n')


def _framed_logo(logo: str) -> str:
    """Return an ASCII logo enclosed in a clean box-drawing frame."""
    lines  = logo.splitlines()
    width  = max((len(line) for line in lines), default=0)
    top    = f"╔{'═' * (width + 2)}╗"
    bottom = f"╚{'═' * (width + 2)}╝"
    rows   = [top]
    for line in lines:
        rows.append(f"║ {line.ljust(width)} ║")
    rows.append(bottom)
    return "\n".join(rows)


_BOXED_LOGO = _framed_logo(_LOGO)

BANNER       = f"[bold cyan]{_BOXED_LOGO}[/bold cyan]"
BANNER_PLAIN = _BOXED_LOGO




def print_banner(*, quiet: bool = False) -> None:
    """Print the AKHA banner with a polished introduction."""
    if quiet:
        return

    console.print()
    console.print(Text(_BOXED_LOGO, style="bold bright_cyan"))
    console.print()
    console.print(Text(f"AKHA XSS Scanner  ·  v{VERSION}", style="bold white"))
    console.print(
        Text(
            "AKHA-XSS Detection Framework",
            style="dim",
        )
    )
    console.print()


def print_welcome_screen(*, quiet: bool = False) -> None:
    """Print a polished no-args welcome screen."""
    if quiet:
        return
    print_banner(quiet=quiet)
    console.print(
        Text.from_markup(
            "[bold white]Key Features:[/bold white]  "
            "Smart Payload Generation · DOM Flow Tracking · Zero False Positives"
        )
    )
    console.print(
        Text("Proves vulnerabilities by executing them in a real browser environment.", style="dim")
    )
    
    console.print()
    tips = Table(
        show_header=False,
        box=rich_box.SIMPLE,
        padding=(0, 2),
        expand=False,
    )
    tips.add_column("label", style="bold cyan",  no_wrap=True)
    tips.add_column("value", style="white")
    tips.add_row("Quick Start", "akha-xss scan --url https://example.com")
    tips.add_row("Help",        "akha-xss -h  ·  akha-xss --help")
    console.print(tips)
    
    console.print()


def print_root_short_help() -> None:
    """Print concise root help for `akha-xss -h`."""
    console.print()
    console.print(Rule("[bold white]AKHA XSS Scanner[/bold white]", style="cyan", align="left"))
    console.print()

    console.print("[bold cyan]Commands[/bold cyan]")
    cmd_table = Table(show_header=False, box=None, padding=(0, 2))
    cmd_table.add_column("cmd",  style="bold white", no_wrap=True)
    cmd_table.add_column("desc", style="dim")
    cmd_table.add_row("scan",     "Scan targets for XSS vulnerabilities")
    cmd_table.add_row("payloads", "Manage payload generation / listing")
    cmd_table.add_row("stats",    "Show learning-engine statistics")
    console.print(cmd_table)

    console.print("[bold cyan]Examples[/bold cyan]")
    ex_table = Table(show_header=False, box=None, padding=(0, 2))
    ex_table.add_column("example", style="white")
    examples = [
        "akha-xss scan --url https://example.com",
        "akha-xss scan --url https://example.com/page?id=1 --mode url",
        "akha-xss scan --url https://example.com --profile deep",
        "akha-xss scan --url https://example.com --deep-scan --aggressive",
        'akha-xss scan --url https://example.com --cookie "session=abc"',
        "akha-xss scan --url https://example.com --blind-xss-url https://oast.site/cb",
        "akha-xss scan --file targets.txt --threads 20 --format both",
    ]
    for ex in examples:
        ex_table.add_row(ex)
    console.print(ex_table)

    console.print("[bold cyan]Tips[/bold cyan]")
    tip_table = Table(show_header=False, box=None, padding=(0, 2))
    tip_table.add_column("cmd",  style="bold white", no_wrap=True)
    tip_table.add_column("desc", style="dim")
    tip_table.add_row("akha-xss --help",      "Detailed global help")
    tip_table.add_row("akha-xss scan --help", "Detailed scan options")
    console.print(tip_table)
    console.print()


def print_scan_config(
    target_url: str,
    scan_mode: str,
    config: Any,
    *,
    authenticated: bool = False,
    features: Optional[List[str]] = None,
) -> None:
    """Print scan configuration in a structured, easy-to-scan layout."""
    cfg = Table(show_header=False, box=None, padding=(0, 3), expand=False)
    cfg.add_column("key",   style="dim", no_wrap=True)
    cfg.add_column("value", style="bold white")

    cfg.add_row("Target",           f"[cyan]{target_url}[/cyan]")
    cfg.add_row("Mode",             f"[yellow]{scan_mode.upper()}[/yellow]")
    cfg.add_row(
        "Performance",
        f"Threads [green]{config.threads}[/green]  ·  "
        f"Rate [green]{config.rate_limit} req/s[/green]",
    )
    if getattr(config, "proxy", None):
        cfg.add_row("Proxy", f"[cyan]{config.proxy}[/cyan]")
    cfg.add_row("Payload Strategy", f"[yellow]{config.payload_strategy.upper()}[/yellow]")

    if authenticated:
        cfg.add_row("Authentication",  "[green]Enabled[/green]")
    if getattr(config, "include_patterns", None):
        cfg.add_row("Include",         f"[dim]{', '.join(config.include_patterns)}[/dim]")
    if getattr(config, "exclude_patterns", None):
        cfg.add_row("Exclude",         f"[dim]{', '.join(config.exclude_patterns)}[/dim]")
    if features:
        cfg.add_row("Features",        f"[magenta]{' · '.join(features)}[/magenta]")
    if getattr(config, "collaborator_url", None):
        cfg.add_row("Collaborator",    f"[dim]{config.collaborator_url}[/dim]")

    console.print()
    console.print(
        Panel(
            cfg,
            title=f"[bold white]AKHA XSS Scanner  ·  v{VERSION}[/bold white]",
            title_align="left",
            border_style="cyan",
            box=rich_box.ROUNDED,
            padding=(1, 2),
        )
    )
    console.print(
        "  [dim]Controls:[/dim]  "
        "[bold white]P[/bold white][dim] Pause & report[/dim]   "
        "[bold white]SPACE[/bold white][dim] Stop & report[/dim]   "
        "[bold white]CTRL+C[/bold white][dim] Force exit[/dim]"
    )
    console.print()




def print_phase(num: int, title: str, icon: str = _SYM_PHASE) -> None:
    """Print a compact, high-contrast phase header."""
    console.print()
    console.print(
        f"[bold cyan] {icon} [/bold cyan]"
        f"[bold white]Phase {num}[/bold white]"
        f"[dim]  ──  [/dim]"
        f"[bold white]{title}[/bold white]"
    )
    console.print(f"[dim]{'─' * 60}[/dim]")


def print_result(success: bool, message: str) -> None:
    """Print a phase result line (✓ green or ⚠ yellow)."""
    if success:
        console.print(f"   [bold green]{_SYM_OK}[/bold green]  {message}")
    else:
        console.print(f"   [bold yellow]{_SYM_WARN}[/bold yellow]  {message}")


def print_detail(message: str) -> None:
    """Print an indented sub-detail line."""
    console.print(f"[dim]       · {message}[/dim]")


def print_vuln_alert(
    vuln_type: str,
    param: str,
    url: str = "",
    confidence: Optional[int] = None,
    *,
    use_console: Optional[Any] = None,
) -> None:
    """Print a vulnerability detection alert."""
    c = use_console or console

    header = Text()
    header.append(f" {_SYM_VULN} XSS DETECTED ", style="bold white on red")
    header.append("  ")
    header.append(f"Type: {vuln_type}", style="red")
    header.append("  ·  ", style="dim")
    header.append(f"Parameter: {param}", style="red")

    if confidence is not None:
        header.append("  ·  ", style="dim")
        conf_style = (
            "bold green" if confidence >= 80
            else ("yellow" if confidence >= 50 else "red")
        )
        header.append(f"Confidence: {confidence}%", style=conf_style)

    c.print(header)

    if url:
        c.print(f"[dim]      {url[:90]}[/dim]")




def print_error(msg: str) -> None:
    """Print a red error line."""
    console.print(f"   [bold red]{_SYM_ERR}[/bold red]  [red]{msg}[/red]")


def print_success(msg: str) -> None:
    """Print a green success line."""
    console.print(f"   [bold green]{_SYM_OK}[/bold green]  [green]{msg}[/green]")


def print_warning(msg: str) -> None:
    """Print a yellow warning line."""
    console.print(f"   [bold yellow]{_SYM_WARN}[/bold yellow]  [yellow]{msg}[/yellow]")


def print_info(msg: str) -> None:
    """Print a cyan info line."""
    console.print(f"   [cyan]{_SYM_INFO}[/cyan]  [dim]{msg}[/dim]")




def print_scan_results(
    session: Any,
    duration_str: str,
    csp_result: Optional[Dict] = None,
    blind_xss_tracking: Optional[Dict] = None,
    csp_summary: str = "",
) -> None:
    """Print the final scan results in a consistent professional layout."""
    stats = session.statistics
    vulns = session.vulnerabilities

    stats_table = Table(show_header=False, box=None, padding=(0, 3), expand=False)
    stats_table.add_column("metric", style="dim", no_wrap=True)
    stats_table.add_column("value",  style="bold white")

    stats_table.add_row("Duration",         duration_str)
    stats_table.add_row("URLs Crawled",     str(stats.get("urls_crawled", 0)))
    stats_table.add_row("Parameters Found", str(stats.get("params_found", 0)))
    stats_table.add_row("Payloads Tested",  str(stats.get("payloads_tested", 0)))

    if blind_xss_tracking:
        injections = blind_xss_tracking.get("injections", [])
        stats_table.add_row("Blind XSS Injected", f"{len(injections)} payloads")

    if csp_result:
        if csp_result.get("has_csp"):
            stats_table.add_row("CSP Status", csp_summary or "[green]Present[/green]")
        else:
            stats_table.add_row("CSP Status", "[yellow]No CSP header detected[/yellow]")

    vuln_count = stats.get("vulnerabilities_found", 0)
    if vuln_count > 0:
        stats_table.add_row(
            "Vulnerabilities",
            f"[bold red]{_SYM_VULN}  {vuln_count} FOUND[/bold red]",
        )
    else:
        stats_table.add_row(
            "Vulnerabilities",
            f"[bold green]{_SYM_OK}  0 — Clean[/bold green]",
        )

    console.print()
    console.print(
        Panel(
            stats_table,
            title="[bold white]Scan Results[/bold white]",
            border_style="cyan",
            box=rich_box.ROUNDED,
            padding=(1, 2),
        )
    )

    if vulns:
        vuln_table = Table(
            box=rich_box.ROUNDED,
            border_style="red",
            title="Detected Vulnerabilities",
            title_style="bold red",
            show_lines=True,
            padding=(0, 1),
        )
        vuln_table.add_column("#",         style="dim",    width=4,  justify="center")
        vuln_table.add_column("Type",      style="red",    width=16)
        vuln_table.add_column("Severity",                  width=12, justify="center")
        vuln_table.add_column("Parameter", style="yellow", width=16)
        vuln_table.add_column(
            "URL",
            style="cyan",
            max_width=40,
            overflow="ellipsis",
            no_wrap=True,
        )
        vuln_table.add_column("Conf.",     width=7, justify="center")

        for i, v in enumerate(vulns, 1):
            vtype    = v.get("type", "reflected").replace("_", " ").title()
            severity = v.get("severity_level", "potential")
            sev_style = "bold red" if severity == "confirmed" else "yellow"

            conf = v.get("confidence", "?")
            if isinstance(conf, int):
                conf_style = (
                    "bold green" if conf >= 80
                    else ("yellow" if conf >= 50 else "red")
                )
                conf_str = f"[{conf_style}]{conf}%[/{conf_style}]"
            else:
                conf_str = str(conf)

            vuln_table.add_row(
                str(i),
                vtype,
                f"[{sev_style}]{severity.upper()}[/{sev_style}]",
                v.get("parameter", "?"),
                v.get("url", ""),
                conf_str,
            )

        console.print()
        console.print(vuln_table)
        console.print()


def print_scan_summary(
    result: Dict[str, Any],
    *,
    quiet: bool = False,
) -> None:
    """Print a single-target scan completion message."""
    if quiet:
        return
    if result.get("success"):
        if result.get("interrupted"):
            print_warning("Scan interrupted — findings saved.")
        else:
            print_success("Scan completed successfully.")
    else:
        print_error(f"Scan failed: {result.get('error', 'Unknown error')}")




def print_multi_target_summary(
    results: List[Dict[str, Any]],
    *,
    quiet: bool = False,
) -> None:
    """Print summary table after multi-target scanning."""
    if quiet:
        return

    total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)

    summary = Table(
        title="Multi-Target Summary",
        title_style="bold cyan",
        box=rich_box.ROUNDED,
        border_style="cyan",
        show_lines=True,
        padding=(0, 1),
    )
    summary.add_column("#",      style="dim",  width=4,  justify="center")
    summary.add_column("Target", style="cyan", max_width=52, overflow="ellipsis")
    summary.add_column("Status",               width=8,  justify="center")
    summary.add_column("Vulns",                width=8,  justify="center")

    for i, r in enumerate(results, 1):
        vuln_count = len(r.get("vulnerabilities", []))
        status_str = (
            f"[bold green]{_SYM_OK}[/bold green]"
            if r.get("success")
            else f"[bold red]{_SYM_ERR}[/bold red]"
        )
        vuln_str = (
            f"[bold red]{vuln_count}[/bold red]"
            if vuln_count > 0
            else f"[green]0[/green]"
        )
        summary.add_row(str(i), r.get("target", "?"), status_str, vuln_str)

    console.print()
    console.print(summary)
    console.print()

    vuln_color = "red" if total_vulns else "green"
    console.print(
        f"  [dim]Targets scanned:[/dim] [bold white]{len(results)}[/bold white]   "
        f"[dim]Vulnerabilities:[/dim] [bold {vuln_color}]{total_vulns}[/bold {vuln_color}]"
    )
    console.print()




def print_payload_table(
    categories: Sequence[tuple],  # [(name, count, description), ...]
) -> None:
    """Print a table of payload categories."""
    table = Table(
        title="Payload Categories",
        title_style="bold cyan",
        box=rich_box.ROUNDED,
        border_style="cyan",
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Category",    style="cyan")
    table.add_column("Count",       style="bold green", justify="right", width=8)
    table.add_column("Description", style="dim")

    for name, count, desc in categories:
        table.add_row(name, str(count), desc)

    console.print()
    console.print(table)
    console.print()


def print_stats(stats: Dict[str, Any]) -> None:
    """Print learning-engine statistics."""
    stats_table = Table(show_header=False, box=None, padding=(0, 3), expand=False)
    stats_table.add_column("metric", style="dim", no_wrap=True)
    stats_table.add_column("value",  style="bold white")

    stats_table.add_row("Total Payloads",       str(stats["total_payloads"]))
    stats_table.add_row("Total Tests",          str(stats["total_tests"]))
    stats_table.add_row("Average Success Rate", f"{stats['avg_success_rate']:.2%}")

    console.print()
    console.print(
        Panel(
            stats_table,
            title="[bold cyan]Learning Engine Statistics[/bold cyan]",
            border_style="cyan",
            box=rich_box.ROUNDED,
            padding=(1, 2),
        )
    )

    if stats.get("top_payloads"):
        console.print()
        console.print(f"  [bold white]Top Payloads[/bold white]")
        console.print(f"  [dim]{'─' * 50}[/dim]")
        for i, p in enumerate(stats["top_payloads"][:5], 1):
            payload_preview = p["payload"][:55]
            if len(p["payload"]) > 55:
                payload_preview += "…"
            console.print(
                f"  [dim]{i}.[/dim]  {payload_preview}  "
                f"[green]{p['success_rate']:.2%}[/green]  "
                f"[dim]· {p['total_tests']} tests[/dim]"
            )
        console.print()

    if stats.get("failure_reasons"):
        ranked = sorted(stats["failure_reasons"].items(), key=lambda x: int(x[1]), reverse=True)
        console.print(f"  [bold white]Failure Reasons[/bold white]")
        console.print(f"  [dim]{'─' * 50}[/dim]")
        for reason, count in ranked[:5]:
            console.print(f"  [dim]-[/dim] {reason}: [yellow]{count}[/yellow]")
        console.print()
