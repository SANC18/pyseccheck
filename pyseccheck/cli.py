"""
CLI entry point.

Usage:
    pyseccheck scan ./src
    pyseccheck scan app.py --severity HIGH
    pyseccheck scan . --json
    pyseccheck scan . --no-recurse
    pyseccheck rules
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from .scanner import scan_paths
from .rules import RULES, Severity

console = Console()

# Severity → Rich colour mapping
SEV_COLOUR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


# ─────────────────────────────────────────────────────────────────── #
#  Root group                                                         #
# ─────────────────────────────────────────────────────────────────── #
@click.group()
@click.version_option(version="0.1.0", prog_name="pyseccheck")
def main() -> None:
    """PySecCheck — Python security linter powered by AST analysis."""


# ─────────────────────────────────────────────────────────────────── #
#  `pyseccheck scan`                                                  #
# ─────────────────────────────────────────────────────────────────── #
@main.command()
@click.argument(
    "paths",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--severity", "-s",
    default="LOW",
    show_default=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    help="Minimum severity to report.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output findings as JSON (useful for CI pipelines).",
)
@click.option(
    "--no-recurse",
    is_flag=True,
    default=False,
    help="Do not recurse into subdirectories.",
)
def scan(
    paths: tuple[Path, ...],
    severity: str,
    output_json: bool,
    no_recurse: bool,
) -> None:
    """Scan one or more files / directories for security issues."""

    min_severity = Severity(severity.upper())
    min_index    = SEVERITY_ORDER.index(min_severity)

    findings, errors = scan_paths(list(paths), recurse=not no_recurse)

    # Filter by minimum severity
    findings = [
        f for f in findings
        if SEVERITY_ORDER.index(f.severity) <= min_index
    ]

    # ── JSON mode ─────────────────────────────────────────────────── #
    if output_json:
        out = {
            "findings": [
                {
                    "rule_id":  f.rule_id,
                    "severity": f.severity.value,
                    "message":  f.message,
                    "file":     str(f.filepath),
                    "line":     f.line,
                    "col":      f.col,
                    "snippet":  f.snippet,
                }
                for f in findings
            ],
            "errors": [{"file": str(e.filepath), "error": e.error} for e in errors],
            "summary": {
                "total":    len(findings),
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low":      sum(1 for f in findings if f.severity == Severity.LOW),
            },
        }
        click.echo(json.dumps(out, indent=2))
        sys.exit(1 if findings else 0)

    # ── Rich terminal output ───────────────────────────────────────── #
    if errors:
        for err in errors:
            console.print(f"[yellow]WARN[/] Could not parse {err.filepath}: {err.error}")

    if not findings:
        console.print("\n[bold green]  No issues found.[/]\n")
        sys.exit(0)

    # Group findings by file for readable output
    files: dict[Path, list] = {}
    for f in findings:
        files.setdefault(f.filepath, []).append(f)

    for filepath, file_findings in files.items():
        console.print(f"\n[bold]{filepath}[/]")
        for f in file_findings:
            sev_style = SEV_COLOUR.get(f.severity, "white")
            sev_badge = Text(f" {f.severity.value} ", style=f"bold {sev_style}")

            console.print(
                f"  [dim]line {f.line}[/]  ",
                sev_badge,
                f"  [bold]{f.rule_id}[/]  {f.message}",
            )
            if f.snippet:
                console.print(f"  [dim]  → {f.snippet.strip()}[/]")

    # Summary bar
    _print_summary(findings)

    # Non-zero exit if any findings — makes CI fail correctly
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────── #
#  `pyseccheck rules`  — list all available rules                     #
# ─────────────────────────────────────────────────────────────────── #
@main.command()
def rules() -> None:
    """List all available rules."""
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("ID",       style="bold cyan",  width=8)
    table.add_column("Severity", width=10)
    table.add_column("Name",     width=30)
    table.add_column("Description")

    for rule_cls in RULES:
        sev   = rule_cls.SEVERITY
        style = SEV_COLOUR.get(sev, "white")
        table.add_row(
            rule_cls.RULE_ID,
            Text(sev.value, style=style),
            rule_cls.__name__.replace("Rule", ""),
            rule_cls.MESSAGE,
        )

    console.print("\n[bold]PySecCheck — available rules[/]\n")
    console.print(table)


# ─────────────────────────────────────────────────────────────────── #
#  Helpers                                                            #
# ─────────────────────────────────────────────────────────────────── #
def _print_summary(findings: list) -> None:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    parts = []
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            colour = SEV_COLOUR[sev]
            parts.append(Text(f"{counts[sev]} {sev.value}", style=colour))

    summary = Text("  Found: ")
    for i, part in enumerate(parts):
        summary.append_text(part)
        if i < len(parts) - 1:
            summary.append("  ")

    console.print()
    console.print(summary)
    console.print()
