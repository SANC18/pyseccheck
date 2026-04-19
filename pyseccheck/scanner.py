"""
Scanner — the core engine.

Takes a list of file paths, parses each one into an AST,
runs every rule, and returns all findings.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .rules import RULES, Finding


class ParseError:
    """Returned instead of findings when a file can't be parsed."""
    def __init__(self, filepath: Path, error: str) -> None:
        self.filepath = filepath
        self.error    = error


def scan_file(filepath: Path) -> list[Finding] | ParseError:
    """Parse one .py file and run all rules against it."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return ParseError(filepath, str(e))

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        return ParseError(filepath, f"SyntaxError: {e}")

    source_lines = source.splitlines()
    findings: list[Finding] = []

    for rule_class in RULES:
        rule = rule_class(filepath=filepath, source_lines=source_lines)
        findings.extend(rule.run(tree))

    # Sort by line number for readable output
    findings.sort(key=lambda f: f.line)
    return findings


def scan_paths(paths: list[Path], recurse: bool = True) -> tuple[list[Finding], list[ParseError]]:
    """
    Scan a list of paths (files or directories).
    Returns (all_findings, parse_errors).
    """
    all_findings: list[Finding] = []
    errors: list[ParseError]    = []

    py_files = _collect_py_files(paths, recurse)

    for py_file in py_files:
        result = scan_file(py_file)
        if isinstance(result, ParseError):
            errors.append(result)
        else:
            all_findings.extend(result)

    return all_findings, errors


def _collect_py_files(paths: list[Path], recurse: bool) -> list[Path]:
    """Expand dirs → .py files, keep plain .py paths as-is."""
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            if p.suffix == ".py":
                files.append(p)
        elif p.is_dir():
            pattern = "**/*.py" if recurse else "*.py"
            files.extend(sorted(p.glob(pattern)))
    return files
