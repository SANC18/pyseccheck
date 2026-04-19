"""
Base class for all PySecCheck AST rules.

Every rule is a self-contained ast.NodeVisitor subclass.
It walks a parsed AST and appends Finding objects to self.findings.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


@dataclass
class Finding:
    rule_id:  str
    severity: Severity
    message:  str
    filepath: Path
    line:     int
    col:      int
    snippet:  str = ""

    def __str__(self) -> str:
        return (
            f"{self.filepath}:{self.line}:{self.col} "
            f"[{self.severity}] {self.rule_id} — {self.message}"
        )


class BaseRule(ast.NodeVisitor):
    """
    Subclass this for every new rule.

    Subclasses must set:
        RULE_ID  — short code,  e.g. "S001"
        SEVERITY — a Severity value
        MESSAGE  — one-line description shown in output

    Then override visit_* methods exactly like a normal ast.NodeVisitor.
    Call self._add(node) from inside a visitor to record a finding.
    """

    RULE_ID:  str = ""
    SEVERITY: Severity = Severity.MEDIUM
    MESSAGE:  str = ""

    def __init__(self, filepath: Path, source_lines: list[str]) -> None:
        self.filepath     = filepath
        self.source_lines = source_lines
        self.findings:    list[Finding] = []

    def _add(self, node: ast.AST, message: str | None = None) -> None:
        lineno = getattr(node, "lineno", 0)
        col    = getattr(node, "col_offset", 0)
        line_text = (
            self.source_lines[lineno - 1].rstrip()
            if 0 < lineno <= len(self.source_lines)
            else ""
        )
        self.findings.append(
            Finding(
                rule_id  = self.RULE_ID,
                severity = self.SEVERITY,
                message  = message or self.MESSAGE,
                filepath = self.filepath,
                line     = lineno,
                col      = col,
                snippet  = line_text,
            )
        )

    def run(self, tree: ast.AST) -> list[Finding]:
        self.visit(tree)
        return self.findings
