"""
S005 — Debug/development artefacts left in production code.

Catches two common mistakes developers make before shipping:

  1. debug=True passed to Flask/Django/FastAPI app runner
       app.run(debug=True)        ← exposes interactive debugger to the internet

  2. Hardcoded non-loopback IP addresses assigned to host/bind variables
       HOST = "0.0.0.0"          ← intentionally binds all interfaces (warn)
       host = "192.168.1.50"     ← hardcoded internal IP leaks network topology

AST nodes:
  ast.Call    — to catch debug=True in run() calls
  ast.Assign  — to catch HOST = "0.0.0.0" style assignments
"""
from __future__ import annotations

import ast
import re

from .base import BaseRule, Severity

# Variable names that suggest a bind address
HOST_NAMES = frozenset({"host", "bind", "bind_address", "listen_address", "server_host"})

# Matches IPv4 addresses that are not localhost
NON_LOCALHOST_IP = re.compile(
    r"^(?!127\.0\.0\.1|localhost)(\d{1,3}\.){3}\d{1,3}$"
)


class DebugArtifactsRule(BaseRule):
    RULE_ID  = "S005"
    SEVERITY = Severity.MEDIUM
    MESSAGE  = "Debug/development artefact detected — review before deploying"

    # ── app.run(debug=True) ───────────────────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # Match any .run() call — covers Flask, Werkzeug, custom servers
        if isinstance(func, ast.Attribute) and func.attr == "run":
            for kw in node.keywords:
                if (
                    kw.arg == "debug"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._add(
                        node,
                        "debug=True enables the interactive debugger — "
                        "never deploy with this enabled; use an environment variable instead",
                    )
        self.generic_visit(node)

    # ── HOST = "0.0.0.0"  /  host = "192.168.x.x" ───────────────
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = self._name(target)
            if name and name.lower() in HOST_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    ip = node.value.value.strip()
                    if ip == "0.0.0.0":
                        self._add(
                            node,
                            f"'{name}' is set to 0.0.0.0 — binds all network interfaces; "
                            "confirm this is intentional and load from config",
                        )
                    elif NON_LOCALHOST_IP.match(ip):
                        self._add(
                            node,
                            f"'{name}' contains a hardcoded IP address '{ip}' — "
                            "load network config from environment variables",
                        )
        self.generic_visit(node)

    @staticmethod
    def _name(target: ast.expr) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return None
