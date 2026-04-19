"""
S002 — Dangerous function calls.

Detects calls to functions that are common sources of security vulnerabilities:
  eval()     → arbitrary code execution from user input
  exec()     → same
  os.system()    → shell injection
  os.popen()     → shell injection
  subprocess with shell=True  → shell injection
  pickle.loads() → arbitrary code execution on deserialisation
  pickle.load()  → same

AST node used: ast.Call
  node.func   — the function being called (Name or Attribute)
  node.args   — positional arguments
  node.keywords — keyword arguments (for shell=True check)
"""
from __future__ import annotations

import ast

from .base import BaseRule, Severity


# Simple function names (not qualified): eval("x")
DANGEROUS_BUILTINS: dict[str, str] = {
    "eval": "eval() executes arbitrary code — never pass user input to it",
    "exec": "exec() executes arbitrary code — avoid or sandbox carefully",
}

# Qualified calls: module.function(...)
DANGEROUS_ATTRS: dict[tuple[str, str], str] = {
    ("os", "system"):      "os.system() is vulnerable to shell injection — use subprocess with a list",
    ("os", "popen"):       "os.popen() is vulnerable to shell injection — use subprocess with a list",
    ("pickle", "loads"):   "pickle.loads() executes arbitrary code on deserialisation — use json or safer formats",
    ("pickle", "load"):    "pickle.load() executes arbitrary code on deserialisation — use json or safer formats",
    ("marshal", "loads"):  "marshal.loads() can execute arbitrary code — avoid for untrusted data",
    ("yaml", "load"):      "yaml.load() with default Loader is unsafe — use yaml.safe_load() instead",
}


class DangerousFunctionsRule(BaseRule):
    RULE_ID  = "S002"
    SEVERITY = Severity.HIGH
    MESSAGE  = "Dangerous function call detected"

    def visit_Call(self, node: ast.Call) -> None:
        """
        ast.Call has:
            node.func      — ast.Name for bare calls, ast.Attribute for dotted calls
            node.keywords  — list of ast.keyword nodes (for shell=True detection)
        """
        func = node.func

        # --- bare call: eval(...), exec(...) ---
        if isinstance(func, ast.Name):
            if func.id in DANGEROUS_BUILTINS:
                self._add(node, DANGEROUS_BUILTINS[func.id])

        # --- dotted call: os.system(...), pickle.loads(...) ---
        elif isinstance(func, ast.Attribute):
            # Reconstruct "module.method" from the AST
            module = self._get_name(func.value)
            method = func.attr
            key = (module, method)
            if key in DANGEROUS_ATTRS:
                self._add(node, DANGEROUS_ATTRS[key])

            # subprocess.run / subprocess.Popen / subprocess.call with shell=True
            if module in {"subprocess", "Popen"} or method in {
                "run", "call", "check_call", "check_output", "Popen"
            }:
                if self._has_shell_true(node):
                    self._add(
                        node,
                        "subprocess called with shell=True — "
                        "pass a list of arguments instead to prevent shell injection",
                    )

        self.generic_visit(node)

    @staticmethod
    def _get_name(node: ast.expr) -> str:
        """Extract a simple name from an AST node, e.g. 'os' from ast.Name(id='os')."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        """Return True if any keyword argument is shell=True."""
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                if kw.value.value is True:
                    return True
        return False
