"""
S003 — Weak cryptography.

Detects use of broken or insufficient cryptographic primitives:
  hashlib.md5()   → MD5 is broken for security use
  hashlib.sha1()  → SHA-1 is weak for security use
  random.random() → Not cryptographically secure — use secrets module
  random.randint()→ Same
"""
from __future__ import annotations

import ast

from .base import BaseRule, Severity

WEAK_HASH_METHODS = {"md5", "sha1"}

INSECURE_RANDOM = {"random", "randint", "choice", "shuffle", "sample", "uniform"}


class WeakCryptoRule(BaseRule):
    RULE_ID  = "S003"
    SEVERITY = Severity.HIGH
    MESSAGE  = "Weak cryptographic primitive detected"

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        if isinstance(func, ast.Attribute):
            module = self._module_name(func.value)
            method = func.attr.lower()

            # hashlib.md5(), hashlib.sha1(), hashlib.new("md5")
            if module == "hashlib":
                if method in WEAK_HASH_METHODS:
                    self._add(
                        node,
                        f"hashlib.{method}() is cryptographically broken — "
                        "use hashlib.sha256() or higher for security purposes",
                    )
                if method == "new":
                    # hashlib.new("md5", ...) — check the first string argument
                    if node.args and isinstance(node.args[0], ast.Constant):
                        algo = str(node.args[0].value).lower()
                        if algo in WEAK_HASH_METHODS:
                            self._add(
                                node,
                                f"hashlib.new('{algo}') is cryptographically broken — "
                                "use sha256 or higher",
                            )

            # random.random(), random.randint() — not for security use
            if module == "random" and method in INSECURE_RANDOM:
                self._add(
                    node,
                    f"random.{method}() is not cryptographically secure — "
                    "use the `secrets` module for tokens, passwords, or security values",
                )

        # Also catch bare: md5(...) after from hashlib import md5
        elif isinstance(func, ast.Name):
            if func.id.lower() in WEAK_HASH_METHODS:
                self._add(
                    node,
                    f"{func.id}() is cryptographically broken — "
                    "use sha256 or higher",
                )

        self.generic_visit(node)

    @staticmethod
    def _module_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id.lower()
        return ""
