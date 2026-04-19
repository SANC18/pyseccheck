"""
S001 — Hardcoded secrets detector.

Detects passwords, API keys, tokens, and secrets assigned directly
as string literals in source code.

How the AST visitor pattern works here
---------------------------------------
Python's `ast` module parses source into a tree of Node objects.
`ast.NodeVisitor` lets us walk that tree by defining visit_<NodeType>
methods. When the visitor reaches a node of that type it calls our method.

We care about two node types:

  ast.Assign     →  x = "abc"          (simple assignment)
  ast.AnnAssign  →  x: str = "abc"     (annotated assignment, Python 3.6+)

For each, we check:
  1. Is the variable name suspicious?  (matches SECRET_NAMES)
  2. Is the value a non-empty string literal?  (not a placeholder like "")

If both are true → Finding.
"""
from __future__ import annotations

import ast
import re

from .base import BaseRule, Severity


# Variable names that suggest a secret.
# Checked as case-insensitive substring of the actual variable name.
SECRET_NAMES: frozenset[str] = frozenset(
    {
        "password", "passwd", "pwd",
        "secret", "api_key", "apikey",
        "token", "auth_token", "access_token",
        "private_key", "signing_key",
        "client_secret", "aws_secret",
        "database_url", "db_password",
    }
)

# Patterns that look like real secrets (not placeholders).
# We skip obvious placeholders like "", "changeme", "xxx", "todo".
PLACEHOLDER = re.compile(
    r"^(changeme|todo|fixme|placeholder|your[_\-]?key|<.*?>|xxx+|pass|test|example|none|null)$",
    re.IGNORECASE,
)


def _is_suspicious_name(name: str) -> bool:
    """Return True if the variable name contains a secret keyword."""
    lower = name.lower()
    return any(keyword in lower for keyword in SECRET_NAMES)


def _is_real_secret(value: ast.expr) -> bool:
    """
    Return True if the AST expression is a non-empty string literal
    that does NOT look like a placeholder.
    """
    # ast.Constant covers str in Python 3.8+
    if not isinstance(value, ast.Constant):
        return False
    if not isinstance(value.value, str):
        return False
    v = value.value.strip()
    if not v:            # empty string — skip
        return False
    if PLACEHOLDER.match(v):
        return False
    return True


class HardcodedSecretRule(BaseRule):
    RULE_ID  = "S001"
    SEVERITY = Severity.CRITICAL
    MESSAGE  = "Hardcoded secret — move to environment variable or secrets manager"

    # ------------------------------------------------------------------ #
    #  visit_Assign  handles:   password = "hunter2"                      #
    # ------------------------------------------------------------------ #
    def visit_Assign(self, node: ast.Assign) -> None:
        """
        ast.Assign has:
            node.targets  — list of assignment targets (left-hand side)
            node.value    — the right-hand side expression

        We iterate over targets because Python allows:
            a = b = "value"   (two targets, one value)
        """
        for target in node.targets:
            name = self._extract_name(target)
            if name and _is_suspicious_name(name) and _is_real_secret(node.value):
                self._add(
                    node,
                    f"Hardcoded secret in variable '{name}' — "
                    "move to os.environ or a secrets manager",
                )

        # IMPORTANT: call generic_visit so child nodes are still visited.
        # Without this, nested code (e.g. inside a function) is skipped.
        self.generic_visit(node)

    # ------------------------------------------------------------------ #
    #  visit_AnnAssign  handles:  password: str = "hunter2"               #
    # ------------------------------------------------------------------ #
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """
        ast.AnnAssign has:
            node.target  — single target (not a list like Assign)
            node.value   — right-hand side (optional — can be None)
        """
        if node.value is None:
            self.generic_visit(node)
            return

        name = self._extract_name(node.target)
        if name and _is_suspicious_name(name) and _is_real_secret(node.value):
            self._add(
                node,
                f"Hardcoded secret in annotated variable '{name}' — "
                "move to os.environ or a secrets manager",
            )

        self.generic_visit(node)

    # ------------------------------------------------------------------ #
    #  Helper: extract a plain string name from a target node             #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_name(target: ast.expr) -> str | None:
        """
        Return the variable name as a string, or None if we can't determine it.

        We handle:
          ast.Name          →  simple variable:   x = ...
          ast.Attribute     →  attribute:         self.password = ...
          ast.Subscript     →  dict key:          config["password"] = ...
                               (we extract the key string if it's a constant)
        """
        if isinstance(target, ast.Name):
            return target.id

        if isinstance(target, ast.Attribute):
            return target.attr

        if isinstance(target, ast.Subscript):
            # config["api_key"] = "secret"
            # node.slice is the key expression
            key = target.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                return key.value

        return None
