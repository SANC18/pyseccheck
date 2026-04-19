"""
S004 — SQL injection via string building.

Detects SQL queries constructed by concatenating or formatting strings
with variables — the most common source of SQL injection vulnerabilities.

Patterns caught:
  "SELECT * FROM users WHERE id = " + user_id          (BinOp / Add)
  "SELECT * FROM users WHERE id = %s" % user_id        (BinOp / Mod)
  f"SELECT * FROM users WHERE id = {user_id}"          (JoinedStr / f-string)
  "SELECT * FROM {} WHERE id = {}".format(table, uid)  (Call to .format())

AST nodes used:
  ast.BinOp     — binary operation (+ or %)
  ast.JoinedStr — f-string
  ast.Call      — .format() call on a string
"""
from __future__ import annotations

import ast
import re

from .base import BaseRule, Severity

SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|FROM|WHERE)\b",
    re.IGNORECASE,
)


def _is_sql_string(node: ast.expr) -> bool:
    """Return True if a Constant string node looks like a SQL fragment."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(SQL_KEYWORDS.search(node.value))
    return False


class SQLInjectionRule(BaseRule):
    RULE_ID  = "S004"
    SEVERITY = Severity.CRITICAL
    MESSAGE  = "Possible SQL injection — build queries with parameterised statements"

    # ── "SELECT … " + user_input   OR   "SELECT … " % user_input ──
    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, (ast.Add, ast.Mod)):
            if _is_sql_string(node.left) or _is_sql_string(node.right):
                self._add(
                    node,
                    "SQL query built with string concatenation/formatting — "
                    "use parameterised queries: cursor.execute(sql, (value,))",
                )
        self.generic_visit(node)

    # ── f"SELECT … {user_input}" ──────────────────────────────────
    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        # JoinedStr.values contains a mix of Constant and FormattedValue nodes.
        # If any Constant part looks like SQL, the whole f-string is suspect.
        for part in node.values:
            if _is_sql_string(part):
                self._add(
                    node,
                    "SQL query built with f-string interpolation — "
                    "use parameterised queries instead",
                )
                break
        self.generic_visit(node)

    # ── "SELECT … {}".format(user_input) ─────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and _is_sql_string(node.func.value)
        ):
            self._add(
                node,
                "SQL query built with .format() — "
                "use parameterised queries instead",
            )
        self.generic_visit(node)
