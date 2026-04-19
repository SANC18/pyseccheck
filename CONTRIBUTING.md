# Contributing to PySecCheck

## Adding a new rule

This is the most common contribution. The entire process takes about 30 minutes.

### 1. Create the rule file

```
pyseccheck/rules/sXXX_your_rule_name.py
```

Use the next available rule ID (S006, S007, etc.).

### 2. Implement the rule

```python
from __future__ import annotations
import ast
from .base import BaseRule, Severity

class YourRule(BaseRule):
    RULE_ID  = "S006"
    SEVERITY = Severity.HIGH
    MESSAGE  = "One-line description shown in output"

    def visit_SomeNode(self, node: ast.SomeNode) -> None:
        if <condition>:
            self._add(node, "Specific message for this finding")
        self.generic_visit(node)  # always call this at the end
```

**Always call `self.generic_visit(node)` at the end of every visitor method.**
Without it, the walker stops descending into child nodes and misses nested code.

### 3. Register the rule

In `pyseccheck/rules/__init__.py`, add your import and class to the `RULES` list.
The scanner picks it up automatically — no other changes needed.

### 4. Write tests

Add a `TestYourRule` class to `tests/test_rules.py`. Each rule needs at minimum:
- One test that confirms the rule catches the vulnerable pattern
- One test that confirms safe/correct code is **not** flagged

Run tests with: `pytest tests/ -v`

### 5. Update the fixture files

Add an example of the vulnerability to `tests/fixtures/insecure_example.py`
and confirm the clean fixture still produces zero findings.

---

## Running tests locally

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Project structure

```
pyseccheck/
├── pyseccheck/
│   ├── cli.py          ← Click CLI (scan, rules subcommands)
│   ├── scanner.py      ← file collection + AST parsing engine
│   └── rules/
│       ├── base.py     ← BaseRule, Finding, Severity — start here
│       ├── __init__.py ← RULES registry
│       └── sXXX_*.py  ← one file per rule
└── tests/
    ├── fixtures/       ← intentionally insecure + clean Python files
    └── test_rules.py   ← pytest test suite
```
