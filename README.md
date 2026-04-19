# PySecCheck

[![CI](https://github.com/SANC18/pyseccheck/actions/workflows/ci.yml/badge.svg)](https://github.com/SANC18/pyseccheck/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Code style](https://img.shields.io/badge/code%20style-PEP8-black?style=flat-square)](https://peps.python.org/pep-0008/)

A Python security linter that uses **AST (Abstract Syntax Tree) analysis** to detect security vulnerabilities in Python source code — catching patterns that regex-based tools miss.

Scans your code for hardcoded secrets, dangerous function calls, weak cryptography, SQL injection, and debug artefacts left in production. Works entirely on the source text — no code execution required.

---

## Quick start

```bash
# Install
pip install pyseccheck

# Scan a file or directory
pyseccheck scan app.py
pyseccheck scan ./src

# Only report HIGH and CRITICAL findings
pyseccheck scan . --severity HIGH

# Output as JSON (for CI pipelines)
pyseccheck scan . --json

# List all available rules
pyseccheck rules
```

### Example output

```
app/auth.py
  line 12   CRITICAL   S001  Hardcoded secret in variable 'api_key' — move to os.environ
    →  api_key = "sk-1234567890abcdef"

  line 31   HIGH       S002  eval() executes arbitrary code — never pass user input to it
    →  eval(user_input)

  line 47   CRITICAL   S004  SQL query built with string concatenation — use parameterised queries
    →  query = "SELECT * FROM users WHERE id = " + user_id

  Found: 2 CRITICAL  1 HIGH
```

---

## Why AST, not regex?

Regex works on text. AST works on structure.

A regex looking for `password\s*=\s*".*"` will flag a `password` variable inside a comment, a docstring, or a test mock. It can't tell if a suspicious string came from `os.environ` or a literal. It can't detect `config["password"] = "secret"` without a separate pattern.

PySecCheck parses Python source into its AST — the same tree Python's own compiler uses — and inspects the actual structure of the code. It knows the difference between a variable assignment and a comment. It knows what `self.password = ...` means versus `expected_password = "test"`.

---

## Rules

| ID | Severity | What it detects |
|----|----------|----------------|
| S001 | CRITICAL | Hardcoded passwords, API keys, tokens, secrets |
| S002 | HIGH | Dangerous calls: `eval`, `exec`, `os.system`, `pickle.loads`, `subprocess` with `shell=True` |
| S003 | HIGH | Weak crypto: `hashlib.md5`, `hashlib.sha1`, `random` for security values |
| S004 | CRITICAL | SQL injection via string concatenation, f-strings, `%` formatting, `.format()` |
| S005 | MEDIUM | Debug artefacts: `debug=True` in app runners, hardcoded IP addresses |

### S001 — Hardcoded secrets

Detects secrets assigned as string literals in any of these forms:

```python
# All of these are caught:
password = "hunter2"                        # simple assignment
api_key: str = "sk-abc123"                  # annotated assignment
self.secret = "my_secret"                   # attribute assignment
config["db_password"] = "postgres_pass"     # dict key assignment

# These are NOT flagged:
password = os.environ.get("DB_PASSWORD")    # correct — from environment
api_key = ""                                # empty string — skip
token = "changeme"                          # placeholder — skip
```

### S002 — Dangerous functions

```python
# Caught:
eval(user_input)                            # arbitrary code execution
exec(code_string)                           # same
os.system("rm -rf " + path)                # shell injection
subprocess.run(cmd, shell=True)             # shell injection
pickle.loads(untrusted_data)               # arbitrary code on deserialisation
yaml.load(stream)                           # unsafe default Loader

# Not flagged:
subprocess.run(["ls", "-la", path])        # safe — list form, no shell
yaml.safe_load(stream)                      # safe Loader
```

### S003 — Weak cryptography

```python
# Caught:
hashlib.md5(data)                           # MD5 is broken
hashlib.sha1(data)                          # SHA-1 is weak
hashlib.new("md5", data)                    # same, indirect form
random.randint(1, 1000000)                  # not cryptographically secure

# Not flagged:
hashlib.sha256(data)                        # strong
secrets.token_hex(32)                       # correct for security use
```

### S004 — SQL injection

```python
# All caught:
query = "SELECT * FROM users WHERE id = " + user_id     # concatenation
query = "SELECT * FROM users WHERE id = %s" % user_id   # % formatting
query = f"SELECT * FROM users WHERE id = {user_id}"     # f-string
query = "DELETE FROM {} WHERE id = {}".format(t, uid)   # .format()

# Not flagged:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # parameterised
```

### S005 — Debug artefacts

```python
# Caught:
app.run(debug=True)         # Flask/Werkzeug interactive debugger exposed
HOST = "192.168.1.50"       # hardcoded internal IP leaks network topology
host = "0.0.0.0"            # binds all interfaces — confirm intentional

# Not flagged:
app.run(debug=False)
host = "127.0.0.1"          # localhost is fine
```

---

## Architecture

```
pyseccheck/
├── pyseccheck/
│   ├── __init__.py
│   ├── cli.py              ← Click CLI: scan, rules subcommands
│   ├── scanner.py          ← file collection, AST parsing, rule runner
│   └── rules/
│       ├── base.py         ← BaseRule, Finding, Severity
│       ├── __init__.py     ← RULES registry
│       ├── s001_hardcoded_secrets.py
│       ├── s002_dangerous_functions.py
│       ├── s003_weak_crypto.py
│       ├── s004_sql_injection.py
│       └── s005_debug_artifacts.py
└── tests/
    ├── fixtures/
    │   ├── insecure_example.py   ← intentionally vulnerable code
    │   └── clean_example.py      ← all correct — should produce 0 findings
    └── test_rules.py             ← 36 pytest tests
```

### How it works

1. `pyseccheck scan ./src` → Click parses CLI args
2. `scanner.scan_paths()` collects all `.py` files recursively
3. `scanner.scan_file()` reads each file and calls `ast.parse()` to build the AST
4. Each rule class (a subclass of `ast.NodeVisitor`) walks the tree via `visit_*` methods
5. When a rule matches a suspicious pattern, it appends a `Finding` to its list
6. All findings are sorted by line number and printed with Rich

### Adding a new rule

Every rule is a self-contained file. To add S006:

```python
# pyseccheck/rules/s006_my_rule.py
from .base import BaseRule, Severity
import ast

class MyRule(BaseRule):
    RULE_ID  = "S006"
    SEVERITY = Severity.HIGH
    MESSAGE  = "Short description"

    def visit_Call(self, node: ast.Call) -> None:
        # inspect node here, call self._add(node, "message") to flag it
        self.generic_visit(node)  # never skip this
```

Then add it to `pyseccheck/rules/__init__.py`. The scanner picks it up automatically.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## Development setup

```bash
git clone https://github.com/SANC18/pyseccheck.git
cd pyseccheck
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Scan the project itself
pyseccheck scan pyseccheck/
```

---

## Comparison with Bandit

[Bandit](https://github.com/PyCQA/bandit) is the standard Python security linter. PySecCheck takes a different approach in a few areas:

| Feature | Bandit | PySecCheck |
|---------|--------|-----------|
| AST-based | Yes | Yes |
| SQL injection (string concat) | Partial | Yes (S004) |
| f-string SQL injection | No | Yes (S004) |
| `.format()` SQL injection | No | Yes (S004) |
| Dict key secret assignment | No | Yes (S001) |
| JSON output | Yes | Yes (`--json`) |
| Pre-commit hook | Yes | Planned |
| PyPI package | Yes | Yes |

PySecCheck is a learning project — Bandit is more mature and should be used in production. The goal here is to understand how static analysis tools work from the inside.

---

## Roadmap

- [ ] S006 — insecure HTTP requests (`requests.get("http://...")`)
- [ ] S007 — assert used for security checks
- [ ] S008 — unsafe deserialization (`marshal.loads`)
- [ ] Pre-commit hook configuration
- [ ] `--fix` flag for auto-remediation of S001 (replace with `os.environ.get`)
- [ ] Benchmark against real vulnerable repositories (OWASP WebGoat Python port)

---

## License

MIT — see [LICENSE](LICENSE).

---

Built as part of a security + Python portfolio. Related project: [ml-intrusion-detection](https://github.com/SANC18/ml-intrusion-detection) — an ML-based IDS comparing 5 classifiers on KDD Cup 99 with SHAP explainability.
