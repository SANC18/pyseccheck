"""
Tests for PySecCheck rules.

Each test follows the same pattern:
  1. Write a small inline Python snippet as a string
  2. Parse it with ast.parse()
  3. Run the rule
  4. Assert findings were / were not produced

This is better than only testing with fixture files because:
  - Tests are self-contained and readable
  - You can test one specific pattern at a time
  - Failures are easier to debug
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyseccheck.rules.s001_hardcoded_secrets import HardcodedSecretRule
from pyseccheck.rules.s002_dangerous_functions import DangerousFunctionsRule
from pyseccheck.rules.s003_weak_crypto import WeakCryptoRule
from pyseccheck.rules.s004_sql_injection import SQLInjectionRule
from pyseccheck.rules.s005_debug_artifacts import DebugArtifactsRule
from pyseccheck.rules.base import Severity
from pyseccheck.scanner import scan_file

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def run_rule(rule_class, source: str):
    """Helper: parse source and run a single rule."""
    tree  = ast.parse(source)
    lines = source.splitlines()
    rule  = rule_class(filepath=Path("test.py"), source_lines=lines)
    return rule.run(tree)


# ══════════════════════════════════════════════════════════════════ #
#  S001 — Hardcoded secrets                                          #
# ══════════════════════════════════════════════════════════════════ #
class TestHardcodedSecrets:

    def test_catches_simple_password(self):
        source = 'password = "hunter2"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 1
        assert findings[0].rule_id == "S001"
        assert findings[0].severity == Severity.CRITICAL

    def test_catches_api_key(self):
        source = 'api_key = "sk-1234567890abcdef"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 1

    def test_catches_annotated_assignment(self):
        source = 'secret: str = "my_real_secret_value"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 1

    def test_catches_dict_key_assignment(self):
        source = 'config["api_key"] = "hardcoded_value"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 1

    def test_catches_attribute_assignment(self):
        source = 'self.password = "plaintext_pass"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 1

    def test_ignores_env_var_lookup(self):
        source = 'password = os.environ.get("DB_PASSWORD")'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 0

    def test_ignores_empty_string(self):
        source = 'password = ""'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 0

    def test_ignores_placeholder(self):
        source = 'api_key = "changeme"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 0

    def test_ignores_unrelated_variable(self):
        source = 'username = "alice"'
        findings = run_rule(HardcodedSecretRule, source)
        assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════ #
#  S002 — Dangerous functions                                        #
# ══════════════════════════════════════════════════════════════════ #
class TestDangerousFunctions:

    def test_catches_eval(self):
        source = 'eval(user_input)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert len(findings) == 1
        assert "eval" in findings[0].message

    def test_catches_exec(self):
        source = 'exec(code)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert len(findings) == 1

    def test_catches_os_system(self):
        source = 'import os\nos.system("ls " + user_input)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert any(f.rule_id == "S002" for f in findings)

    def test_catches_subprocess_shell_true(self):
        source = 'import subprocess\nsubprocess.run(cmd, shell=True)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert any("shell=True" in f.message for f in findings)

    def test_subprocess_shell_false_is_ok(self):
        source = 'import subprocess\nsubprocess.run(["ls", "-la"], shell=False)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert len(findings) == 0

    def test_catches_pickle_loads(self):
        source = 'import pickle\nresult = pickle.loads(data)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert len(findings) == 1
        assert "pickle" in findings[0].message

    def test_catches_yaml_load(self):
        source = 'import yaml\nyaml.load(stream)'
        findings = run_rule(DangerousFunctionsRule, source)
        assert len(findings) == 1


# ══════════════════════════════════════════════════════════════════ #
#  S003 — Weak crypto                                                #
# ══════════════════════════════════════════════════════════════════ #
class TestWeakCrypto:

    def test_catches_md5(self):
        source = 'import hashlib\nhashlib.md5(data)'
        findings = run_rule(WeakCryptoRule, source)
        assert len(findings) == 1
        assert "md5" in findings[0].message.lower()

    def test_catches_sha1(self):
        source = 'import hashlib\nhashlib.sha1(data)'
        findings = run_rule(WeakCryptoRule, source)
        assert len(findings) == 1

    def test_catches_hashlib_new_md5(self):
        source = 'import hashlib\nhashlib.new("md5", data)'
        findings = run_rule(WeakCryptoRule, source)
        assert len(findings) == 1

    def test_sha256_is_ok(self):
        source = 'import hashlib\nhashlib.sha256(data)'
        findings = run_rule(WeakCryptoRule, source)
        assert len(findings) == 0

    def test_catches_random_randint(self):
        source = 'import random\nrandom.randint(1, 100)'
        findings = run_rule(WeakCryptoRule, source)
        assert len(findings) == 1
        assert "secrets" in findings[0].message

    def test_secrets_module_is_ok(self):
        source = 'import secrets\nsecrets.token_hex(32)'
        findings = run_rule(WeakCryptoRule, source)
        assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════ #
#  S004 — SQL injection                                              #
# ══════════════════════════════════════════════════════════════════ #
class TestSQLInjection:

    def test_catches_string_concat(self):
        source = 'query = "SELECT * FROM users WHERE id = " + user_id'
        findings = run_rule(SQLInjectionRule, source)
        assert len(findings) == 1
        assert findings[0].rule_id == "S004"

    def test_catches_percent_format(self):
        source = 'query = "SELECT * FROM users WHERE name = %s" % name'
        findings = run_rule(SQLInjectionRule, source)
        assert len(findings) == 1

    def test_catches_fstring(self):
        source = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = run_rule(SQLInjectionRule, source)
        assert len(findings) == 1

    def test_catches_format_method(self):
        source = 'query = "DELETE FROM {} WHERE id = {}".format(table, uid)'
        findings = run_rule(SQLInjectionRule, source)
        assert len(findings) == 1

    def test_parameterised_query_is_ok(self):
        source = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = run_rule(SQLInjectionRule, source)
        assert len(findings) == 0

    def test_non_sql_fstring_is_ok(self):
        source = 'msg = f"Hello {name}, welcome!"'
        findings = run_rule(SQLInjectionRule, source)
        assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════ #
#  S005 — Debug artefacts                                            #
# ══════════════════════════════════════════════════════════════════ #
class TestDebugArtifacts:

    def test_catches_flask_debug_true(self):
        source = 'app.run(debug=True)'
        findings = run_rule(DebugArtifactsRule, source)
        assert len(findings) == 1
        assert "debug=True" in findings[0].message

    def test_debug_false_is_ok(self):
        source = 'app.run(debug=False)'
        findings = run_rule(DebugArtifactsRule, source)
        assert len(findings) == 0

    def test_catches_hardcoded_ip(self):
        source = 'host = "192.168.1.50"'
        findings = run_rule(DebugArtifactsRule, source)
        assert len(findings) == 1

    def test_catches_bind_all_interfaces(self):
        source = 'host = "0.0.0.0"'
        findings = run_rule(DebugArtifactsRule, source)
        assert len(findings) == 1

    def test_localhost_is_ok(self):
        source = 'host = "127.0.0.1"'
        findings = run_rule(DebugArtifactsRule, source)
        assert len(findings) == 0

    def test_unrelated_variable_is_ok(self):
        source = 'server_name = "192.168.1.50"'
        findings = run_rule(DebugArtifactsRule, source)
        assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════ #
#  Integration — scan real fixture files                             #
# ══════════════════════════════════════════════════════════════════ #
class TestScannerIntegration:

    def test_insecure_file_has_findings(self):
        findings = scan_file(FIXTURE_DIR / "insecure_example.py")
        assert not isinstance(findings, Exception)
        assert len(findings) > 0

    def test_clean_file_has_no_findings(self):
        findings = scan_file(FIXTURE_DIR / "clean_example.py")
        assert not isinstance(findings, Exception)
        assert len(findings) == 0
