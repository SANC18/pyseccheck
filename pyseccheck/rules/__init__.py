"""
Rule registry.

All rules are collected here. The scanner imports RULES and runs each
one against every parsed file.

To add a new rule:
  1. Create pyseccheck/rules/sXXX_your_rule.py
  2. Define a class inheriting BaseRule
  3. Import and add it to RULES below — that's it.
"""
from .base import BaseRule, Finding, Severity
from .s001_hardcoded_secrets import HardcodedSecretRule
from .s002_dangerous_functions import DangerousFunctionsRule
from .s003_weak_crypto import WeakCryptoRule
from .s004_sql_injection import SQLInjectionRule
from .s005_debug_artifacts import DebugArtifactsRule

RULES: list[type[BaseRule]] = [
    HardcodedSecretRule,
    DangerousFunctionsRule,
    WeakCryptoRule,
    SQLInjectionRule,
    DebugArtifactsRule,
]

__all__ = ["RULES", "BaseRule", "Finding", "Severity", "SQLInjectionRule", "DebugArtifactsRule"]
