"""Evaluation engine for the model firewall."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Direction, Finding, Report, Rule, Verdict
from .rules import builtin_rules, load_rules_file


class RuleCompilationError(ValueError):
    """Raised when a rule pattern cannot be compiled."""


@dataclass
class FirewallConfig:
    """Configuration for Firewall behavior."""

    default_verdict: Verdict = Verdict.ALLOW
    max_findings: int | None = None
    redact_matches: bool = False
    redact_keep_start: int = 2
