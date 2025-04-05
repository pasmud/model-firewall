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
    redact_keep_end: int = 2

    def __post_init__(self) -> None:
        if self.max_findings is not None and self.max_findings < 1:
            raise ValueError("max_findings must be >= 1 when provided")
        if self.redact_keep_start < 0 or self.redact_keep_end < 0:
            raise ValueError("redact keep values must be >= 0")


@dataclass
class _CompiledRule:
    rule: Rule
    regex: re.Pattern[str]


@dataclass
class Firewall:
    """Evaluate text against a set of firewall rules."""

    rules: list[Rule] = field(default_factory=builtin_rules)
    config: FirewallConfig = field(default_factory=FirewallConfig)
    _compiled: list[_CompiledRule] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        self._compiled = []
        for rule in self.rules:
            try:
                compiled = re.compile(rule.pattern)
            except re.error as exc:
                raise RuleCompilationError(
                    f"invalid regex for rule {rule.id!r}: {exc}"
                ) from exc
            self._compiled.append(_CompiledRule(rule=rule, regex=compiled))
