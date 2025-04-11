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

    @classmethod
    def from_rule_files(
        cls,
        paths: Iterable[str | Path],
        *,
        include_builtin: bool = True,
        config: FirewallConfig | None = None,
    ) -> "Firewall":
        rules: list[Rule] = []
        if include_builtin:
            rules.extend(builtin_rules())
        for path in paths:
            rules.extend(load_rules_file(path))
        return cls(rules=rules, config=config or FirewallConfig())

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def _redact(self, text: str) -> str:
        if not self.config.redact_matches:
            return text
        if len(text) <= self.config.redact_keep_start + self.config.redact_keep_end:
            return "*" * len(text)
        start = text[: self.config.redact_keep_start]
        end = text[-self.config.redact_keep_end :] if self.config.redact_keep_end else ""
        middle_len = max(0, len(text) - len(start) - len(end))
        return f"{start}{'*' * middle_len}{end}"

    def evaluate(self, text: str, direction: str | Direction = Direction.INPUT) -> Report:
        """Evaluate text in a given direction and return a Report."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        direction = Direction.from_value(direction)

        findings: list[Finding] = []
        verdict = self.config.default_verdict
        rules_evaluated = 0

        for compiled in self._compiled:
            rule = compiled.rule
            if not rule.enabled:
                continue
            if not rule.direction.matches(direction):
                continue
            rules_evaluated += 1
            matches = list(compiled.regex.finditer(text))
            if not matches:
                continue
            for match in matches:
                matched_text = match.group(0)
                finding = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    action=rule.action,
                    direction=direction,
                    message=rule.description,
                    match=self._redact(matched_text),
                    span=(match.start(), match.end()),
                )
                findings.append(finding)
                verdict = Verdict.combine(verdict, rule.action)
                if (
                    self.config.max_findings is not None
                    and len(findings) >= self.config.max_findings
                ):
                    return Report(
                        direction=direction,
                        verdict=verdict,
                        findings=findings,
                        text_length=len(text),
                        rules_evaluated=rules_evaluated,
                        metadata={"truncated": True},
                    )

        return Report(
            direction=direction,
            verdict=verdict,
            findings=findings,
            text_length=len(text),
            rules_evaluated=rules_evaluated,
            metadata={"truncated": False},
        )
