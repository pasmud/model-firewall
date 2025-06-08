"""Data models for the model firewall."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Direction(str, Enum):
    """Direction a rule applies to."""

    INPUT = "input"
    OUTPUT = "output"
    BOTH = "both"

    @classmethod
    def from_value(cls, value: str | Direction) -> "Direction":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(
            f"unknown direction {value!r}; expected one of: "
            + ", ".join(m.value for m in cls)
        )

    def matches(self, direction: "Direction") -> bool:
        if self is Direction.BOTH:
            return True
        if direction is Direction.BOTH:
            return True
        return self is direction


class Severity(str, Enum):
    """Severity of a rule finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_value(cls, value: str | Severity) -> "Severity":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(
            f"unknown severity {value!r}; expected one of: "
            + ", ".join(m.value for m in cls)
        )

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Verdict(str, Enum):
    """Overall verdict for an evaluated text."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"

    @classmethod
    def from_value(cls, value: str | Verdict) -> "Verdict":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(
            f"unknown verdict {value!r}; expected one of: "
            + ", ".join(m.value for m in cls)
        )

    @property
    def rank(self) -> int:
        return {
            Verdict.ALLOW: 0,
            Verdict.FLAG: 1,
            Verdict.BLOCK: 2,
        }[self]

    @classmethod
    def combine(cls, left: "Verdict", right: "Verdict") -> "Verdict":
        return left if left.rank >= right.rank else right


@dataclass(frozen=True)
class Rule:
    """A firewall rule definition."""

    id: str
    name: str
    description: str
    pattern: str
    direction: Direction = Direction.BOTH
    severity: Severity = Severity.MEDIUM
    action: Verdict = Verdict.FLAG
    enabled: bool = True
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("rule id must not be empty")
        if not self.name or not self.name.strip():
            raise ValueError("rule name must not be empty")
        if not self.pattern:
            raise ValueError("rule pattern must not be empty")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        if not isinstance(data, dict):
            raise ValueError("rule definition must be an object")
        required = {"id", "name", "description", "pattern"}
        missing = required - set(data)
        if missing:
            raise ValueError(
                "rule definition missing required fields: " + ", ".join(sorted(missing))
            )
        unknown = set(data) - {
            "id",
            "name",
            "description",
            "pattern",
            "direction",
            "severity",
            "action",
            "enabled",
            "tags",
        }
        if unknown:
            raise ValueError(
                "rule definition has unknown fields: " + ", ".join(sorted(unknown))
            )
        tags = data.get("tags", ())
        if isinstance(tags, list):
            tags = tuple(str(tag) for tag in tags)
        elif isinstance(tags, tuple):
            tags = tuple(str(tag) for tag in tags)
        else:
            raise ValueError("rule tags must be a list of strings")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            description=str(data["description"]),
            pattern=str(data["pattern"]),
            direction=Direction.from_value(data.get("direction", Direction.BOTH)),
            severity=Severity.from_value(data.get("severity", Severity.MEDIUM)),
            action=Verdict.from_value(data.get("action", Verdict.FLAG)),
            enabled=bool(data.get("enabled", True)),
            tags=tags,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "direction": self.direction.value,
            "severity": self.severity.value,
            "action": self.action.value,
            "enabled": self.enabled,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class Finding:
    """A single rule match found in text."""

    rule_id: str
    rule_name: str
    severity: Severity
    action: Verdict
    direction: Direction
    message: str
    match: str
    span: tuple[int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "action": self.action.value,
            "direction": self.direction.value,
            "message": self.message,
            "match": self.match,
            "span": [self.span[0], self.span[1]],
        }


@dataclass
class Report:
    """Result of evaluating text against the firewall."""

    direction: Direction
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    text_length: int = 0
    rules_evaluated: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK
