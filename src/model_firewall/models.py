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
