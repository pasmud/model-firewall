"""Data models for the model firewall."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Direction(str, Enum):
    """Direction a rule applies to."""

    INPUT = "input"
    OUTPUT = "output"
