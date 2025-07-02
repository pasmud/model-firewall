"""Built-in firewall rules and rule loading utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Direction, Rule, Severity, Verdict


def builtin_rules() -> list[Rule]:
    """Return the default built-in rule set.

    The rules are intentionally conservative and deterministic. They focus on
    common LLM application risks: prompt injection, secret exfiltration requests,
    credential leakage in outputs, and obvious PII exposure.
    """
