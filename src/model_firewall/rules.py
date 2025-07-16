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

    return [
        Rule(
            id="INJ-001",
            name="Ignore previous instructions",
            description="Detects prompt-injection attempts that ask the model to ignore prior instructions.",
            pattern=r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier)\b.{0,40}\b(instructions?|messages?|prompts?)\b",
            direction=Direction.INPUT,
            severity=Severity.HIGH,
            action=Verdict.BLOCK,
            tags=("prompt-injection", "instruction-override"),
        ),
        Rule(
            id="INJ-002",
            name="System prompt exfiltration",
            description="Detects requests to reveal system/developer prompts or hidden policies.",
            pattern=r"(?i)\b(reveal|show|print|dump|expose|repeat)\b.{0,50}\b(system prompt|developer message|hidden instructions?|internal policy|chain of thought)\b",
            direction=Direction.INPUT,
            severity=Severity.HIGH,
            action=Verdict.BLOCK,
            tags=("prompt-injection", "exfiltration"),
        ),
        Rule(
            id="INJ-003",
            name="Jailbreak role-play",
            description="Detects common jailbreak framing such as DAN or unrestricted mode.",
            pattern=r"(?i)\b(do anything now|\bdan\b|developer mode|jailbreak|unrestricted mode|act as an evil|no rules apply)\b",
            direction=Direction.INPUT,
            severity=Severity.HIGH,
            action=Verdict.BLOCK,
            tags=("prompt-injection", "jailbreak"),
        ),
        Rule(
            id="SEC-001",
            name="Shell or destructive command request",
            description="Flags requests that include obviously dangerous shell commands.",
            pattern=r"(?i)\b(rm\s+-rf\b|curl\s+.+\|\s*(?:ba)?sh|wget\s+.+\|\s*(?:ba)?sh|powershell\s+-enc|mkfs\.|:\(\)\s*\{\s*:\|:\&\s*\};:)\b",
            direction=Direction.INPUT,
            severity=Severity.CRITICAL,
            action=Verdict.BLOCK,
            tags=("command-injection", "malware"),
        ),
        Rule(
            id="PII-001",
            name="Email address",
            description="Detects email addresses in text.",
            pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            direction=Direction.BOTH,
            severity=Severity.MEDIUM,
            action=Verdict.FLAG,
            tags=("pii", "email"),
        ),
        Rule(
            id="PII-002",
            name="US Social Security Number",
            description="Detects common U.S. SSN formatting.",
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            direction=Direction.BOTH,
            severity=Severity.HIGH,
            action=Verdict.BLOCK,
            tags=("pii", "ssn"),
        ),
        Rule(
            id="PII-003",
            name="Credit card number",
            description="Detects common 13-16 digit card-like number sequences.",
            pattern=r"\b(?:\d[ -]*?){13,16}\b",
            direction=Direction.BOTH,
            severity=Severity.HIGH,
            action=Verdict.BLOCK,
            tags=("pii", "payment"),
        ),
        Rule(
            id="SEC-002",
            name="Private key material",
            description="Detects private key blocks in text.",
            pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            direction=Direction.BOTH,
            severity=Severity.CRITICAL,
            action=Verdict.BLOCK,
            tags=("secret", "credential"),
        ),
        Rule(
            id="SEC-003",
            name="API key assignment",
            description="Flags obvious API key or token assignments.",
            pattern=r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
            direction=Direction.BOTH,
            severity=Severity.HIGH,
            action=Verdict.BLOCK,
            tags=("secret", "credential"),
        ),
        Rule(
            id="OUT-001",
            name="Unsafe medical or legal certainty",
            description="Flags outputs that present high-stakes advice with unwarranted certainty.",
            pattern=r"(?i)\b(guaranteed cure|you definitely have|I am certain you have|this is not legal advice but you should definitely|ignore your doctor)\b",
            direction=Direction.OUTPUT,
            severity=Severity.MEDIUM,
            action=Verdict.FLAG,
            tags=("safety", "compliance"),
        ),
    ]


def _normalize_rule_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if "rules" in payload:
            rules = payload["rules"]
        else:
            raise ValueError("rule file object must contain a 'rules' list")
    elif isinstance(payload, list):
        rules = payload
    else:
        raise ValueError("rule file must contain a list or an object with 'rules'")

    if not isinstance(rules, list):
        raise ValueError("'rules' must be a list")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(rules):
        if not isinstance(item, dict):
            raise ValueError(f"rule at index {index} must be an object")
        normalized.append(item)
    return normalized


def load_rules_file(path: str | Path) -> list[Rule]:
    """Load rules from a JSON file."""
