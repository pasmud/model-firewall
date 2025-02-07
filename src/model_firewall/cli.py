"""Command-line interface for model-firewall."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .engine import Firewall, FirewallConfig
from .models import Direction, Verdict
from .rules import builtin_rules, dump_rules


EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="model-firewall",
        description="Evaluate LLM inputs/outputs against firewall rules.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="model-firewall 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Scan text or a file for firewall rule matches.",
        description="Scan input/output text against firewall rules and emit a report.",
    )
    scan.add_argument("--text", help="Text to scan. Use '-' to read from stdin.")
    scan.add_argument("--file", help="Path to a UTF-8 text file to scan.")
    scan.add_argument(
        "--direction",
        choices=[d.value for d in Direction if d is not Direction.BOTH],
        default=Direction.INPUT.value,
        help="Evaluation direction (default: input).",
    )
    scan.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="Additional JSON rules file. May be provided multiple times.",
    )
    scan.add_argument(
        "--no-builtin",
        action="store_true",
        help="Disable built-in rules (use only rules from --rules).",
    )
    scan.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json).",
    )
    scan.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Stop after N findings (default: unlimited).",
    )
    scan.add_argument(
        "--redact-matches",
        action="store_true",
        help="Redact matched text in findings.",
    )
    scan.add_argument(
        "--fail-on",
        choices=[v.value for v in Verdict],
        default=Verdict.BLOCK.value,
        help="Exit with code 1 when verdict is at or above this level (default: block).",
    )
    scan.add_argument(
        "--output",
        help="Write report to a file instead of stdout.",
    )

    rules_cmd = subparsers.add_parser(
        "rules",
        help="List built-in rules as JSON.",
        description="Print the built-in firewall rules.",
    )
