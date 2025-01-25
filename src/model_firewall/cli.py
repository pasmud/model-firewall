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
