"""Tests for rule loading and model validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from model_firewall.models import Direction, Rule, Severity, Verdict
from model_firewall.rules import builtin_rules, load_rules_file
