"""Tests for the firewall evaluation engine."""

from __future__ import annotations

import unittest

from model_firewall.engine import Firewall, FirewallConfig
from model_firewall.models import Direction, Rule, Severity, Verdict


class FirewallEngineTests(unittest.TestCase):
    def test_allows_benign_input(self) -> None:
        firewall = Firewall()
        report = firewall.evaluate("Summarize the quarterly sales report.", Direction.INPUT)
        self.assertEqual(report.verdict, Verdict.ALLOW)
        self.assertEqual(report.findings, [])
        self.assertTrue(report.allowed)
