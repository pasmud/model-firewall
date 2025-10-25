"""Tests for rule loading and model validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from model_firewall.models import Direction, Rule, Severity, Verdict
from model_firewall.rules import builtin_rules, load_rules_file


class RuleModelTests(unittest.TestCase):
    def test_builtin_rules_are_valid(self) -> None:
        rules = builtin_rules()
        self.assertGreaterEqual(len(rules), 8)
        ids = [rule.id for rule in rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rule_from_dict_round_trip(self) -> None:
        payload = {
            "id": "X-1",
            "name": "Example",
            "description": "Example rule",
            "pattern": "example",
            "direction": "input",
            "severity": "high",
            "action": "block",
            "enabled": True,
            "tags": ["test"],
        }
        rule = Rule.from_dict(payload)
        self.assertEqual(rule.direction, Direction.INPUT)
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.action, Verdict.BLOCK)
        self.assertEqual(rule.to_dict()["tags"], ["test"])

    def test_rule_from_dict_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ValueError):
            Rule.from_dict(
                {
                    "id": "X-1",
                    "name": "Example",
                    "description": "Example rule",
                    "pattern": "example",
                    "unknown": "nope",
                }
            )

    def test_load_rules_file(self) -> None:
        payload = {
            "rules": [
                {
                    "id": "CUSTOM-9",
                    "name": "Codename",
                    "description": "Detects codename",
                    "pattern": "project phoenix",
                    "direction": "output",
                    "severity": "medium",
                    "action": "flag",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rules.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            rules = load_rules_file(path)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].id, "CUSTOM-9")
        self.assertEqual(rules[0].direction, Direction.OUTPUT)

    def test_load_rules_file_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rules.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules_file(path)


if __name__ == "__main__":
    unittest.main()
