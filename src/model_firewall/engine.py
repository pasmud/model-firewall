"""Evaluation engine for the model firewall."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Direction, Finding, Report, Rule, Verdict
