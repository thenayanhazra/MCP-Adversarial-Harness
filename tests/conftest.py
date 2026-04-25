"""Shared fixtures for the test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the fixture server is importable
sys.path.insert(0, str(Path(__file__).parent))

VULN_SERVER_PATH = Path(__file__).parent / "fixtures" / "vulnerable_server" / "server.py"
VULN_SERVER_SPEC = f"stdio:{sys.executable} {VULN_SERVER_PATH}"
