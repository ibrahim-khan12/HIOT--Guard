"""Compatibility entry point; the implementation lives in Module 3/module3.

Keep python -m module3 working from the checkout root without copying code.
"""
from pathlib import Path

__path__ = [str(Path(__file__).resolve().parents[1] / "Module 3" / "module3")]
from ._version import SCHEMA_VERSION
