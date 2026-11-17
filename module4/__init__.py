"""Compatibility entry point for the implementation in Module 4/module4."""
from pathlib import Path

_implementation = Path(__file__).resolve().parents[1] / "Module 4" / "module4"
__path__ = [str(_implementation)]
_initializer = _implementation / "__init__.py"
exec(compile(_initializer.read_bytes(), str(_initializer), "exec"))
