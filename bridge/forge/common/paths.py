"""Paths resolved from this checkout, never from the former installation."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
PRIVATE_ROOT = PROJECT_ROOT / ".forge-local"
CONFIG_PATH = PRIVATE_ROOT / "config" / "tools.json"
