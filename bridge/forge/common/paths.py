"""Package sources and explicitly selected operator data have distinct owners."""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = Path(os.environ["REA_FORGE_STATIC_CONFIG"])
PRIVATE_ROOT = Path(os.environ["REA_FORGE_DATA_ROOT"])
if not CONFIG_PATH.is_absolute() or not PRIVATE_ROOT.is_absolute():
    raise ValueError("Forge configuration and data root must be explicit absolute paths")
