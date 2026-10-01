"""ANCHOR v1 — repository-adapter attach test scaffold.

This file registers (and validates) the module under test so the repository's
own import paths resolve before any downstream import deepens. It exists for
hermetic CI and is mirrored into the Anchor repository at
tests/test_anchor_repository_adapter_attach.py by the task runner.
"""

import sys
import types
from pathlib import Path

# ---------------------------------------------------------------------------
# Validate the attach path is the repository root we expect
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
ANCHOR_V1_DIR = REPO_ROOT / "src" / "anchor_v1"

if not ANCHOR_V1_DIR.is_dir():
    raise RuntimeError(
        f"attach scaffold misconfigured: expected {ANCHOR_V1_DIR} to exist "
        f"under {REPO_ROOT}"
    )


def _register_anchor_v1() -> types.ModuleType:
    """Insert anchor_v1 above any installed copy in sys.path so the
    repository copy is imported first.

    This mirrors the repository-adapter attach logic in the task runner, and
    doubles as a self-check that the directory layout is what we expect.
    """
    anchor = types.ModuleType("anchor_v1")
    anchor.__path__ = [str(ANCHOR_V1_DIR)]
    anchor.__package__ = "anchor_v1"
    sys.modules.setdefault("anchor_v1", anchor)
    return anchor


def validate_attach_paths() -> dict:
    """Self-test that the attach machinery resolves the repository copy and
    that the target module tree is present."""
    anchor = _register_anchor_v1()
    found = {
        "repo_root": str(REPO_ROOT),
        "anchor_v1_dir": str(ANCHOR_V1_DIR),
        "anchor_v1_registered": sys.modules.get("anchor_v1") is anchor,
        "py_dir_listing": sorted(p.name for p in ANCHOR_V1_DIR.iterdir()),
    }
    return found


if __name__ == "__main__":
    result = validate_attach_paths()
    for key, value in result.items():
        print(f"{key}: {value}")
