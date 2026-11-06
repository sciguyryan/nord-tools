"""The routing-mode acceptance runner requires explicit privileged opt-in."""

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "probe_application_routing_modes.py"


def test_preview_is_non_mutating():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "PREVIEW:" in result.stdout


def test_privileged_probe_requires_identity():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--run-privileged"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "uid" in result.stderr
