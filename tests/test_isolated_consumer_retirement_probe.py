"""The isolated retirement acceptance probe is opt-in and safe by default."""

import subprocess
import sys
from pathlib import Path


def test_isolated_consumer_probe_defaults_to_dry_run():
    script = Path(__file__).resolve().parents[1] / "tools" / "probe_isolated_consumer_retirement.py"
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr
    assert "DRY RUN" in result.stdout
    assert "No changes made" in result.stdout
