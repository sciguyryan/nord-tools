"""Real-process acceptance of cooperating lifecycle lock continuity."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "probe_lifecycle_lock_concurrency.py"


@unittest.skipUnless(sys.platform == "linux", "Linux file locking required")
class LifecycleProcessConcurrencyTests(unittest.TestCase):
    def test_disposable_real_process_lock_and_sigkill_recovery(self):
        result = subprocess.run(
            [sys.executable, str(PROBE), "--run"],
            capture_output=True,
            text=True,
            timeout=35,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("PASS:"), 4)
        self.assertIn("waiting contender refuses a replaced lifecycle lock inode", result.stdout)

    def test_default_invocation_is_non_mutating(self):
        result = subprocess.run(
            [sys.executable, str(PROBE)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Dry run", result.stdout)
