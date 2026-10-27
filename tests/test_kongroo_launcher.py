"""Keep the reproducible, obfuscated puzzle launcher aligned with its source."""

import subprocess
import sys
import unittest
from pathlib import Path

from tools.generate_kongroo_launcher import build

ROOT = Path(__file__).resolve().parents[1]


class PackedLauncherTests(unittest.TestCase):
    def test_generated_launcher_matches_canonical_source(self):
        self.assertEqual(
            (ROOT / "nordvpn_kongroo_packed.py").read_text(),
            build((ROOT / "nordvpn_kongroo.py").read_bytes()),
            "Operation Kongroo launcher is stale. Run python tools/generate_kongroo_launcher.py after editing or formatting the readable source.",
        )

    def test_packed_launcher_matches_readable_entrypoint(self):
        for args in ([], ["--decode", "incorrect"], ["--decode", "el psy kongroo", "--no-animation"]):
            results = [
                subprocess.run(
                    [sys.executable, str(ROOT / module), *args],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                for module in ("nordvpn_kongroo.py", "nordvpn_kongroo_packed.py")
            ]
            self.assertEqual((results[0].returncode, results[0].stdout), (results[1].returncode, results[1].stdout))
