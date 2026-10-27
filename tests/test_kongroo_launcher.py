"""Keep the reproducible, obfuscated puzzle launcher aligned with its source."""

import base64
import re
import subprocess
import zlib
import sys
import unittest
from pathlib import Path

from tools.generate_kongroo_launcher import build, matches_source

ROOT = Path(__file__).resolve().parents[1]


class PackedLauncherTests(unittest.TestCase):
    def test_generated_launcher_matches_canonical_source(self):
        self.assertTrue(
            matches_source(
                (ROOT / "nordvpn_kongroo_packed.py").read_text(),
                (ROOT / "nordvpn_kongroo.py").read_bytes(),
            ),
            "Operation Kongroo launcher is stale. Run python tools/generate_kongroo_launcher.py after editing the readable source.",
        )

    def test_alternative_valid_zlib_stream_is_accepted(self):
        source = (ROOT / "nordvpn_kongroo.py").read_bytes()
        launcher = build(source)
        original = re.search(r'^_PAYLOAD = "([^"]+)"$', launcher, flags=re.MULTILINE)
        self.assertIsNotNone(original)
        alternative = base64.b85encode(zlib.compress(source, level=1)).decode("ascii")
        modified = launcher.replace(original.group(1), alternative, 1)
        self.assertNotEqual(modified, launcher)
        self.assertTrue(matches_source(modified, source))

    def test_modified_launcher_structure_is_rejected(self):
        source = (ROOT / "nordvpn_kongroo.py").read_bytes()
        self.assertFalse(matches_source(build(source).replace('"exec"', '"eval"'), source))
        self.assertFalse(matches_source(build(source).replace("_SOURCE_HASH =", "_WRONG_HASH ="), source))

    def test_corrupt_or_wrong_source_payload_is_rejected(self):
        source = (ROOT / "nordvpn_kongroo.py").read_bytes()
        launcher = build(source)
        self.assertFalse(matches_source(launcher.replace('_PAYLOAD = "', '_PAYLOAD = "!'), source))
        self.assertFalse(matches_source(launcher, source + b"\n"))

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
