#!/usr/bin/env python3
"""Regenerate the reproducible, obfuscated Operation Kongroo launcher.

This is presentation-only obfuscation. The readable source is retained in Git,
there is no key, and no secrecy or security boundary is claimed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nordvpn_kongroo.py"
DESTINATION = ROOT / "nordvpn_kongroo_packed.py"


def build(source: bytes) -> str:
    digest = hashlib.sha256(source).hexdigest()
    encoded = base64.b85encode(zlib.compress(source, level=9)).decode("ascii")
    return f'''"""Generated Operation Kongroo launcher; edit nordvpn_kongroo.py instead.

Regenerate with python tools/generate_kongroo_launcher.py. No key is used.
This is obfuscation for an Easter egg, not encryption or a security control.
"""

import base64
import hashlib
import zlib

_SOURCE_HASH = "{digest}"
_PAYLOAD = "{encoded}"
_source = zlib.decompress(base64.b85decode(_PAYLOAD))
if hashlib.sha256(_source).hexdigest() != _SOURCE_HASH:
    raise RuntimeError("Operation Kongroo launcher integrity check failed")
exec(compile(_source, "nordvpn_kongroo.py", "exec"), globals())
del _source

if __name__ == "__main__":
    raise SystemExit(globals()["main"]())
'''


def matches_source(launcher: str, source: bytes) -> bool:
    """Verify the complete launcher contract without assuming identical zlib output.

    zlib streams can vary across implementations even for identical input. Only
    the encoded payload may vary; the launcher structure and decoded bytes must
    match the canonical source exactly.
    """
    match = re.search(r'^_PAYLOAD = "([^"]+)"$', launcher, flags=re.MULTILINE)
    if match is None:
        return False
    try:
        compressed = base64.b85decode(match.group(1))
        decoded = zlib.decompress(compressed)
    except (ValueError, zlib.error):
        return False
    if decoded != source:
        return False
    expected = build(source)
    canonical_match = re.search(r'^_PAYLOAD = "([^"]+)"$', expected, flags=re.MULTILINE)
    assert canonical_match is not None
    return launcher[: match.start(1)] + canonical_match.group(1) + launcher[match.end(1) :] == expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify that the committed launcher is current")
    args = parser.parse_args()
    source = SOURCE.read_bytes()
    if args.check:
        if not DESTINATION.exists() or not matches_source(DESTINATION.read_text(encoding="utf-8"), source):
            print("Operation Kongroo launcher is stale; regenerate it")
            return 1
        print("Operation Kongroo launcher is current")
        return 0
    DESTINATION.write_text(build(source), encoding="utf-8")
    print("Regenerated Operation Kongroo launcher")
    return 0


if __name__ == "__main__":
    raise SystemExit(globals()["main"]())
