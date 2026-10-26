#!/usr/bin/env python3
"""Regenerate the encrypted Kongroo scene without retaining plaintext in Git.

The puzzle's password-derived XOR stream and HMAC are intentionally not
cryptographic protection for real secrets. This tool preserves the existing
scene format so the runtime can authenticate regenerated payloads.
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import json
import re
import sys
import zlib
from pathlib import Path

# Permit direct execution from the repository root or another working directory.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from nordvpn_kongroo import _key, _payload, _stream  # noqa: E402


def encode_scene(scene: dict[str, object], phrase: str) -> tuple[str, str]:
    """Return ciphertext and authentication tag in the runtime's wire format."""
    if not phrase.strip():
        raise ValueError("The decoding phrase must not be empty")
    if not isinstance(scene, dict) or not isinstance(scene.get("message"), list):
        raise ValueError("Scene must be an object containing a message list")
    if not scene["message"] or not all(isinstance(line, str) for line in scene["message"]):
        raise ValueError("The message must contain text lines")
    if (
        not isinstance(scene.get("phases"), list)
        or not scene["phases"]
        or not all(isinstance(phase, str) for phase in scene["phases"])
    ):
        raise ValueError("The scene must contain text phases")
    if scene.get("glyphs") != "0123456789ABCDEF":
        raise ValueError("The hexadecimal glyph alphabet must contain all sixteen digits")
    signature = scene.get("signature")
    if not isinstance(signature, str) or re.fullmatch(r"[0-9]+\.[0-9]{6}", signature) is None:
        raise ValueError("The worldline signature must have six decimal places")
    if not isinstance(scene.get("footer"), str):
        raise ValueError("The scene must contain a text footer")
    raw = json.dumps(scene, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=9)
    key = _key(phrase)
    ciphertext = bytes(a ^ b for a, b in zip(compressed, _stream(key, len(compressed))))
    tag = hmac.digest(key, b"transmission:" + ciphertext, "sha256")
    return ciphertext.hex(), tag.hex()


def replace_constants(source: str, ciphertext: str, tag: str) -> str:
    """Replace only the two blob constants, refusing unexpected source layouts."""
    for name, value in (("CIPHERTEXT", ciphertext), ("TAG", tag)):
        pattern = rf'(?m)^{name} = "[0-9a-f]+"$'
        updated, count = re.subn(pattern, f'{name} = "{value}"', source)
        if count != 1:
            raise ValueError(f"Expected exactly one {name} constant; source left unchanged")
        source = updated
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--scene", type=Path, help="JSON scene file (keep plaintext outside Git)")
    source.add_argument("--current", action="store_true", help="Decrypt the bundled scene using the old phrase")
    parser.add_argument("--old-phrase", help="Old decoding phrase for --current; otherwise prompted securely")
    parser.add_argument("--phrase", help="New decoding phrase; otherwise prompted securely")
    parser.add_argument(
        "--update-module", action="store_true", help="Replace only CIPHERTEXT and TAG in nordvpn_kongroo.py"
    )
    args = parser.parse_args(argv)
    if args.old_phrase is not None and not args.current:
        parser.error("--old-phrase requires --current")
    try:
        if args.current:
            old_phrase = (
                args.old_phrase if args.old_phrase is not None else getpass.getpass("Current decoding phrase: ")
            )
            scene = _payload(old_phrase)
            if scene is None:
                raise ValueError("Current phrase does not authenticate the bundled scene")
        else:
            scene = json.loads(args.scene.read_text(encoding="utf-8"))
        phrase = args.phrase if args.phrase is not None else getpass.getpass("New decoding phrase: ")
        ciphertext, tag = encode_scene(scene, phrase)
        if args.update_module:
            module = ROOT / "nordvpn_kongroo.py"
            old_source = module.read_text(encoding="utf-8")
            new_source = replace_constants(old_source, ciphertext, tag)
            module.write_text(new_source, encoding="utf-8")
            print("Updated nordvpn_kongroo.py ciphertext and tag; test decryption with the new phrase.")
        else:
            print(f'CIPHERTEXT = "{ciphertext}"')
            print(f'TAG = "{tag}"')
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"Cannot generate transmission: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
