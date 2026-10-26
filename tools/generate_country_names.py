"""Regenerate the committed ISO 3166-1 country-name snapshot.

Requires pycountry==24.6.1 only when regenerating or checking the snapshot.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pycountry

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "country-names.json"


def render() -> str:
    names = {country.alpha_2.lower(): country.name for country in pycountry.countries}
    return json.dumps(dict(sorted(names.items())), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the snapshot is out of date")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            parser.exit(1, "country-names.json differs from generated ISO data; regenerate it\n")
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
