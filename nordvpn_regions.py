"""Country names and explicitly curated country groups."""

from __future__ import annotations
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# NordVPN uses a few provider-specific identifiers rather than ISO alpha-2 codes.
COUNTRY_ALIASES = {"uk": "gb"}


def normalise_country_code(code: str) -> str:
    """Convert a provider country identifier to its ISO alpha-2 equivalent."""
    code = code.lower()
    return COUNTRY_ALIASES.get(code, code)


def country_code(hostname: str) -> str | None:
    match = re.fullmatch(r"([a-z]{2})[0-9]+\.nordvpn\.com", hostname, re.I)
    return normalise_country_code(match.group(1)) if match else None


def country_name(hostname: str) -> str:
    code = country_code(hostname)
    if code is None:
        return "Unknown"
    names = json.loads((ROOT / "country-names.json").read_text(encoding="utf-8"))
    return names.get(code, "Unknown")


def country_flag(hostname: str) -> str:
    """Return a Unicode flag for a recognised ISO country, or an empty string."""
    code = country_code(hostname)
    if code is None:
        return ""
    names = json.loads((ROOT / "country-names.json").read_text(encoding="utf-8"))
    if code not in names:
        return ""
    return "".join(chr(0x1F1E6 + ord(letter) - ord("a")) for letter in code)


def load_region_lists(custom_file: Path | None = None) -> dict:
    """Custom definitions replace built-ins by name, never silently merge."""
    names = json.loads((ROOT / "country-names.json").read_text(encoding="utf-8"))
    groups = json.loads((ROOT / "region-lists.json").read_text(encoding="utf-8"))
    if custom_file is not None:
        custom = json.loads(custom_file.expanduser().read_text(encoding="utf-8"))
        if not isinstance(custom, dict):
            raise ValueError("region lists must be a JSON object")
        groups.update(custom)
    for name, item in groups.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", name):
            raise ValueError(f"invalid region list name: {name!r}")
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("description"), str)
            or not isinstance(item.get("countries"), list)
        ):
            raise ValueError(f"invalid region list definition: {name!r}")
        codes = item["countries"]
        if any(
            not isinstance(code, str) or code != code.lower() or normalise_country_code(code) not in names
            for code in codes
        ):
            raise ValueError(f"invalid country code in region list: {name!r}")
        canonical = [normalise_country_code(code) for code in codes]
        if len(canonical) != len(set(canonical)):
            raise ValueError(f"duplicate country code in region list: {name!r}")
        item["countries"] = canonical
    return groups
