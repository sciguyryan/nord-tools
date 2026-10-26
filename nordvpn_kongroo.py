"""An optional, unprivileged terminal puzzle unrelated to VPN management.

The bundled compressed scene uses a password-derived XOR stream and HMAC for
puzzle integrity. This is obfuscation, not protection of a genuine secret:
all material needed to inspect the puzzle is distributed with the source.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import json
import shutil
import zlib
import sys
import time
from typing import TextIO

SALT = b"nord-tools/worldline/1.048596"
# Encoded at development time; the answer is not stored as plaintext here.
CIPHERTEXT = "c2bbd20f7c6f9b165ebbc34f84bbae0b4745eabb222115dfae1b7ef7071f3825132198ee5602fe6042aad17c6ad7ee4145f032fd266146a1bed7b1fe66c3fb40d34b1905165d5877f8a96fb5c32fa5e441879ac273bc63e8bd71bc46519887e847dabf41805be5f2890145849bcff9b97782c8bb77723f5effbb89d94fee0dbb2216d9b981f5094df81330268a71848f824062e9c4445b6f0b34dac2d98c820fb113a22d370b943cec2f2033fb67d5a71010cef79d8e559b1dd61bcd01e361c8a9e447c3be0a82c42421b231d35dad074aa29b3cc9b65bc461de2b8cbb264b17d2d2ccc367cddf57f6b3323f7cd1d195389485ad8fc3a903272130fff025606b1f7acf23af127b9fdd26c67b2b279a2bf400805a0423b99bdd6bc9d7a79668acb2e9f79a739971dfb4"
TAG = "04941f31269f38a24bb3ba0293b892720d1d0876ae2909513d01e2eac6a1bd29"
CLUE = "The organisation's farewell, three words. Spaces matter; case does not."

# A deliberately uneven acquisition curve: bursts of progress alternate with
# slower verification intervals. Anchors are frame index and displayed percent.
ANIMATION_FRAMES = 120
FRAME_INTERVAL_SECONDS = 0.065
PROGRESS_ANCHORS = (
    (0, 0),
    (12, 24),
    (29, 30),
    (44, 57),
    (67, 63),
    (84, 85),
    (104, 90),
    (119, 100),
)


def _progress(step: int) -> int:
    """Interpolate monotonic progress without a uniform per-frame increment."""
    step = max(0, min(step, ANIMATION_FRAMES - 1))
    for (start, low), (end, high) in zip(PROGRESS_ANCHORS, PROGRESS_ANCHORS[1:]):
        if step <= end:
            fraction = (step - start) / (end - start)
            # Smooth acceleration and deceleration at each acquisition boundary.
            eased = fraction * fraction * (3 - 2 * fraction)
            return round(low + (high - low) * eased)
    return 100


def _stream(key: bytes, size: int) -> bytes:
    """Generate a deterministic puzzle stream using counter-separated HMAC."""
    result = bytearray()
    counter = 0
    while len(result) < size:
        result.extend(hmac.digest(key, counter.to_bytes(8, "big"), "sha256"))
        counter += 1
    return bytes(result[:size])


def _key(answer: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", answer.strip().casefold().encode(), SALT, 120_000)


def _payload(answer: str) -> dict[str, object] | None:
    """Authenticate and decompress the bundled scene without executing payload code."""
    key = _key(answer)
    ciphertext = bytes.fromhex(CIPHERTEXT)
    expected = hmac.digest(key, b"transmission:" + ciphertext, "sha256")
    if not hmac.compare_digest(expected, bytes.fromhex(TAG)):
        return None
    raw = bytes(a ^ b for a, b in zip(ciphertext, _stream(key, len(ciphertext))))
    scene = json.loads(zlib.decompress(raw).decode("utf-8"))
    if not isinstance(scene, dict) or not isinstance(scene.get("message"), list):
        raise ValueError("Invalid transmission scene")
    return scene


def decrypt(answer: str) -> str | None:
    """Return authenticated transmission text, or None for an incorrect answer."""
    scene = _payload(answer)
    return "\n".join(scene["message"]) if scene is not None else None


def render(message: str, *, unicode: bool, colour: bool) -> str:
    """Present the authenticated transmission as an eccentric lab printout.

    Deliberate asymmetry is part of the design, but every line remains bounded
    and static output requires neither cursor control nor terminal capabilities.
    """
    lines = message.splitlines()
    if not lines or any("\n" in line or "\r" in line for line in lines):
        raise ValueError("Invalid transmission text")
    width = max(52, min(76, max(len(line) for line in lines) + 10))
    horizontal = "═" if unicode else "="
    thin = "─" if unicode else "-"
    corner = "╔" if unicode else "+"
    top_right = "╗" if unicode else "+"
    # The jagged lab-paper edges are intentional, not terminal corruption.
    left = "║" if unicode else "|"
    right = "┃" if unicode else "|"
    header = "  F.G.L. / TOP SECRET / DO NOT LET THE ORGANISATION SEE THIS"
    output = [
        " " + corner + horizontal * (width - 2) + top_right,
        " " + left + header[: width - 4].ljust(width - 4) + " " + right,
        "   " + thin * (width - 7) + "  !",
        "   >> DECODED WORLDLINE INTERCEPT <<",
        "   [CAUTION] THE UNIVERSE HAS NOT SIGNED OFF ON THIS REPORT",
        "   " + thin * (width - 9),
    ]
    for index, line in enumerate(lines):
        prefix = ("  !! ", "    > ", "  >>> ", "      * ")[index % 4]
        output.append((prefix + line)[:width])
        if index == 1:
            output.append("   ...WAIT. RECHECK THAT NUMBER. AGAIN.")
    output.extend(
        [
            "   " + thin * (width - 13) + " ???",
            "       [TRANSMISSION ENDS?]  ...probably.",
            "  /" + horizontal * (width - 11) + "\\  (lab copy #001)",
        ]
    )
    result = "\n".join(output)
    return f"\033[32m{result}\033[0m" if colour else result


def _search_window(step: int, target: int) -> tuple[int, int]:
    """Narrow a fictional six-decimal worldline search around the target."""
    progress = _progress(step)
    # The radius shrinks in steps, with the existing uneven acquisition curve.
    radius = max(1, round(900_000 * (1 - progress / 100) ** 3))
    return max(0, target - radius), min(9_999_999, target + radius)


def _search_rows(alphabet: str, signature: str, step: int, count: int, width: int) -> list[str]:
    """Render deterministic candidate probes within an increasingly narrow interval.

    This is a theatrical numerical search, not a claim of real computation.
    The signature and hexadecimal alphabet originate in the authenticated scene.
    """
    if alphabet != "0123456789ABCDEF":
        raise ValueError("Invalid hexadecimal search alphabet")
    whole, dot, fraction = signature.partition(".")
    if not dot or not whole.isdigit() or len(fraction) != 6 or not fraction.isdigit():
        raise ValueError("Invalid worldline signature")
    target = int(whole) * 1_000_000 + int(fraction)
    low, high = _search_window(step, target)
    span = high - low
    rows = []
    for index in range(count):
        # Multiplicative mixing gives changing but reproducible candidate offsets.
        sample = (step * 2654435761 + index * 2246822519 + (index + 1) * step * 97) & 0xFFFFFFFF
        candidate = low + (sample % (span + 1))
        if step == ANIMATION_FRAMES - 1:
            candidate = target
        distance = abs(candidate - target)
        address = f"{sample & 0xFFFF:04X}:{(sample >> 16) & 0xFFFF:04X}"
        status = "LOCK" if candidate == target else ("NEAR" if distance <= max(10, span // 30) else "SCAN")
        line = f" {address}  {candidate // 1_000_000}.{candidate % 1_000_000:06d}  Δ{distance:07d}  {status}"
        rows.append(line[:width].ljust(width))
    return rows


def _frame(scene: dict[str, object], step: int, *, width: int, height: int, colour: bool) -> str:
    """Produce one bounded, deterministic numerical-search terminal frame."""
    width = max(40, min(width, 120))
    height = max(16, min(height, 42))
    phases = scene["phases"]
    phase = phases[min(_progress(step) * len(phases) // 101, len(phases) - 1)]
    signature = scene["signature"]
    alphabet = scene["glyphs"]
    target = int(signature.replace(".", ""))
    low, high = _search_window(step, target)
    inner = width - 4

    def cell(text: str) -> str:
        return text[: width - 2].ljust(width - 2)

    lines = ["╔" + "═" * (width - 2) + "╗"]
    lines.append("║" + cell("  FUTURE GADGET LAB // WORLDLINE OBSERVER") + "║")
    lines.append("╠" + "═" * (width - 2) + "╣")
    lines.append("║" + cell(f"  {phase}   //   {signature}") + "║")
    lines.append(
        "║"
        + cell(f"  RANGE  {low // 1_000_000}.{low % 1_000_000:06d} .. {high // 1_000_000}.{high % 1_000_000:06d}")
        + "║"
    )
    lines.append("║" + cell("  PROBE ADDRESS  CANDIDATE   DISTANCE   STATE") + "║")
    lines.append("╟" + "─" * (width - 2) + "╢")
    count = max(3, height - 11)
    for row in _search_rows(alphabet, signature, step, count, inner):
        lines.append("║ " + row + " ║")
    progress = _progress(step)
    filled = (width - 18) * progress // 100
    lines.append("║" + cell(f"  [{('█' * filled).ljust(width - 18, '░')}] {progress:3d}%") + "║")
    lines.append("║" + cell(f"  {scene['footer']}") + "║")
    lines.append("╚" + "═" * (width - 2) + "╝")
    frame = "\n".join(lines)
    return "\033[38;5;46m" + frame + "\033[0m" if colour else frame


def _animate(scene: dict[str, object], stream: TextIO, *, colour: bool) -> None:
    """Animate in an alternate screen, restoring cursor and screen even on interruption."""
    columns, rows = shutil.get_terminal_size((80, 24))
    if columns < 44 or rows < 19:
        print(render("\n".join(scene["message"]), unicode=True, colour=colour), file=stream)
        return
    stream.write("\033[?1049h\033[?25l")
    stream.flush()
    try:
        for step in range(ANIMATION_FRAMES):
            stream.write("\033[H\033[2J" + _frame(scene, step, width=columns, height=rows, colour=colour))
            stream.flush()
            time.sleep(FRAME_INTERVAL_SECONDS)
    finally:
        stream.write("\033[0m\033[?25h\033[?1049l")
        stream.flush()
    print(render("\n".join(scene["message"]), unicode=True, colour=colour), file=stream)


def main(argv: list[str] | None = None, *, output: TextIO | None = None) -> int:
    """Run the isolated puzzle without reading credentials or modifying networking."""
    parser = argparse.ArgumentParser(description="A curious transmission from another worldline.")
    parser.add_argument("--decode", metavar="PHRASE", help="Attempt to decode the transmission")
    parser.add_argument("--ascii", action="store_true", help="Use ASCII rather than Unicode borders")
    parser.add_argument("--no-colour", action="store_true", help="Disable ANSI colours")
    parser.add_argument("--no-animation", action="store_true", help="Disable the cinematic terminal reveal")
    args = parser.parse_args(argv)
    stream = output if output is not None else sys.stdout
    if args.decode is None:
        print("INTERCEPTED TRANSMISSION // 1.048596", file=stream)
        print(f"CLUE: {CLUE}", file=stream)
        print("Use --decode PHRASE to attempt decryption.", file=stream)
        return 0
    scene = _payload(args.decode)
    if scene is None:
        print("Transmission authentication failed. The worldline remains unchanged.", file=stream)
        return 1
    interactive = bool(getattr(stream, "isatty", lambda: False)())
    unicode = not args.ascii and interactive and (getattr(stream, "encoding", "") or "").lower().startswith("utf")
    colour = interactive and not args.no_colour and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    animated = (
        unicode
        and not args.no_animation
        and os.environ.get("NORD_TOOLS_REDUCED_MOTION") != "1"
        and os.environ.get("TERM") not in (None, "dumb")
    )
    if animated:
        _animate(scene, stream, colour=colour)
    else:
        print(render("\n".join(scene["message"]), unicode=unicode, colour=colour), file=stream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
