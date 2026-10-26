#!/usr/bin/env python3
"""Compare paired fixed and adaptive benchmark reports without network access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys


def load_report(path: Path, adaptive: bool) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if (
        data.get("schema_version") != 1
        or not isinstance(data.get("ranking"), list)
        or not isinstance(data.get("measurements"), list)
    ):
        raise ValueError(f"{path}: unsupported or incomplete benchmark report")
    settings = data.get("settings", {})
    if settings.get("adaptive_enabled") is not adaptive:
        raise ValueError(f"{path}: expected {'adaptive' if adaptive else 'fixed'} sampling")
    for row in data["measurements"]:
        if not isinstance(row.get("sent"), int) or row["sent"] < 0:
            raise ValueError(f"{path}: invalid measurement attempt count")
    return data


def identity(row: dict) -> tuple[str, str]:
    return row["server"], row["address"]


def compare_pair(fixed: dict, adaptive: dict, top: int) -> dict:
    # The comparison is meaningful only for matching benchmark policies.
    fields = ("probe", "protocol", "accuracy", "top", "workers", "timeout_seconds", "filters", "region_lists")
    for field in fields:
        if fixed["settings"].get(field) != adaptive["settings"].get(field):
            raise ValueError(f"benchmark setting differs: {field}")
    for field in ("kind", "url", "archive_sha256"):
        if fixed.get("source", {}).get(field) != adaptive.get("source", {}).get(field):
            raise ValueError(f"catalogue provenance differs: {field}")
    for field in ("survey_samples_per_target", "refinement_additional_samples_per_target"):
        if fixed.get("methodology", {}).get(field) != adaptive.get("methodology", {}).get(field):
            raise ValueError(f"sampling budget differs: {field}")
    f_rank = [identity(row) for row in fixed["ranking"] if row.get("received", 0) > 0]
    a_rank = [identity(row) for row in adaptive["ranking"] if row.get("received", 0) > 0]
    f_top, a_top = set(f_rank[:top]), set(a_rank[:top])
    f_attempts = sum(row["sent"] for row in fixed["measurements"])
    a_attempts = sum(row["sent"] for row in adaptive["measurements"])
    return {
        "fixed_attempts": f_attempts,
        "adaptive_attempts": a_attempts,
        "saved_attempts": f_attempts - a_attempts,
        "saved_percent": (100 * (f_attempts - a_attempts) / f_attempts) if f_attempts else 0.0,
        "top_overlap": len(f_top & a_top),
        "top_denominator": len(f_top | a_top),
        "same_winner": bool(f_rank and a_rank and f_rank[0] == a_rank[0]),
        "fixed_winner": f_rank[0] if f_rank else None,
        "adaptive_winner": a_rank[0] if a_rank else None,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed", type=Path, nargs="+", required=True, help="fixed-run reports in pair order")
    parser.add_argument("--adaptive", type=Path, nargs="+", required=True, help="adaptive-run reports in pair order")
    parser.add_argument("--top", type=int, default=10, help="top-ranked servers to compare (default: 10)")
    args = parser.parse_args(argv)
    if len(args.fixed) != len(args.adaptive) or args.top < 1:
        parser.error("provide equal numbers of fixed and adaptive reports and a positive --top")
    try:
        comparisons = [
            compare_pair(load_report(f, False), load_report(a, True), args.top)
            for f, a in zip(args.fixed, args.adaptive)
        ]
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Paired runs: {len(comparisons)} | top-{args.top} comparison")
    for number, result in enumerate(comparisons, 1):
        print(
            f"Pair {number}: fixed {result['fixed_attempts']} attempts; adaptive "
            f"{result['adaptive_attempts']}; saved {result['saved_percent']:.1f}%; "
            f"top-set overlap {result['top_overlap']}/{result['top_denominator']}; "
            f"same winner: {'yes' if result['same_winner'] else 'no'}"
        )
    print(f"Median attempt reduction: {statistics.median(item['saved_percent'] for item in comparisons):.1f}%")
    print(f"Winner agreement: {sum(item['same_winner'] for item in comparisons)}/{len(comparisons)} pairs")
    print("Interpretation: runs are sequential, not simultaneous; changing network conditions can affect rankings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
