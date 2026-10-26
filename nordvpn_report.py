"""Versioned, self-contained benchmark reports with atomic file replacement."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

SCHEMA_VERSION = 1


def timestamp():
    """Return an explicit UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_report(*, started_at, finished_at, settings, source, methodology, records, ranked, stability=None):
    """Capture measured facts and their interpretation without modifying either."""
    report = {
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "finished_at": finished_at,
        "settings": settings,
        "source": source,
        "methodology": methodology,
        "measurements": records,
        "ranking": ranked,
    }
    if stability is not None:
        report["stability"] = stability
    return report


def write_report(path: Path, report):
    """Write only complete reports, leaving an existing report intact on failure."""
    path = Path(path)
    data = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=".benchmark-report-", suffix=".tmp", delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
