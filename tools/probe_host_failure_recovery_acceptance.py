#!/usr/bin/env python3
"""Accept host-default failure and recovery guarantees in a disposable guest."""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.probe_host_domain_acceptance import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(phase="d2"))
