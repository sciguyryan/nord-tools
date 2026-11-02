#!/usr/bin/env python3
"""Exercise cooperating lifecycle lock exclusion across real Linux processes.

This probe touches only a private temporary directory. It never modifies VPN,
network namespace, routing, DNS or firewall state. It does not simulate an
independent privileged adversary that ignores the lock.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

WORKER = """\
import os, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
journal = Path(sys.argv[2]); marker = Path(sys.argv[3]); mode = sys.argv[4]
with lifecycle_execution_lock(journal):
    marker.write_text('entered', encoding='ascii')
    if mode == 'hold':
        while True: time.sleep(0.05)
"""


def _spawn(journal: Path, marker: Path, mode: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", WORKER, str(ROOT), str(journal), str(marker), mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for_marker(marker: Path, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker.exists():
            return
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise RuntimeError(f"lock worker exited before entering: {stderr.strip()}")
        time.sleep(0.02)
    raise RuntimeError("lock worker did not enter within the timeout")


def run_probe(timeout: float = 8.0) -> None:
    if sys.platform != "linux":
        raise RuntimeError("this process-concurrency probe requires Linux")
    with tempfile.TemporaryDirectory(prefix="nt-lock-concurrency-") as temporary:
        parent = Path(temporary) / "authority"
        parent.mkdir(mode=0o700)
        journal = parent / "journal.json"
        lock = parent / "journal.json.restore.lock"
        first_marker = parent / "first.entered"
        second_marker = parent / "second.entered"
        first = _spawn(journal, first_marker, "hold")
        second = None
        try:
            _wait_for_marker(first_marker, first, timeout)
            identity = lock.stat().st_dev, lock.stat().st_ino
            second = _spawn(journal, second_marker, "once")
            time.sleep(0.25)
            if second_marker.exists() or second.poll() is not None:
                raise RuntimeError("competing lifecycle process did not wait for the lock")
            print("PASS: a competing process cannot enter while the lifecycle lock is held")
            first.send_signal(signal.SIGKILL)
            first.wait(timeout=timeout)
            _wait_for_marker(second_marker, second, timeout)
            if second.wait(timeout=timeout) != 0:
                raise RuntimeError("waiting lifecycle process failed after owner death")
            if (lock.stat().st_dev, lock.stat().st_ino) != identity:
                raise RuntimeError("lock inode changed across interrupted owner and successor")
            print("PASS: SIGKILL releases the lock and the waiting process acquires its original inode")
            third_marker = parent / "third.entered"
            third = _spawn(journal, third_marker, "once")
            try:
                _wait_for_marker(third_marker, third, timeout)
                if third.wait(timeout=timeout) != 0:
                    raise RuntimeError("subsequent lifecycle process failed")
                if (lock.stat().st_dev, lock.stat().st_ino) != identity:
                    raise RuntimeError("lock inode changed during repeated acquisition")
            finally:
                if third.poll() is None:
                    third.kill()
                    third.wait()
            print("PASS: repeat acquisition preserves the same lock inode")
        finally:
            for process in (first, second):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="run the disposable multi-process probe")
    args = parser.parse_args()
    if not args.run:
        print(
            "Dry run: use --run to exercise cooperating process exclusion and SIGKILL recovery; no network resources are touched."
        )
        return 0
    try:
        run_probe()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
