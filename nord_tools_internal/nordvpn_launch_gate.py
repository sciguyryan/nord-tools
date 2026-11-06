"""Private pre-exec barrier for an authorised namespace application launcher.

Not a public entry point. The gate performs no network I/O and will not exec
an application until the parent has durably reserved its consumer lease.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    # All arguments originate from the privileged launcher, not the application.
    if len(sys.argv) < 6:
        return 126
    ready, release, uid, gid = map(int, sys.argv[1:5])
    executable = sys.argv[5]
    arguments = sys.argv[6:]
    if uid <= 0 or gid <= 0 or not executable.startswith("/"):
        return 126
    os.write(ready, b"R")
    os.close(ready)
    if os.read(release, 1) != b"G":
        return 126
    os.close(release)
    # Drop all root and supplementary privileges before executing the program.
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.execv(executable, [executable, *arguments])
    return 126


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        raise SystemExit(126) from None
