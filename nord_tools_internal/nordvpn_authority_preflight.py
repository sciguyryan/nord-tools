"""Read-only Part 8 authority boundary inspection.

This preflight checks whether durable authority stores are protected from
unprivileged replacement. It is deliberately not a certificate of kernel
resource ownership and never permits a mutation on its own.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat


class AuthorityPreflightError(ValueError):
    """The requested authority boundary cannot be inspected safely."""


def inspect_authority_directory(directory: str | Path, *, trusted_uid: int = 0) -> dict:
    """Inspect a dedicated privileged state directory without changing it.

    A writable ancestor, symlink, foreign owner or unexpectedly linked store
    invalidates the boundary. The caller must still verify live kernel identity
    and hold an operation-specific lock immediately before every mutation.
    """
    path = Path(directory).absolute()
    if not isinstance(trusted_uid, int) or isinstance(trusted_uid, bool) or trusted_uid < 0:
        raise AuthorityPreflightError("trusted_uid must be a non-negative integer")
    findings: list[str] = []
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except OSError:
            findings.append(f"missing component: {component}")
            continue
        if not stat.S_ISDIR(info.st_mode):
            findings.append(f"non-directory or symlink component: {component}")
        elif info.st_uid != trusted_uid or info.st_mode & 0o022:
            findings.append(f"untrusted owner or writable component: {component}")
    if not findings:
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != trusted_uid
                        or info.st_mode & 0o077
                        or info.st_nlink != 1
                    ):
                        findings.append(f"unsafe state entry: {entry.name}")
        except OSError:
            findings.append("cannot inspect state directory")
    return {
        "mode": "read_only_authority_preflight",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "trusted": not findings,
        "findings": sorted(findings),
    }
