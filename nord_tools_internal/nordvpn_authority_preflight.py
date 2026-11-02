"""Read-only inspection of privileged state-directory trust boundaries.

Inspection is anchored to opened directory descriptors, rather than following
pathnames after checking them. It is not kernel-resource ownership authority.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import stat


class AuthorityPreflightError(ValueError):
    """The requested authority boundary cannot be inspected safely."""


def inspect_authority_directory(directory: str | Path, *, trusted_uid: int = 0) -> dict:
    """Inspect a state directory without following symlinks or changing state.

    Each component is opened relative to its already-open parent. This avoids
    inspecting one path and subsequently traversing a different symlink target.
    An attacker who can rename an ancestor may still change the pathname after
    inspection: this result is never permission to mutate resources or files.
    """
    if not isinstance(trusted_uid, int) or isinstance(trusted_uid, bool) or trusted_uid < 0:
        raise AuthorityPreflightError("trusted_uid must be a non-negative integer")
    path = Path(os.path.abspath(os.fspath(directory)))
    findings: list[str] = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = None
    try:
        descriptor = os.open("/", flags)
        components = (
            Path("/"),
            *[Path("/").joinpath(*path.parts[1 : index + 1]) for index in range(1, len(path.parts))],
        )
        for index, component in enumerate(components):
            if index:
                try:
                    child = os.open(path.parts[index], flags, dir_fd=descriptor)
                except OSError as exc:
                    if exc.errno == errno.ENOENT:
                        findings.append(f"missing component: {component}")
                    else:
                        findings.append(f"unopenable or symlink component: {component}")
                    break
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                findings.append(f"non-directory component: {component}")
                break
            if info.st_uid != trusted_uid or info.st_mode & 0o022:
                findings.append(f"untrusted owner or writable component: {component}")
        else:
            try:
                # Directory enumeration and entry inspection share the same
                # opened parent. Never follow links when examining entries.
                for name in os.listdir(descriptor):
                    try:
                        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    except OSError:
                        findings.append(f"uninspectable state entry: {name}")
                        continue
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != trusted_uid
                        or info.st_mode & 0o077
                        or info.st_nlink != 1
                    ):
                        findings.append(f"unsafe state entry: {name}")
            except OSError:
                findings.append("cannot inspect state directory")
    except OSError:
        findings.append("cannot open authority root")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return {
        "mode": "read_only_authority_preflight",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "trusted": not findings,
        "findings": sorted(findings),
    }
