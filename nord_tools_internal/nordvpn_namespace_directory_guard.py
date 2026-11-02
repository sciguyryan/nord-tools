"""Fail-closed baseline checks for the privileged named namespace directory.

This is a necessary environmental precondition, not atomic mutation authority.
A process with CAP_SYS_ADMIN can still replace namespace mounts after inspection.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat


class NamespaceDirectoryError(RuntimeError):
    """The named namespace directory is not a trusted mutation location."""


def require_trusted_netns_directory(path: Path = Path("/run/netns")) -> None:
    """Reject symlinked, non-root-owned or group/other-writable mount directories.

    Inspect the opened directory rather than trusting a pathname-only stat. The
    caller must still establish resource identity at the actual mutation boundary.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            named = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or opened.st_uid != 0
                or opened.st_mode & 0o022
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise NamespaceDirectoryError("namespace directory ownership or identity is unsafe")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise NamespaceDirectoryError("namespace directory cannot be inspected safely") from exc
