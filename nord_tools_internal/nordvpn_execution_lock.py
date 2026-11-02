"""Shared single-flight boundary for privileged lifecycle executors.

The lock coordinates restoration, cleanup and recovery against one journal.
It is not kernel ownership evidence and cannot authorise a mutation. Keep the
lock inode stable across operations, including failures and interruptions.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
from typing import Iterator

from nord_tools_internal.nordvpn_registry import RegistryError


@contextmanager
def lifecycle_execution_lock(journal_path: str | Path) -> Iterator[None]:
    """Serialise cooperating lifecycle executors using one stable lock inode.

    The journal parent is opened without following symlinks. The lock is opened
    relative to that descriptor and its identity checked again after waiting.
    This does not protect against a hostile actor who can rename the parent,
    or make a multi-file state transition atomic.
    """
    target = Path(journal_path).absolute()
    for component in (target, *target.parents):
        if component.is_symlink():
            raise RegistryError("refusing symlinked lifecycle execution path")
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent_fd = os.open(target.parent, parent_flags)
    except OSError as exc:
        raise RegistryError("lifecycle execution requires an existing safe journal directory") from exc
    try:
        parent_info = os.fstat(parent_fd)
        lock_name = target.name + ".restore.lock"
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise RegistryError("cannot open lifecycle execution lock") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
            ):
                raise RegistryError("unsafe lifecycle execution lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            current = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise RegistryError("lifecycle execution lock identity changed")
            try:
                live_parent = os.stat(target.parent, follow_symlinks=False)
            except OSError as exc:
                raise RegistryError("lifecycle execution directory disappeared") from exc
            if (live_parent.st_dev, live_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino):
                raise RegistryError("lifecycle execution directory identity changed")
            yield
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
