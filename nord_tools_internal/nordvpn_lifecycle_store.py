"""Serialised offline lifecycle journal updates, without network authority.

This store is deliberately not a privileged ownership registrar. The stable
sibling lock serialises cooperating writers; it does not authenticate kernel
resources or protect against hostile processes with directory write access.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Callable, Iterator

from nord_tools_internal.nordvpn_lifecycle import record_transition, validate_journal, write_journal
from nord_tools_internal.nordvpn_registry import RegistryError


def _check_path(path: Path) -> None:
    """Reject symlinks throughout an existing path, not just its final parent."""
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RegistryError("refusing symlinked lifecycle store path")


@contextmanager
def locked_journal(path: str | Path) -> Iterator[None]:
    """Take a blocking, stable sibling lock for cooperating Linux writers."""
    target = Path(path).absolute()
    _check_path(target)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_path(target)
    lock = target.with_name(target.name + ".lock")
    _check_path(lock)
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(lock, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RegistryError("lifecycle lock must be a single regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _check_path(target)
        if lock.stat().st_ino != metadata.st_ino or lock.stat().st_dev != metadata.st_dev:
            raise RegistryError("lifecycle lock identity changed")
        yield
    finally:
        os.close(fd)
    # Never unlink the lock: doing so would permit two independent lock inodes.


def update_journal(path: str | Path, transform: Callable[[dict], object]) -> dict:
    """Read, validate, transform and atomically replace under one lock.

    Requires an existing journal; does not invent allocations after a crash.
    A failed transform leaves the previous journal unchanged.
    """
    target = Path(path).absolute()
    with locked_journal(target):
        try:
            fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            with os.fdopen(fd, "r", encoding="utf-8") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise RegistryError("lifecycle journal must be a regular file")
                original = validate_journal(json.load(source))
        except (OSError, ValueError, UnicodeError) as exc:
            raise RegistryError("cannot read a valid existing lifecycle journal") from exc
        revised = validate_journal(transform(original))
        write_journal(target, revised)
        return revised


def transition_journal(path: str | Path, allocation_id: str, state: str) -> dict:
    """Append a validated lifecycle event without a lost-update race."""
    return update_journal(path, lambda journal: record_transition(journal, allocation_id, state))
