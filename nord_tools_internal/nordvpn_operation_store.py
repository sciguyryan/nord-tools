"""Durable, locked offline operation intents for future privileged execution.

The journal and intent files are separate documents. This store deliberately
cannot atomically commit changes to both, and must not be used to authorise
kernel mutations. An intent is persisted before any future executor acts.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterator

from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_operation_intent import begin_intent, resolve_intent, validate_intents
from nord_tools_internal.nordvpn_registry import RegistryError


def _check_components(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RegistryError("refusing symlinked operation store path")


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    _check_components(path)
    if not path.parent.is_dir():
        raise RegistryError("operation store parent must already exist")
    lock = path.with_name(path.name + ".lock")
    _check_components(lock)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise RegistryError("unsafe operation lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _check_components(path)
        current = os.stat(lock, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RegistryError("operation lock identity changed")
        yield
    finally:
        os.close(fd)


def _load(path: Path, journal: dict) -> dict:
    _check_components(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise RegistryError("unsafe operation intent file")
        return validate_intents(json.load(source), journal)


def _write(path: Path, document: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".operation-intents-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(document, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def initialise_intents(path: str | Path, journal: object) -> dict:
    """Create an empty store only if absent; never overwrite existing state."""
    target = Path(path).absolute()
    validated_journal = validate_journal(journal)
    with _locked(target):
        if target.exists() or target.is_symlink():
            raise RegistryError("operation store already exists")
        document = validate_intents({"version": 1, "operations": []}, validated_journal)
        # Exclusive creation avoids replacing a concurrently introduced file.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(document, output, sort_keys=True, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            # Do not erase an uncertain partially written file.
            raise
        return document


def update_intent(
    path: str | Path,
    journal: object,
    *,
    allocation_id: str | None = None,
    action: str | None = None,
    operation_id: str | None = None,
    outcome: str | None = None,
) -> dict:
    """Persist one begin or resolution under the same stable advisory lock."""
    target = Path(path).absolute()
    validated_journal = validate_journal(journal)
    if allocation_id is not None and action is not None and operation_id is None and outcome is None:
        mode = "begin"
    elif operation_id is not None and outcome is not None and allocation_id is None and action is None:
        mode = "resolve"
    else:
        raise RegistryError("specify exactly one operation intent update")
    with _locked(target):
        try:
            existing = _load(target, validated_journal)
        except (OSError, ValueError, UnicodeError) as exc:
            raise RegistryError("cannot load existing operation intents") from exc
        revised = (
            begin_intent(existing, validated_journal, allocation_id, action)
            if mode == "begin"
            else resolve_intent(existing, validated_journal, operation_id, outcome)
        )
        _write(target, revised)
        return revised


def read_intents(path: str | Path, journal: object) -> dict:
    """Validate an existing store without modifying it."""
    target = Path(path).absolute()
    validated_journal = validate_journal(journal)
    with _locked(target):
        return _load(target, validated_journal)
