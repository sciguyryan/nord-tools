"""Process-bound ownership of disposable Linux network namespaces.

Authority exists only while this process retains an open namespace descriptor
obtained immediately after its own successful creation. Persistent journals,
names and inode numbers cannot recreate that authority after a crash.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Iterator


class OwnershipError(RuntimeError):
    """Namespace ownership cannot be established or safely exercised."""


_NAME = re.compile(r"nt-[a-z0-9]{8,24}\Z")
_NETNS_DIR = Path("/run/netns")


def _command(*args: str) -> str:
    try:
        result = subprocess.run(["ip", "netns", *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OwnershipError("namespace command failed") from exc
    if result.returncode:
        raise OwnershipError(f"namespace command failed: {args[0]}")
    return result.stdout


def _namespace_names() -> set[str]:
    output = _command("list")
    return {line.split()[0] for line in output.splitlines() if line.strip()}


@dataclass
class OwnedNamespace:
    """Ephemeral descriptor-bound authority; never serialise this object."""

    name: str
    descriptor: int
    device: int
    inode: int
    closed: bool = False

    def verify(self) -> None:
        if self.closed:
            raise OwnershipError("namespace ownership descriptor has been closed")
        try:
            held = os.fstat(self.descriptor)
            current = os.stat(_NETNS_DIR / self.name, follow_symlinks=False)
        except OSError as exc:
            raise OwnershipError("namespace is no longer observable") from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or (held.st_dev, held.st_ino) != (self.device, self.inode)
            or (current.st_dev, current.st_ino) != (self.device, self.inode)
        ):
            raise OwnershipError("namespace identity changed; refusing operation")
        if self.name not in _namespace_names():
            raise OwnershipError("namespace no longer appears in kernel discovery")

    def retire(self) -> None:
        """Delete only this process's still-matching disposable namespace.

        A nonempty namespace is left for operator review, not forcibly killed.
        """
        self.verify()
        if _command("pids", self.name).strip():
            raise OwnershipError("namespace still contains processes")
        self.verify()
        _command("del", self.name)
        self.closed = True
        os.close(self.descriptor)

    def release(self) -> None:
        """Drop ephemeral authority without deleting a possibly live resource."""
        if not self.closed:
            self.closed = True
            os.close(self.descriptor)


@contextmanager
def disposable_namespace(name: str) -> Iterator[OwnedNamespace]:
    """Create a uniquely named namespace, hold its descriptor, and retire safely.

    Requires explicit privileged invocation. On uncertain cleanup, fail closed
    and leave the resource for manual investigation instead of guessing.
    """
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise OwnershipError("disposable namespace name must match nt-[a-z0-9]{8,24}")
    if name in _namespace_names() or (_NETNS_DIR / name).exists():
        raise OwnershipError("namespace already exists")
    _command("add", name)
    owned = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(_NETNS_DIR / name, flags)
        try:
            info = os.fstat(descriptor)
            owned = OwnedNamespace(name, descriptor, info.st_dev, info.st_ino)
            owned.verify()
        except BaseException:
            os.close(descriptor)
            raise
        yield owned
    finally:
        if owned is not None and not owned.closed:
            try:
                owned.retire()
            finally:
                owned.release()
        # If opening/verification failed, there is no deletion authority.
        # Leave the namespace for explicit operator inspection.
