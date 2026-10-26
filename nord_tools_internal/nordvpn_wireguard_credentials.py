"""Single-use, descriptor-based WireGuard private-key input.

This module never persists, prints or passes private keys through command-line
arguments. The caller must provide an already-open, trusted descriptor. It is
not a privileged tunnel executor or a secure-memory implementation.
"""

from __future__ import annotations

from contextlib import contextmanager
import base64
import binascii
import os
import stat
from typing import Iterator


class CredentialError(ValueError):
    """A private-key descriptor or its contents are unsuitable."""


@contextmanager
def private_key_from_fd(fd: int) -> Iterator[bytearray]:
    """Read one canonical WireGuard key, then overwrite the temporary buffer.

    The descriptor is consumed but not closed. Pipes and private regular files
    are accepted; terminal, socket and device descriptors are rejected. The
    caller owns descriptor lifecycle and must not reuse the returned buffer.
    """
    if type(fd) is not int or fd < 0:
        raise CredentialError("a valid inherited credential descriptor is required")
    try:
        metadata = os.fstat(fd)
    except OSError as exc:
        raise CredentialError("credential descriptor is unavailable") from exc
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode)):
        raise CredentialError("credential input must be a regular file or pipe")
    if stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o077:
        raise CredentialError("credential file permissions are too permissive")
    buffer = bytearray()
    try:
        # 44 encoded bytes, one optional newline, and a sentinel for excess.
        while len(buffer) < 46:
            chunk = os.read(fd, 46 - len(buffer))
            if not chunk:
                break
            buffer.extend(chunk)
        if buffer.endswith(b"\n"):
            buffer.pop()
        if len(buffer) != 44:
            raise CredentialError("WireGuard private key must have canonical encoding")
        try:
            decoded = base64.b64decode(buffer, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CredentialError("WireGuard private key must have canonical encoding") from exc
        if len(decoded) != 32 or base64.b64encode(decoded) != buffer:
            raise CredentialError("WireGuard private key must have canonical encoding")
        yield buffer
    except OSError as exc:
        raise CredentialError("credential descriptor read failed") from exc
    finally:
        buffer[:] = b"\x00" * len(buffer)
