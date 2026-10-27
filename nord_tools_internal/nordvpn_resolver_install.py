"""Conservative namespace-specific resolver installation.

Linux ip netns exec bind-mounts /etc/netns/NAME/resolv.conf over the command's
/etc/resolv.conf. This installer never writes the host's /etc/resolv.conf.
Installation is exclusive and deliberately refuses pre-existing state.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

from .nordvpn_resolver_policy import NamespaceResolverPolicy


class ResolverInstallError(RuntimeError):
    """Namespace resolver installation cannot proceed safely."""


_NAMESPACE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}\Z")


@dataclass(frozen=True)
class InstalledResolver:
    """Identity of a newly created resolver directory for explicit cleanup."""

    namespace: str
    directory: Path
    device: int
    inode: int


def install_namespace_resolver(
    namespace: str,
    policy: NamespaceResolverPolicy,
    *,
    root: Path = Path("/etc/netns"),
) -> InstalledResolver:
    """Create a new resolver directory and file, without replacing existing data.

    Caller must own the namespace and arrange cleanup. This does not verify
    route confinement, and must not be used as evidence of DNS leak protection.
    """
    if not _NAMESPACE_RE.fullmatch(namespace) or namespace in (".", ".."):
        raise ResolverInstallError("invalid network namespace name")
    if not isinstance(policy, NamespaceResolverPolicy):
        raise ResolverInstallError("validated resolver policy required")
    # Do not follow a symlink for the root. The parent is managed by the OS.
    try:
        root_stat = root.lstat()
    except FileNotFoundError as exc:
        raise ResolverInstallError("namespace resolver root does not exist") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_mode & 0o022:
        raise ResolverInstallError("namespace resolver root is unsafe")
    directory = root / namespace
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ResolverInstallError("namespace resolver directory already exists") from exc
    try:
        # Exclusive creation ensures an existing resolver is never overwritten.
        fd = os.open(directory / "resolv.conf", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(policy.render_resolv_conf())
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            (directory / "resolv.conf").unlink(missing_ok=True)
            raise
        info = directory.stat(follow_symlinks=False)
        return InstalledResolver(namespace, directory, info.st_dev, info.st_ino)
    except BaseException:
        directory.rmdir()
        raise


def remove_namespace_resolver(installation: InstalledResolver) -> None:
    """Remove only the original directory containing its expected resolver file.

    Refuse unexpected files or replacement directories instead of deleting
    unrelated state. Caller must ensure namespace users have stopped.
    """
    directory = installation.directory
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (installation.device, installation.inode):
        raise ResolverInstallError("resolver directory identity changed")
    entries = list(directory.iterdir())
    if len(entries) != 1 or entries[0].name != "resolv.conf" or not entries[0].is_file() or entries[0].is_symlink():
        raise ResolverInstallError("resolver directory contains unexpected state")
    entries[0].unlink()
    directory.rmdir()
