"""Experimental namespace-local nftables installation boundary.

Only call this while a newly created disposable namespace is still empty.
The caller must not start interfaces, peers or applications before installation.
This is not a production transaction or a crash-safe ownership mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
import subprocess

from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy
from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace, OwnershipError


class IsolationInstallError(RuntimeError):
    """The proposed namespace isolation rules could not be installed safely."""


@dataclass(frozen=True)
class IsolationInstallResult:
    """Evidence of a successful invocation, not proof of leak-free networking."""

    namespace: str
    policy_checked: bool
    policy_applied: bool
    dns_confined: bool = False
    tunnel_loss_verified: bool = False


def _run_nft(namespace: str, ruleset: str, *, check: bool) -> None:
    args = ["ip", "netns", "exec", namespace, "nft"]
    if check:
        args.append("-c")
    args.extend(("-f", "-"))
    try:
        completed = subprocess.run(args, input=ruleset, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IsolationInstallError("namespace firewall command could not complete") from exc
    if completed.returncode:
        stage = "validation" if check else "installation"
        raise IsolationInstallError(f"namespace firewall {stage} failed")


def install_disposable_isolation(owned: OwnedNamespace, policy: NamespaceIsolationPolicy) -> IsolationInstallResult:
    """Validate and install a dedicated table in an empty owned namespace.

    The nft batch installs the table and its chains together. The separate
    preflight check is advisory and cannot establish atomicity with the apply.
    The caller must ensure no networking is active before calling this method.
    A failure is uncertain and must prevent subsequent tunnel configuration.
    """
    if not isinstance(owned, OwnedNamespace) or not isinstance(policy, NamespaceIsolationPolicy):
        raise IsolationInstallError("owned namespace and validated policy required")
    try:
        owned.verify()
        _run_nft(owned.name, policy.render_nft(), check=True)
        owned.verify()
        _run_nft(owned.name, policy.render_nft(), check=False)
        owned.verify()
    except OwnershipError as exc:
        raise IsolationInstallError("namespace ownership changed during firewall installation") from exc
    return IsolationInstallResult(namespace=owned.name, policy_checked=True, policy_applied=True)
