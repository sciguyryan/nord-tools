"""Experimental namespace-local nftables installation boundary.

Only call this while a newly created disposable namespace is still empty.
The caller must not start interfaces, peers or applications before installation.
This is not a production transaction or a crash-safe ownership mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
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
    base_chains_verified: bool = False


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


def _verify_base_chains(namespace: str) -> None:
    """Require kernel readback of all three default-drop base chains.

    This is structural confirmation only. It does not prove that every rule is
    installed as intended or that traffic cannot leak through other paths.
    """
    try:
        completed = subprocess.run(
            ["ip", "netns", "exec", namespace, "nft", "-j", "list", "table", "inet", "nord_tools_isolation"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode:
            raise IsolationInstallError("namespace firewall readback failed")
        document = json.loads(completed.stdout)
        entries = document["nftables"]
        chains = {}
        for entry in entries:
            chain = entry.get("chain") if isinstance(entry, dict) else None
            if (
                isinstance(chain, dict)
                and chain.get("family") == "inet"
                and chain.get("table") == "nord_tools_isolation"
            ):
                name = chain.get("name")
                if name in chains:
                    raise IsolationInstallError("duplicate namespace firewall chain")
                chains[name] = chain
        for name in ("input", "output", "forward"):
            chain = chains.get(name)
            if (
                not isinstance(chain, dict)
                or chain.get("hook") != name
                or chain.get("type") != "filter"
                or chain.get("policy") != "drop"
            ):
                raise IsolationInstallError("namespace firewall base-chain verification failed")
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
        raise IsolationInstallError("namespace firewall readback could not be verified") from exc


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
        _verify_base_chains(owned.name)
        owned.verify()
    except OwnershipError as exc:
        raise IsolationInstallError("namespace ownership changed during firewall installation") from exc
    return IsolationInstallResult(
        namespace=owned.name, policy_checked=True, policy_applied=True, base_chains_verified=True
    )
