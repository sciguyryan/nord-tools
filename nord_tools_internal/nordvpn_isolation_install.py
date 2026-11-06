"""Experimental namespace-local nftables installation boundary.

Only call this while a newly created disposable namespace is still empty.
The caller must not start interfaces, peers or applications before installation.
This is not a production transaction or a crash-safe ownership mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
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


def _expected_rules(policy: NamespaceIsolationPolicy) -> dict[str, list[list[dict]]]:
    """Expected nftables JSON expressions for the generated policy."""
    endpoint = ipaddress.ip_address(policy.endpoint_address)
    family = "ip6" if endpoint.version == 6 else "ip"

    def interface_match(direction: str, name: str) -> dict:
        return {"match": {"op": "==", "left": {"meta": {"key": direction}}, "right": name}}

    return {
        "input": [
            [interface_match("iifname", "lo"), {"accept": None}],
            [
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
                {"accept": None},
            ],
        ],
        "forward": [],
        "output": [
            [interface_match("oifname", "lo"), {"accept": None}],
            [interface_match("oifname", policy.tunnel_interface), {"accept": None}],
            [
                interface_match("oifname", policy.underlay_interface),
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": family, "field": "daddr"}},
                        "right": str(endpoint),
                    }
                },
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "udp", "field": "dport"}},
                        "right": policy.endpoint_port,
                    }
                },
                {"accept": None},
            ],
        ],
    }


def _verify_rules(entries: list, policy: NamespaceIsolationPolicy) -> None:
    """Fail closed on extra, missing or altered rules in the dedicated table."""
    actual: dict[str, list[list[dict]]] = {"input": [], "output": [], "forward": []}
    for entry in entries:
        if not isinstance(entry, dict):
            raise IsolationInstallError("invalid namespace firewall readback entry")
        rule = entry.get("rule")
        if rule is None:
            continue
        if not isinstance(rule, dict):
            raise IsolationInstallError("invalid namespace firewall rule")
        if rule.get("family") != "inet" or rule.get("table") != "nord_tools_isolation":
            continue
        chain = rule.get("chain")
        if chain not in actual or not isinstance(rule.get("expr"), list):
            raise IsolationInstallError("unexpected namespace firewall rule")
        actual[chain].append(rule["expr"])
    if actual != _expected_rules(policy):
        raise IsolationInstallError("namespace firewall allow rules differ from pinned policy")


def _verify_base_chains(namespace: str, policy: NamespaceIsolationPolicy) -> None:
    """Require default-drop chains and precisely scoped allow rules.

    A chain-only check is insufficient: an unexpected broad accept rule could
    silently defeat the intended fail-closed boundary. This readback validates
    the recognised nft JSON expression shapes and refuses unknown additions.
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
        if not isinstance(entries, list):
            raise IsolationInstallError("invalid namespace firewall readback entries")
        # The table is dedicated to Nord Tools. Unrecognised objects can alter
        # packet evaluation (for example, additional base chains or flowtables)
        # without changing the expected allow rules. Refuse them rather than
        # claiming that a partial readback proves the firewall is pinned.
        permitted_metadata = {"metainfo", "table", "chain", "rule"}
        for entry in entries:
            if not isinstance(entry, dict) or len(entry) != 1 or not set(entry) <= permitted_metadata:
                raise IsolationInstallError("unexpected namespace firewall readback object")
            table = entry.get("table")
            if table is not None and (
                not isinstance(table, dict)
                or table.get("family") != "inet"
                or table.get("name") != "nord_tools_isolation"
            ):
                raise IsolationInstallError("unexpected namespace firewall table")
        chains = {}
        for entry in entries:
            chain = entry.get("chain")
            if (
                isinstance(chain, dict)
                and chain.get("family") == "inet"
                and chain.get("table") == "nord_tools_isolation"
            ):
                name = chain.get("name")
                if name in chains:
                    raise IsolationInstallError("duplicate namespace firewall chain")
                chains[name] = chain
        if set(chains) != {"input", "output", "forward"}:
            raise IsolationInstallError("unexpected namespace firewall chains")
        for name in ("input", "output", "forward"):
            chain = chains.get(name)
            if (
                not isinstance(chain, dict)
                or chain.get("hook") != name
                or chain.get("type") != "filter"
                or chain.get("policy") != "drop"
                or type(chain.get("prio")) is not int
                or chain["prio"] != 0
            ):
                raise IsolationInstallError("namespace firewall base-chain verification failed")
        _verify_rules(entries, policy)
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
        _verify_base_chains(owned.name, policy)
        owned.verify()
    except OwnershipError as exc:
        raise IsolationInstallError("namespace ownership changed during firewall installation") from exc
    return IsolationInstallResult(
        namespace=owned.name, policy_checked=True, policy_applied=True, base_chains_verified=True
    )
