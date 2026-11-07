"""Linux command boundary for host-default protection.

The executor records intent before calling these functions.  Commands use
argument vectors or nftables standard input; no shell is involved.  This
module owns only the dedicated table, interface, route table and rule
priorities declared by a validated plan.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import subprocess
from typing import Any

from nord_tools_internal.nordvpn_host_executor import HostKernel, HostProtectionError
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_startup import read_boot_id


_TIMEOUT = 15


def _run(argv: list[str], *, input_text: str | None = None, pass_fds: tuple[int, ...] = ()) -> str:
    try:
        result = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=_TIMEOUT,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostProtectionError(f"host command {argv[0]!r} could not complete") from exc
    if result.returncode:
        raise HostProtectionError(f"host command {argv[0]!r} failed (exit {result.returncode})")
    return result.stdout


def _json(argv: list[str]) -> Any:
    try:
        return json.loads(_run(argv))
    except (ValueError, TypeError) as exc:
        raise HostProtectionError(f"host command {argv[0]!r} returned malformed JSON") from exc


def _optional_json(argv: list[str]) -> Any | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostProtectionError(f"host command {argv[0]!r} could not complete") from exc
    if result.returncode:
        # nft uses ENOENT for a missing table.  Permission failures and
        # malformed/unsupported invocations must never certify absence.
        message = result.stderr.strip().lower()
        if result.returncode == 1 and ("no such file or directory" in message or "does not exist" in message):
            return None
        raise HostProtectionError(
            f"host command {argv[0]!r} could not establish resource absence (exit {result.returncode})"
        )
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise HostProtectionError(f"host command {argv[0]!r} returned malformed JSON") from exc


def _service_active(name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", name], capture_output=True, check=False, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _links() -> list[dict]:
    data = _json(["ip", "-j", "link", "show"])
    if not isinstance(data, list):
        raise HostProtectionError("host link inventory is malformed")
    result = []
    for item in data:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("ifname"), str)
            or type(item.get("ifindex")) is not int
        ):
            raise HostProtectionError("host link identity is malformed")
        result.append(
            {
                "name": item["ifname"],
                "index": item["ifindex"],
                "kind": (item.get("linkinfo") or {}).get("info_kind"),
            }
        )
    return result


def _nft(plan: HostProtectionPlan) -> dict | None:
    data = _optional_json(["nft", "-j", "list", "table", plan.firewall_family, plan.firewall_table])
    if data is None:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise HostProtectionError("host firewall readback is malformed")
    return data


def _nft_markers(plan: HostProtectionPlan) -> tuple[set[str], bool]:
    document = _nft(plan)
    if document is None:
        return set(), False
    markers: set[str] = set()
    chains: dict[str, dict] = {}
    expressions = _expected_nft_expressions(plan)
    allowed = {"metainfo", "table", "chain", "rule"}
    ambiguous = False
    for item in document["nftables"]:
        if not isinstance(item, dict) or len(item) != 1 or not set(item) <= allowed:
            return set(), True
        table = item.get("table")
        if isinstance(table, dict) and (
            table.get("family") != plan.firewall_family or table.get("name") != plan.firewall_table
        ):
            ambiguous = True
        chain = item.get("chain")
        if isinstance(chain, dict):
            if chain.get("name") in chains:
                ambiguous = True
            chains[chain.get("name")] = chain
        rule = item.get("rule")
        if isinstance(rule, dict):
            comment = rule.get("comment")
            expected_chain = (
                "input"
                if isinstance(comment, str)
                and comment
                in {
                    f"nt:{plan.generation}:barrier:input-loopback",
                    f"nt:{plan.generation}:barrier:input-established",
                }
                else "output"
            )
            if (
                not isinstance(comment, str)
                or comment not in expressions
                or rule.get("family") != plan.firewall_family
                or rule.get("table") != plan.firewall_table
                or rule.get("chain") != expected_chain
                or rule.get("expr") != expressions[comment]
            ):
                ambiguous = True
            else:
                markers.add(comment)
    expected_chains = {"input", "output", "forward"}
    ambiguous |= set(chains) != expected_chains
    for name in expected_chains:
        chain = chains.get(name, {})
        ambiguous |= not (
            chain.get("family") == "inet"
            and chain.get("table") == plan.firewall_table
            and chain.get("type") == "filter"
            and chain.get("hook") == name
            and chain.get("prio") == plan.firewall_priority
            and chain.get("policy") == "drop"
        )
    recognised = {
        f"nt:{plan.generation}:barrier:input-loopback",
        f"nt:{plan.generation}:barrier:input-established",
        f"nt:{plan.generation}:barrier:output-loopback",
        f"nt:{plan.generation}:barrier:output-tunnel",
        f"nt:{plan.generation}:endpoint",
    }
    ambiguous |= bool(markers - recognised)
    return markers, ambiguous


def _expected_nft_expressions(plan: HostProtectionPlan) -> dict[str, list[dict]]:
    endpoint = ipaddress.ip_address(plan.endpoint_address)
    family = "ip6" if endpoint.version == 6 else "ip"

    def interface(direction: str, name: str) -> dict:
        return {"match": {"op": "==", "left": {"meta": {"key": direction}}, "right": name}}

    def address(field: str, value: str) -> dict:
        return {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": family, "field": field}},
                "right": value,
            }
        }

    return {
        f"nt:{plan.generation}:barrier:input-loopback": [interface("iifname", "lo"), {"accept": None}],
        f"nt:{plan.generation}:barrier:input-established": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
            {"accept": None},
        ],
        f"nt:{plan.generation}:barrier:output-loopback": [interface("oifname", "lo"), {"accept": None}],
        f"nt:{plan.generation}:barrier:output-tunnel": [
            interface("oifname", plan.interface),
            {"accept": None},
        ],
        f"nt:{plan.generation}:endpoint": [
            interface("oifname", plan.egress_interface),
            address("saddr", plan.egress_source_address),
            address("daddr", plan.endpoint_address),
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "udp", "field": "dport"}},
                    "right": plan.endpoint_port,
                }
            },
            {"accept": None},
        ],
    }


def _rule_rows(family: int) -> list[dict]:
    data = _json(["ip", f"-{family}", "-j", "rule", "show"])
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise HostProtectionError("host routing rule readback is malformed")
    return data


def _route_rows(family: int, table: int) -> list[dict]:
    data = _json(["ip", f"-{family}", "-j", "route", "show", "table", str(table)])
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise HostProtectionError("host route readback is malformed")
    return data


def _routes_state(plan: HostProtectionPlan) -> str:
    endpoint_family = ipaddress.ip_address(plan.endpoint_address).version
    found_endpoint = False
    found_tunnel: set[int] = set()
    endpoint_count = 0
    tunnel_counts = {4: 0, 6: 0}
    unexpected = False

    def table_number(value: object) -> int | None:
        if value == "main":
            return 254
        if type(value) is int:
            return value
        if isinstance(value, str) and value.isdecimal():
            return int(value)
        return None

    for family in (4, 6):
        rows = _rule_rows(family)
        for item in rows:
            priority = item.get("priority")
            table = table_number(item.get("table"))
            if priority in {plan.endpoint_rule_priority, plan.tunnel_rule_priority}:
                if priority == plan.endpoint_rule_priority:
                    endpoint_count += 1
                    expected_dst = plan.endpoint_address if family == endpoint_family else None
                    if (
                        expected_dst is None
                        or table != 254
                        or item.get("dst") != expected_dst
                        or item.get("src") != "all"
                        or any(key in item for key in ("fwmark", "not", "suppress_prefixlen"))
                    ):
                        unexpected = True
                    else:
                        found_endpoint = True
                else:
                    tunnel_counts[family] += 1
                if priority == plan.tunnel_rule_priority and (
                    table != plan.route_table
                    or item.get("src") != "all"
                    or "dst" in item
                    or any(key in item for key in ("fwmark", "not", "suppress_prefixlen"))
                ):
                    unexpected = True
                elif priority == plan.tunnel_rule_priority:
                    found_tunnel.add(family)
        routes = _route_rows(family, plan.route_table)
        defaults = [item for item in routes if item.get("dst") in {"default", "0.0.0.0/0", "::/0"}]
        if (
            len(routes) > 1
            or len(defaults) > 1
            or (defaults and (defaults[0].get("dev") != plan.interface or defaults[0].get("protocol") != "static"))
        ):
            unexpected = True
    unexpected |= endpoint_count != 1 and (endpoint_count != 0 or bool(found_tunnel))
    unexpected |= any(count > 1 for count in tunnel_counts.values())
    present = found_tunnel == {4, 6} and all(len(_route_rows(family, plan.route_table)) == 1 for family in (4, 6))
    if present and found_endpoint and not unexpected:
        return "present"
    if not found_tunnel and not found_endpoint and not any(_route_rows(family, plan.route_table) for family in (4, 6)):
        return "absent"
    return "ambiguous"


def _wireguard_observation(plan: HostProtectionPlan) -> tuple[str, dict | None]:
    matches = [item for item in _links() if item["name"] == plan.interface]
    if not matches:
        return "absent", None
    if len(matches) != 1 or matches[0]["kind"] != "wireguard":
        return "ambiguous", None
    try:
        peers = _run(["wg", "show", plan.interface, "peers"]).strip().splitlines()
        endpoints = _run(["wg", "show", plan.interface, "endpoints"]).strip().splitlines()
        allowed = _run(["wg", "show", plan.interface, "allowed-ips"]).strip().splitlines()
        mark_text = _run(["wg", "show", plan.interface, "fwmark"]).strip()
        addresses = _json(["ip", "-j", "address", "show", "dev", plan.interface])
        mark = int(mark_text, 0)
    except (HostProtectionError, ValueError):
        return "ambiguous", None
    endpoint = (
        f"[{plan.endpoint_address}]:{plan.endpoint_port}"
        if ":" in plan.endpoint_address
        else f"{plan.endpoint_address}:{plan.endpoint_port}"
    )
    expected_addresses = set(plan.tunnel_addresses)
    observed_addresses: set[str] = set()
    if isinstance(addresses, list) and len(addresses) == 1 and isinstance(addresses[0], dict):
        for item in addresses[0].get("addr_info", []):
            if isinstance(item, dict) and isinstance(item.get("local"), str) and type(item.get("prefixlen")) is int:
                observed_addresses.add(f"{item['local']}/{item['prefixlen']}")
    if (
        peers != [plan.peer_public_key]
        or endpoints != [f"{plan.peer_public_key}\t{endpoint}"]
        or allowed != [f"{plan.peer_public_key}\t{','.join(plan.peer_allowed_ips)}"]
        or mark != plan.fwmark
        or observed_addresses != expected_addresses
    ):
        return "ambiguous", None
    return (
        "present",
        {
            "interface": plan.interface,
            "ifindex": matches[0]["index"],
            "kind": "wireguard",
            "peer_public_key": plan.peer_public_key,
            "endpoint": endpoint,
            "allowed_ips": list(plan.peer_allowed_ips),
            "fwmark": plan.fwmark,
            "addresses": list(plan.tunnel_addresses),
        },
    )


def _wireguard_state(plan: HostProtectionPlan, evidence: dict) -> str:
    state, observed = _wireguard_observation(plan)
    if state != "present" or observed is None:
        return state
    expected = evidence.get("ifindex")
    return "present" if expected is None or observed["ifindex"] == expected else "ambiguous"


def _resolver_state(plan: HostProtectionPlan) -> str:
    # A vanished link is distinguishable from a resolver inspection failure.
    # A link with the expected name but an unknown resolver state is ambiguous.
    links = [item for item in _links() if item["name"] == plan.interface]
    if not links:
        return "absent"
    if len(links) != 1 or links[0]["kind"] != "wireguard":
        return "ambiguous"
    try:
        dns_output = _run(["resolvectl", "dns", plan.interface]).strip()
        domain_output = _run(["resolvectl", "domain", plan.interface]).strip()
        route_output = _run(["resolvectl", "default-route", plan.interface]).strip()
    except HostProtectionError:
        return "ambiguous"
    if any(":" not in output for output in (dns_output, domain_output, route_output)):
        return "ambiguous"
    addresses = set(dns_output.partition(":")[2].split())
    domains = set(domain_output.partition(":")[2].split())
    default_route = route_output.partition(":")[2].strip().lower()
    return (
        "present"
        if addresses == set(plan.dns_servers) and domains == {"~."} and default_route == "yes"
        else "ambiguous"
    )


def _resource_state(name: str, evidence: dict, plan: HostProtectionPlan) -> str:
    if name == "barrier":
        markers, ambiguous = _nft_markers(plan)
        required = {
            f"nt:{plan.generation}:barrier:input-loopback",
            f"nt:{plan.generation}:barrier:input-established",
            f"nt:{plan.generation}:barrier:output-loopback",
            f"nt:{plan.generation}:barrier:output-tunnel",
        }
        if ambiguous:
            return "ambiguous"
        return "present" if required <= markers else "absent" if not markers else "ambiguous"
    if name == "endpoint":
        markers, ambiguous = _nft_markers(plan)
        if ambiguous:
            return "ambiguous"
        return "present" if f"nt:{plan.generation}:endpoint" in markers else "absent"
    if name == "wireguard":
        return _wireguard_state(plan, evidence)
    if name == "routes":
        return _routes_state(plan)
    if name == "resolver":
        return _resolver_state(plan)
    raise HostProtectionError("unknown host resource kind")


def _observe_resource(name: str, plan: HostProtectionPlan) -> tuple[str, dict | None]:
    if name == "wireguard":
        return _wireguard_observation(plan)
    state = _resource_state(name, {}, plan)
    if state != "present":
        return state, None
    evidence = {
        "barrier": {"family": "inet", "table": plan.firewall_table, "generation": plan.generation},
        "endpoint": {
            "interface": plan.egress_interface,
            "ifindex": plan.egress_ifindex,
            "address": plan.endpoint_address,
            "port": plan.endpoint_port,
        },
        "routes": {
            "table": plan.route_table,
            "endpoint_priority": plan.endpoint_rule_priority,
            "tunnel_priority": plan.tunnel_rule_priority,
        },
        "resolver": {
            "manager": "systemd-resolved",
            "interface": plan.interface,
            "servers": list(plan.dns_servers),
        },
    }[name]
    return "present", evidence


def _inventory(plan: HostProtectionPlan) -> dict:
    links = _links()
    conflicts = [name for name in ("NetworkManager", "firewalld", "ufw") if _service_active(name)]
    other_wireguard = [item["name"] for item in links if item["kind"] == "wireguard" and item["name"] != plan.interface]
    conflicts.extend(f"wireguard:{name}" for name in other_wireguard)
    endpoint_family = ipaddress.ip_address(plan.endpoint_address).version
    path = _json(
        [
            "ip",
            f"-{endpoint_family}",
            "-j",
            "route",
            "get",
            plan.endpoint_address,
            "from",
            plan.egress_source_address,
        ]
    )
    if (
        not isinstance(path, list)
        or len(path) != 1
        or path[0].get("dev") != plan.egress_interface
        or path[0].get("prefsrc") not in {None, plan.egress_source_address}
    ):
        conflicts.append("endpoint-underlay-path")
    owned = []
    for name in ("barrier", "endpoint", "wireguard", "routes", "resolver"):
        state = _resource_state(name, {}, plan)
        if state != "absent":
            owned.append({"kind": name, "state": state})
    return {
        "boot_id": read_boot_id(),
        "links": links,
        "resolver_manager": "systemd-resolved" if _service_active("systemd-resolved") else "unsupported",
        "conflicts": sorted(conflicts),
        "owned_resources": owned,
    }


def _install_barrier(plan: HostProtectionPlan) -> dict:
    rules = f"""table inet {plan.firewall_table} {{
 chain input {{ type filter hook input priority {plan.firewall_priority}; policy drop;
  iifname "lo" accept comment "nt:{plan.generation}:barrier:input-loopback"
  ct state established,related accept comment "nt:{plan.generation}:barrier:input-established"
 }}
 chain output {{ type filter hook output priority {plan.firewall_priority}; policy drop;
  oifname "lo" accept comment "nt:{plan.generation}:barrier:output-loopback"
  oifname "{plan.interface}" accept comment "nt:{plan.generation}:barrier:output-tunnel"
 }}
 chain forward {{ type filter hook forward priority {plan.firewall_priority}; policy drop; }}
}}
"""
    _run(["nft", "-c", "-f", "-"], input_text=rules)
    _run(["nft", "-f", "-"], input_text=rules)
    evidence = {"family": "inet", "table": plan.firewall_table, "generation": plan.generation}
    if _resource_state("barrier", evidence, plan) != "present":
        raise HostProtectionError("host deny barrier readback failed")
    return evidence


def _install_endpoint(plan: HostProtectionPlan) -> dict:
    family = "ip6" if ipaddress.ip_address(plan.endpoint_address).version == 6 else "ip"
    command = (
        f'add rule inet {plan.firewall_table} output oifname "{plan.egress_interface}" '
        f"{family} saddr {plan.egress_source_address} {family} daddr {plan.endpoint_address} "
        f"udp dport {plan.endpoint_port} accept "
        f'comment "nt:{plan.generation}:endpoint"\n'
    )
    _run(["nft", "-f", "-"], input_text=command)
    return {
        "interface": plan.egress_interface,
        "ifindex": plan.egress_ifindex,
        "address": plan.endpoint_address,
        "port": plan.endpoint_port,
    }


def _install_wireguard(plan: HostProtectionPlan, key_fd: int) -> dict:
    _run(["ip", "link", "add", plan.interface, "type", "wireguard"])
    for address in plan.tunnel_addresses:
        _run(["ip", "address", "add", address, "dev", plan.interface])
    _run(
        [
            "wg",
            "set",
            plan.interface,
            "private-key",
            f"/proc/self/fd/{key_fd}",
            "fwmark",
            str(plan.fwmark),
            "peer",
            plan.peer_public_key,
            "endpoint",
            f"{plan.endpoint_address}:{plan.endpoint_port}"
            if ":" not in plan.endpoint_address
            else f"[{plan.endpoint_address}]:{plan.endpoint_port}",
            "allowed-ips",
            ",".join(plan.peer_allowed_ips),
        ],
        pass_fds=(key_fd,),
    )
    _run(["ip", "link", "set", plan.interface, "up"])
    link = next(item for item in _links() if item["name"] == plan.interface)
    return {"interface": plan.interface, "ifindex": link["index"], "kind": "wireguard"}


def _install_routes(plan: HostProtectionPlan) -> dict:
    endpoint_family = ipaddress.ip_address(plan.endpoint_address).version
    endpoint_network = f"{plan.endpoint_address}/{32 if endpoint_family == 4 else 128}"
    _run(
        [
            "ip",
            f"-{endpoint_family}",
            "rule",
            "add",
            "priority",
            str(plan.endpoint_rule_priority),
            "to",
            endpoint_network,
            "lookup",
            "main",
        ]
    )
    for family in (4, 6):
        _run(
            [
                "ip",
                f"-{family}",
                "route",
                "add",
                "default",
                "dev",
                plan.interface,
                "table",
                str(plan.route_table),
                "proto",
                "static",
            ]
        )
        _run(
            [
                "ip",
                f"-{family}",
                "rule",
                "add",
                "priority",
                str(plan.tunnel_rule_priority),
                "lookup",
                str(plan.route_table),
            ]
        )
    return {
        "table": plan.route_table,
        "endpoint_priority": plan.endpoint_rule_priority,
        "tunnel_priority": plan.tunnel_rule_priority,
    }


def _install_resolver(plan: HostProtectionPlan) -> dict:
    _run(["resolvectl", "dns", plan.interface, *plan.dns_servers])
    _run(["resolvectl", "domain", plan.interface, "~."])
    _run(["resolvectl", "default-route", plan.interface, "yes"])
    return {"manager": "systemd-resolved", "interface": plan.interface, "servers": list(plan.dns_servers)}


def _verify_ready(plan: HostProtectionPlan) -> dict:
    latest = _run(["wg", "show", plan.interface, "latest-handshakes"]).strip().split()
    handshake = False
    if len(latest) >= 2:
        try:
            timestamp = int(latest[-1])
            now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            handshake = 0 < now - timestamp <= 180
        except ValueError:
            handshake = False
    return {
        "barrier": _resource_state("barrier", {}, plan) == "present",
        "wireguard": _resource_state("wireguard", {}, plan) == "present",
        "routes": _resource_state("routes", {}, plan) == "present",
        "resolver": _resource_state("resolver", {}, plan) == "present",
        "handshake": handshake,
    }


def _remove_resolver(plan: HostProtectionPlan, evidence: dict) -> dict:
    _run(["resolvectl", "revert", plan.interface])
    return {"reverted": plan.interface}


def _remove_routes(plan: HostProtectionPlan, evidence: dict) -> dict:
    endpoint_family = ipaddress.ip_address(plan.endpoint_address).version
    _run(["ip", f"-{endpoint_family}", "rule", "del", "priority", str(plan.endpoint_rule_priority)])
    for family in (4, 6):
        _run(["ip", f"-{family}", "rule", "del", "priority", str(plan.tunnel_rule_priority)])
        _run(["ip", f"-{family}", "route", "del", "default", "table", str(plan.route_table)])
    return {"removed_table": plan.route_table}


def _remove_wireguard(plan: HostProtectionPlan, evidence: dict) -> dict:
    # Interface names can be recycled.  Require the original kernel ifindex
    # immediately before deletion, not merely a matching WireGuard config.
    expected = evidence.get("ifindex")
    if type(expected) is not int or expected <= 0:
        raise HostProtectionError("WireGuard retirement lacks an original interface identity")
    observed, identity = _wireguard_observation(plan)
    if observed != "present" or identity is None or identity["ifindex"] != expected:
        raise HostProtectionError("WireGuard interface identity changed before retirement")
    _run(["ip", "link", "del", "dev", plan.interface])
    return {"removed_ifindex": expected}


def _remove_endpoint(plan: HostProtectionPlan, evidence: dict) -> dict:
    # The rule handle is intentionally discovered only after structural and
    # comment verification.  Deleting the table earlier would also remove the
    # deny barrier, so endpoint retirement remains a distinct mutation.
    document = _nft(plan)
    handles = []
    for item in (document or {}).get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if isinstance(rule, dict) and rule.get("comment") == f"nt:{plan.generation}:endpoint":
            handles.append(rule.get("handle"))
    if len(handles) != 1 or type(handles[0]) is not int:
        raise HostProtectionError("endpoint exception handle is absent or ambiguous")
    _run(
        [
            "nft",
            "delete",
            "rule",
            "inet",
            plan.firewall_table,
            "output",
            "handle",
            str(handles[0]),
        ]
    )
    return {"removed_handle": handles[0]}


def _remove_barrier(plan: HostProtectionPlan, evidence: dict) -> dict:
    _run(["nft", "delete", "table", "inet", plan.firewall_table])
    return {"removed_table": plan.firewall_table}


def linux_host_kernel(plan: HostProtectionPlan | None = None) -> HostKernel:
    """Return the real Linux surface, binding inventory when first called."""
    # Inventory receives no plan in the executor protocol.  The closures learn
    # it from the first mutator/resource call; status supplies it immediately.
    holder: dict[str, HostProtectionPlan] = {}

    def bind(value: HostProtectionPlan) -> HostProtectionPlan:
        holder["plan"] = value
        return value

    if plan is not None:
        bind(plan)

    def inventory() -> dict:
        if "plan" not in holder:
            raise HostProtectionError("Linux host inventory requires the validated plan")
        return _inventory(holder["plan"])

    return HostKernel(
        inventory=inventory,
        install_barrier=lambda value: _install_barrier(bind(value)),
        install_endpoint=lambda value: _install_endpoint(bind(value)),
        install_wireguard=lambda value, fd: _install_wireguard(bind(value), fd),
        install_routes=lambda value: _install_routes(bind(value)),
        install_resolver=lambda value: _install_resolver(bind(value)),
        verify_ready=lambda value: _verify_ready(bind(value)),
        resource_state=lambda name, evidence, value: _resource_state(name, evidence, bind(value)),
        observe_resource=lambda name, value: _observe_resource(name, bind(value)),
        remove_resolver=lambda value, evidence: _remove_resolver(bind(value), evidence),
        remove_routes=lambda value, evidence: _remove_routes(bind(value), evidence),
        remove_wireguard=lambda value, evidence: _remove_wireguard(bind(value), evidence),
        remove_endpoint=lambda value, evidence: _remove_endpoint(bind(value), evidence),
        remove_barrier=lambda value, evidence: _remove_barrier(bind(value), evidence),
    )
