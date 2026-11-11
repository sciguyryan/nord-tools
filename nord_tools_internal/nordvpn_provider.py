"""Secure import and deterministic boot selection for NordVPN WireGuard configurations."""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace

from nordvpn_connection import normalise_server_identity
from nordvpn_filter import compile_filter
from nordvpn_regions import country_code
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy


class ProviderError(ValueError):
    """Provider material cannot be imported or selected without ambiguity."""


_KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
_FIELD = re.compile(r"([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*\Z")
_CREDENTIAL_NAME = re.compile(r"ntprovider-[a-z]{2}[0-9]+\Z")
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")
MAX_CONFIGURATION_BYTES = 64 * 1024
MAX_CATALOGUE_BYTES = 4 * 1024 * 1024
MAX_SERVERS = 4096


def read_provider_configuration(path: str | Path) -> bytes:
    """Read a private, caller-owned regular file without following symlinks."""
    source = Path(path)
    try:
        info = source.stat(follow_symlinks=False)
        if (
            source.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > MAX_CONFIGURATION_BYTES
        ):
            raise ProviderError("provider configuration must be a private caller-owned regular file")
        descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(MAX_CONFIGURATION_BYTES + 1)
    except OSError as exc:
        raise ProviderError("provider configuration cannot be read safely") from exc
    if not payload or len(payload) > MAX_CONFIGURATION_BYTES:
        raise ProviderError("provider configuration is empty or exceeds its size limit")
    return payload


def provider_credential_name(server: str) -> str:
    canonical = normalise_server_identity(server)
    if canonical is None:
        raise ProviderError("provider server identity is invalid")
    name = "ntprovider-" + canonical.partition(".")[0]
    if not _CREDENTIAL_NAME.fullmatch(name):
        raise ProviderError("provider credential name is invalid")
    return name


def _canonical_key(value: str, label: str) -> str:
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise ProviderError(f"{label} must use canonical WireGuard key encoding")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProviderError(f"{label} must use canonical WireGuard key encoding") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ProviderError(f"{label} must use canonical WireGuard key encoding")
    return value


def _parse_sections(payload: bytes) -> dict[str, dict[str, str]]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_CONFIGURATION_BYTES:
        raise ProviderError("WireGuard configuration is empty or exceeds its size limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ProviderError("WireGuard configuration is not valid UTF-8") from exc
    sections: dict[str, dict[str, str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            if name not in {"Interface", "Peer"} or name in sections:
                raise ProviderError("WireGuard configuration requires one Interface and one Peer section")
            sections[name] = {}
            current = sections[name]
            continue
        match = _FIELD.fullmatch(line)
        if current is None or match is None or match.group(1) in current:
            raise ProviderError("WireGuard configuration contains an invalid or duplicate field")
        current[match.group(1)] = match.group(2)
    if set(sections) != {"Interface", "Peer"}:
        raise ProviderError("WireGuard configuration requires one Interface and one Peer section")
    return sections


def _split_csv(value: str, label: str) -> list[str]:
    values = [item.strip() for item in value.split(",")]
    if not values or any(not item for item in values):
        raise ProviderError(f"{label} is empty or malformed")
    return values


def _endpoint(value: str, resolver=socket.getaddrinfo, *, families: set[int]) -> tuple[str, int]:
    host = ""
    port_text = ""
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d+)", value)
        if match:
            host, port_text = match.groups()
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            host = ""
    if not host or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ProviderError("WireGuard endpoint must contain a host and valid port")
    try:
        address = str(ipaddress.ip_address(host))
        if ipaddress.ip_address(address).version not in families:
            raise ProviderError("WireGuard endpoint has no matching tunnel address family")
    except ValueError:
        try:
            answers = resolver(host, int(port_text), type=socket.SOCK_DGRAM)
            addresses = sorted(
                {
                    str(ipaddress.ip_address(item[4][0]))
                    for item in answers
                    if ipaddress.ip_address(item[4][0]).version in families
                }
            )
        except (OSError, ValueError, TypeError, IndexError) as exc:
            raise ProviderError("WireGuard endpoint DNS could not be resolved deterministically") from exc
        if not addresses:
            raise ProviderError("WireGuard endpoint DNS returned no numeric address")
        address = addresses[0]
    return address, int(port_text)


def parse_nordvpn_wireguard(payload: bytes, server: str, *, resolver=socket.getaddrinfo) -> tuple[dict, bytearray]:
    """Return a sanitised catalogue entry and an erasable private-key buffer."""
    canonical = normalise_server_identity(server)
    if canonical is None:
        raise ProviderError("NordVPN configuration requires a canonical server identity")
    sections = _parse_sections(payload)
    interface = sections["Interface"]
    peer = sections["Peer"]
    if set(interface) - {"PrivateKey", "Address", "DNS"}:
        raise ProviderError("WireGuard Interface contains unsupported fields")
    if set(peer) - {"PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}:
        raise ProviderError("WireGuard Peer contains unsupported fields")
    required_interface = {"PrivateKey", "Address", "DNS"}
    required_peer = {"PublicKey", "AllowedIPs", "Endpoint"}
    if not required_interface <= set(interface) or not required_peer <= set(peer):
        raise ProviderError("WireGuard configuration is missing required provider fields")
    private_key = bytearray(_canonical_key(interface["PrivateKey"], "private key").encode("ascii"))
    try:
        tunnel_addresses = [str(ipaddress.ip_interface(item)) for item in _split_csv(interface["Address"], "Address")]
        if not 1 <= len(tunnel_addresses) <= 2 or len(
            {ipaddress.ip_interface(x).version for x in tunnel_addresses}
        ) != len(tunnel_addresses):
            raise ProviderError("WireGuard Address must contain at most one address per family")
        dns_servers = [str(ipaddress.ip_address(item)) for item in _split_csv(interface["DNS"], "DNS")]
        try:
            dns_servers = list(NamespaceResolverPolicy(tuple(dns_servers)).servers)
        except (ValueError, TypeError) as exc:
            raise ProviderError("WireGuard DNS contains an unsafe resolver address") from exc
        allowed = [
            str(ipaddress.ip_network(item, strict=True)) for item in _split_csv(peer["AllowedIPs"], "AllowedIPs")
        ]
        if set(allowed) != {"0.0.0.0/0", "::/0"}:
            raise ProviderError("NordVPN WireGuard configuration must carry both default address families")
        endpoint_address, endpoint_port = _endpoint(
            peer["Endpoint"],
            resolver,
            families={ipaddress.ip_interface(item).version for item in tunnel_addresses},
        )
        keepalive = peer.get("PersistentKeepalive", "0")
        if not keepalive.isdigit() or not 0 <= int(keepalive) <= 65535:
            raise ProviderError("WireGuard PersistentKeepalive is invalid")
        entry = {
            "server": canonical,
            "country": country_code(canonical),
            "peer_public_key": _canonical_key(peer["PublicKey"], "peer public key"),
            "endpoint_address": endpoint_address,
            "endpoint_port": endpoint_port,
            "persistent_keepalive_seconds": int(keepalive),
            "tunnel_addresses": tunnel_addresses,
            "peer_allowed_ips": allowed,
            "dns_servers": dns_servers,
        }
        if entry["country"] is None:
            raise ProviderError("NordVPN server country is not recognised")
        return entry, private_key
    except BaseException:
        private_key[:] = b"\x00" * len(private_key)
        raise


def derive_public_key(private_key: bytes | bytearray, *, runner=subprocess.run) -> str:
    """Derive a public key through stdin; neither output nor errors may disclose input."""
    try:
        result = runner(
            ["wg", "pubkey"],
            input=bytes(private_key) + b"\n",
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProviderError("WireGuard public-key derivation failed") from exc
    if result.returncode:
        raise ProviderError("WireGuard public-key derivation failed")
    try:
        value = result.stdout.decode("ascii").strip() if isinstance(result.stdout, bytes) else result.stdout.strip()
    except (UnicodeError, AttributeError) as exc:
        raise ProviderError("WireGuard public-key derivation returned invalid output") from exc
    return _canonical_key(value, "client public key")


def validate_provider_catalogue(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {"version", "provider", "servers"}:
        raise ProviderError("provider catalogue has an invalid schema")
    if document["version"] != 1 or document["provider"] != "nordvpn" or not isinstance(document["servers"], list):
        raise ProviderError("provider catalogue has an invalid version or provider")
    if len(document["servers"]) > MAX_SERVERS:
        raise ProviderError("provider catalogue exceeds its server limit")
    servers = []
    seen = set()
    expected = {
        "server",
        "country",
        "peer_public_key",
        "client_public_key",
        "endpoint_address",
        "endpoint_port",
        "persistent_keepalive_seconds",
        "tunnel_addresses",
        "peer_allowed_ips",
        "dns_servers",
        "credential",
    }
    for source in document["servers"]:
        if not isinstance(source, dict) or set(source) != expected:
            raise ProviderError("provider catalogue server has invalid fields")
        server = normalise_server_identity(source["server"]) if isinstance(source["server"], str) else None
        if server is None or server != source["server"] or server in seen or country_code(server) != source["country"]:
            raise ProviderError("provider catalogue contains an invalid or duplicate server")
        seen.add(server)
        try:
            endpoint = str(ipaddress.ip_address(source["endpoint_address"]))
            tunnels = [str(ipaddress.ip_interface(item)) for item in source["tunnel_addresses"]]
            allowed = [str(ipaddress.ip_network(item, strict=True)) for item in source["peer_allowed_ips"]]
            dns = [str(ipaddress.ip_address(item)) for item in source["dns_servers"]]
        except (ValueError, TypeError) as exc:
            raise ProviderError("provider catalogue contains invalid network data") from exc
        if (
            type(source["endpoint_port"]) is not int
            or not 1 <= source["endpoint_port"] <= 65535
            or type(source["persistent_keepalive_seconds"]) is not int
            or not 0 <= source["persistent_keepalive_seconds"] <= 65535
            or set(allowed) != {"0.0.0.0/0", "::/0"}
            or not isinstance(source["credential"], str)
            or not _SAFE_PATH.fullmatch(source["credential"])
            or not 1 <= len(tunnels) <= 2
            or len({item.version for item in map(ipaddress.ip_interface, tunnels)}) != len(tunnels)
        ):
            raise ProviderError("provider catalogue contains an invalid endpoint, route or credential path")
        try:
            dns = list(NamespaceResolverPolicy(tuple(dns)).servers)
        except (ValueError, TypeError) as exc:
            raise ProviderError("provider catalogue contains unsafe resolver data") from exc
        servers.append(
            {
                **source,
                "server": server,
                "peer_public_key": _canonical_key(source["peer_public_key"], "peer public key"),
                "client_public_key": _canonical_key(source["client_public_key"], "client public key"),
                "endpoint_address": endpoint,
                "tunnel_addresses": tunnels,
                "peer_allowed_ips": allowed,
                "dns_servers": dns,
            }
        )
    return {"version": 1, "provider": "nordvpn", "servers": sorted(servers, key=lambda item: item["server"])}


def load_provider_catalogue(path: str | Path) -> dict:
    path = Path(path)
    try:
        info = path.stat(follow_symlinks=False)
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > MAX_CATALOGUE_BYTES
        ):
            raise ProviderError("provider catalogue is missing, unsafe or oversized")
        return validate_provider_catalogue(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderError("provider catalogue cannot be read") from exc


def _secure_parent(path: Path) -> None:
    parent = path.parent
    try:
        info = parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise ProviderError("provider destination parent is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ProviderError("provider destination parent must be owned by the caller and not group/world writable")


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    _secure_parent(path)
    if path.exists() or path.is_symlink():
        try:
            info = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise ProviderError("provider destination cannot be inspected") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ProviderError("provider destination must be a private caller-owned regular file")
    fd, temporary = tempfile.mkstemp(prefix=".nord-provider-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def import_provider_configuration(
    payload: bytes,
    *,
    server: str,
    credential_path: str | Path,
    catalogue_path: str | Path,
    rotate: bool = False,
    execute: bool = False,
    resolver=socket.getaddrinfo,
    runner=subprocess.run,
) -> dict:
    entry, private_key = parse_nordvpn_wireguard(payload, server, resolver=resolver)
    try:
        entry["client_public_key"] = derive_public_key(private_key, runner=runner)
        entry["credential"] = str(Path(credential_path))
        catalogue_file = Path(catalogue_path)
        credential_file = Path(credential_path)
        if not catalogue_file.is_absolute() or not credential_file.is_absolute():
            raise ProviderError("provider catalogue and credential paths must be absolute")
        try:
            catalogue = load_provider_catalogue(catalogue_file)
        except ProviderError:
            if catalogue_file.exists() or catalogue_file.is_symlink():
                raise
            catalogue = {"version": 1, "provider": "nordvpn", "servers": []}
        existing = {item["server"]: item for item in catalogue["servers"]}
        if entry["server"] in existing and not rotate:
            raise ProviderError("provider server already exists; explicit rotation is required")
        if credential_file.exists() and not rotate:
            raise ProviderError("provider credential already exists; explicit rotation is required")
        existing[entry["server"]] = entry
        updated = validate_provider_catalogue({"version": 1, "provider": "nordvpn", "servers": list(existing.values())})
        report = {
            "version": 1,
            "mode": "provider_configuration_import",
            "server": entry["server"],
            "country": entry["country"],
            "credential_path": str(credential_file),
            "catalogue_path": str(catalogue_file),
            "rotated": bool(entry["server"] in {item["server"] for item in catalogue["servers"]}),
            "executed": execute,
            "secret_material_reported": False,
        }
        if execute:
            encoded = (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode("utf-8")
            # Publish the non-secret expected public identity first. A crash before
            # credential replacement leaves a detectable mismatch at boot.
            _atomic_write(catalogue_file, encoded, 0o600)
            _atomic_write(credential_file, bytes(private_key) + b"\n", 0o600)
        return report
    finally:
        private_key[:] = b"\x00" * len(private_key)


def _timestamp(value: object) -> datetime.datetime:
    if not isinstance(value, str):
        raise ProviderError("benchmark report has no completion timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderError("benchmark report completion timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ProviderError("benchmark report completion timestamp lacks a timezone")
    return parsed.astimezone(datetime.timezone.utc)


def rank_provider_servers(
    policy: object,
    catalogue: object,
    report: object | None,
    *,
    max_report_age_seconds: int,
    now: datetime.datetime | None = None,
) -> dict[str, list[dict]]:
    """Return every eligible server per profile in deterministic preference order."""
    checked = validate_policy(policy)
    catalogue = validate_provider_catalogue(catalogue)
    servers = {item["server"]: item for item in catalogue["servers"]}
    now = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc)
    if type(max_report_age_seconds) is not int or not 0 <= max_report_age_seconds <= 31 * 24 * 3600:
        raise ProviderError("provider benchmark maximum age is invalid")
    resolved = {}
    for name, profile in sorted(checked["vpn_profiles"].items()):
        selection = profile["selection"]
        mode = selection["mode"]
        candidates = list(servers.values())
        if mode == "pinned":
            candidates = [servers[selection["server"]]] if selection["server"] in servers else []
        elif mode == "country":
            candidates = sorted(
                (item for item in candidates if item["country"] == selection["country"]),
                key=lambda item: item["server"],
            )
        elif mode == "fastest":
            if (
                not isinstance(report, dict)
                or report.get("schema_version") != 1
                or not isinstance(report.get("ranking"), list)
            ):
                raise ProviderError(f"profile {name} requires a version 1 benchmark report")
            age = (now - _timestamp(report.get("finished_at"))).total_seconds()
            if age < 0 or age > max_report_age_seconds:
                raise ProviderError(f"profile {name} benchmark report is outside its permitted age")
            try:
                predicate = compile_filter(selection["filter"])
            except ValueError as exc:
                raise ProviderError(f"profile {name} filter is invalid") from exc
            rankings = []
            for row in report["ranking"]:
                if not isinstance(row, dict):
                    raise ProviderError("benchmark ranking entry is invalid")
                server = normalise_server_identity(row.get("server")) if isinstance(row.get("server"), str) else None
                latency = row.get("median_ms")
                loss = row.get("loss_pct")
                protocol = row.get("protocol")
                port = row.get("port")
                if (
                    server is None
                    or server != row.get("server", "").lower()
                    or protocol not in {"udp", "tcp"}
                    or type(port) is not int
                    or not 1 <= port <= 65535
                    or isinstance(latency, bool)
                    or not isinstance(latency, (int, float))
                    or not math.isfinite(latency)
                    or latency < 0
                    or isinstance(loss, bool)
                    or not isinstance(loss, (int, float))
                    or not math.isfinite(loss)
                    or not 0 <= loss <= 100
                    or type(row.get("received")) is not int
                    or row["received"] < 0
                ):
                    raise ProviderError("benchmark ranking entry is invalid")
                endpoint = SimpleNamespace(name=server, protocol=protocol, port=port)
                if row["received"] and server in servers and predicate(endpoint):
                    rankings.append((float(loss), float(latency), server))
            rankings.sort()
            ordered = []
            seen = set()
            for _, _, server in rankings:
                if server not in seen:
                    ordered.append(servers[server])
                    seen.add(server)
            candidates = ordered
        if not candidates:
            raise ProviderError(f"profile {name} has no eligible imported provider server")
        resolved[name] = [dict(item) for item in candidates]
    return resolved


def select_provider_servers(
    policy: object,
    catalogue: object,
    report: object | None,
    *,
    max_report_age_seconds: int,
    now: datetime.datetime | None = None,
) -> dict[str, dict]:
    """Resolve every policy profile to its first eligible provider configuration."""
    ranked = rank_provider_servers(
        policy,
        catalogue,
        report,
        max_report_age_seconds=max_report_age_seconds,
        now=now,
    )
    return {name: candidates[0] for name, candidates in ranked.items()}


def allocate_provider_servers(
    policy: object, sources: dict[str, str], ranked: dict[str, list[dict]]
) -> dict[str, dict]:
    """Reserve one distinct eligible provider identity for every effective allocation."""
    checked = validate_policy(policy)
    if not isinstance(sources, dict) or not sources or set(sources.values()) - set(checked["vpn_profiles"]):
        raise ProviderError("provider allocation sources are invalid")
    grouped: dict[str, list[str]] = {}
    for name, source in sorted(sources.items()):
        if not isinstance(name, str) or not name:
            raise ProviderError("provider allocation identity is invalid")
        grouped.setdefault(source, []).append(name)
    priority = {"pinned": 0, "country": 1, "fastest": 2}
    source_order = sorted(
        grouped,
        key=lambda source: (priority[checked["vpn_profiles"][source]["selection"]["mode"]], source),
    )
    assignments = {}
    used_servers = set()
    for source in source_order:
        candidates = ranked.get(source)
        if not isinstance(candidates, list) or any(
            not isinstance(entry, dict) or not isinstance(entry.get("server"), str) for entry in candidates
        ):
            raise ProviderError(f"profile {source} has invalid ranked provider candidates")
        available = []
        reserved = set(used_servers)
        for entry in candidates:
            if entry["server"] not in reserved:
                available.append(entry)
                reserved.add(entry["server"])
        if len(available) < len(grouped[source]):
            raise ProviderError(
                f"profile {source} has too few distinct eligible provider configurations for its allocations"
            )
        for name, entry in zip(grouped[source], available[: len(grouped[source])], strict=True):
            assignments[name] = dict(entry)
            used_servers.add(entry["server"])
    return assignments


def catalogue_sha256(catalogue: object) -> str:
    checked = validate_provider_catalogue(catalogue)
    payload = json.dumps(checked, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
