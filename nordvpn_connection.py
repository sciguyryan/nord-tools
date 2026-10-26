"""Opt-in NordVPN Linux CLI connection support.

No benchmark operation imports or calls this module unless connection is requested.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

SERVER_ID = re.compile(r"^(?P<id>[a-z]{2}[0-9]+)\.nordvpn\.com$", re.I)


class ConnectionError(RuntimeError):
    """A connection could not be made or verified safely."""


@dataclass(frozen=True)
class ConnectionState:
    connected: bool
    server: str | None
    raw: str


def run_client(*args: str, timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(["nordvpn", *args], capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ConnectionError(f"nordvpn {args[0]} timed out") from exc
    except OSError as exc:
        raise ConnectionError(f"cannot execute nordvpn: {exc}") from exc


def normalise_server_identity(value: str) -> str | None:
    """Accept only exact NordVPN server IDs or canonical hostnames."""
    candidate = value.strip().lower().rstrip(".")
    if SERVER_ID.fullmatch(candidate):
        return candidate
    if re.fullmatch(r"[a-z]{2}[0-9]+", candidate, re.I):
        return f"{candidate}.nordvpn.com"
    return None


def parse_status(raw: str) -> ConnectionState:
    """Parse recognised English status fields without inferring an identity."""
    states = re.findall(r"^\s*Status:\s*(Connected|Disconnected)\s*$", raw, re.I | re.M)
    if len(states) != 1:
        raise ConnectionError("NordVPN status format is not recognised; refusing to change the connection")
    connected = states[0].lower() == "connected"
    # Some CLI versions use Hostname rather than Current server. Never use
    # Country, City, IP or generic descriptive labels as identity evidence.
    values = re.findall(r"^\s*(?:Current server|Hostname|Server hostname):\s*(.*?)\s*$", raw, re.I | re.M)
    identities = {normalise_server_identity(value) for value in values}
    identities.discard(None)
    if len(identities) > 1:
        raise ConnectionError("NordVPN status contains conflicting server identities")
    # A present but unrecognised field is not evidence of an exact server.
    if values and any(normalise_server_identity(value) is None for value in values):
        raise ConnectionError("NordVPN status contains an unrecognised server identity")
    server = next(iter(identities), None) if connected else None
    return ConnectionState(connected, server, raw)


def status() -> ConnectionState:
    result = run_client("status")
    if result.returncode:
        raise ConnectionError(f"cannot read NordVPN status: {(result.stderr or result.stdout).strip()}")
    return parse_status(result.stdout)


def benchmark_preflight(*, allow_active_vpn: bool = False, stream=None) -> bool:
    """Check NordVPN CLI status without changing any network connections.

    Return False only when a confirmed connection blocks benchmarking. Missing
    clients and unreadable status are reported as uncertain, not disconnected.
    """
    stream = stream or sys.stderr
    if sys.platform != "linux" or shutil.which("nordvpn") is None:
        print("Preflight: NordVPN connection status unavailable; other VPNs may affect results.", file=stream)
        return True
    try:
        current = status()
    except ConnectionError as exc:
        print(
            f"Preflight: cannot establish NordVPN connection status ({exc}). Results may be affected by a VPN.",
            file=stream,
        )
        return True
    if not current.connected:
        return True
    server = current.server or "unknown server"
    print(f"Preflight: NordVPN is connected ({server}). Benchmark measurements may be distorted.", file=stream)
    if allow_active_vpn:
        print("Continuing with --allow-active-vpn; measurements reflect the current network path.", file=stream)
        return True
    print("Disconnect using `nordvpn disconnect`, then rerun; or explicitly use --allow-active-vpn.", file=stream)
    return False


def preview_connection(records: list[dict], rank: int, *, replace_existing: bool = False, stream=None) -> str:
    """Describe the connection plan without executing a NordVPN connection.

    Reading the installed client's status is permitted. Never invoke connect,
    disconnect, or any other command that changes VPN state.
    """
    stream = stream or sys.stderr
    if sys.platform != "linux":
        raise ConnectionError("--auto-connect currently supports Linux only")
    if shutil.which("nordvpn") is None:
        raise ConnectionError("NordVPN Linux CLI not found in PATH")
    if rank < 1 or rank > len(records):
        raise ConnectionError(f"--connect-rank must be between 1 and {len(records)}")
    record = records[rank - 1]
    if not record.get("received", 0):
        raise ConnectionError("selected server has no successful probe samples; refusing automatic connection")
    hostname = str(record["server"]).lower()
    match = SERVER_ID.fullmatch(hostname)
    if not match:
        raise ConnectionError(f"cannot derive a NordVPN server identifier from {hostname!r}")
    server_id = match.group("id").lower()
    current = status()
    print(f"Dry run: selected rank {rank}: {hostname}", file=stream)
    if current.connected and current.server == hostname:
        print(f"Dry run: already connected to {hostname}; no connection command needed.", file=stream)
        return "already-connected"
    if current.connected:
        print(f"Dry run: existing VPN connection: {current.server or 'unknown server'}.", file=stream)
        if not replace_existing:
            print("Dry run: replacement would require interactive confirmation or --replace-connection.", file=stream)
            print("Dry run: no connection command would run without that authorisation.", file=stream)
            return "confirmation-required"
        print("Dry run: --replace-connection authorises replacing the existing connection.", file=stream)
    print(f"Dry run: would execute: nordvpn connect {server_id}", file=stream)
    print("Dry run: no VPN connection was changed; server identity would be verified afterwards.", file=stream)
    return "ready"


def connect(records: list[dict], rank: int, *, replace_existing: bool = False, confirm=None, stream=None) -> str | None:
    """Connect to the selected rank and verify the actual NordVPN status.

    A ranked record is an OpenVPN profile, not necessarily a NordVPN CLI server.
    Only canonical hostnames can be mapped to a CLI identifier; an IP address
    alone does not prove that identity. No implicit fallback to another server.
    """
    stream = stream or sys.stderr
    if sys.platform != "linux":
        raise ConnectionError("--auto-connect currently supports Linux only")
    if shutil.which("nordvpn") is None:
        raise ConnectionError("NordVPN Linux CLI not found in PATH")
    if rank < 1 or rank > len(records):
        raise ConnectionError(f"--connect-rank must be between 1 and {len(records)}")
    record = records[rank - 1]
    if not record.get("received", 0):
        raise ConnectionError("selected server has no successful probe samples; refusing automatic connection")
    filename = record["server"]
    # The canonical name is carried by NordVPN profile filenames even when the
    # remote directive is a numeric IP address.
    match = SERVER_ID.fullmatch(filename)
    if not match:
        raise ConnectionError(f"cannot derive a NordVPN server identifier from {filename!r}")
    hostname = filename.lower()
    server_id = match.group("id").lower()
    current = status()
    if current.connected:
        if current.server == hostname:
            print(f"Already connected to {hostname}; no change required.", file=stream)
            return hostname
        if not replace_existing:
            if confirm is None or not confirm(current.server, hostname):
                raise ConnectionError(
                    "existing VPN connection left unchanged; use --replace-connection to authorise replacement"
                )
    print(f"Connecting to {hostname} using the NordVPN client...", file=stream)
    result = run_client("connect", server_id, timeout=90)
    if result.returncode:
        raise ConnectionError(f"NordVPN connection failed: {(result.stderr or result.stdout).strip()}")
    actual = status()
    if not actual.connected:
        raise ConnectionError("NordVPN reported success but its status is not connected")
    if not actual.server:
        print(
            f"Warning: NordVPN reports an established connection, but does not provide a server identity. "
            f"Cannot verify that {hostname} was selected.",
            file=stream,
        )
        return None
    if actual.server != hostname:
        raise ConnectionError(f"NordVPN connected to {actual.server}, not requested {hostname}")
    print(f"Connected and verified: {actual.server}", file=stream)
    return actual.server
