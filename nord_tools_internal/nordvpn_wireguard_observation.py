"""Read-only observations of disposable WireGuard peer connectivity.

A handshake is evidence of recent peer communication, not proof of routing
isolation, provider identity, resource ownership or a working kill switch.
"""

from __future__ import annotations

from dataclasses import dataclass
import time


class ObservationError(ValueError):
    """WireGuard peer observation is missing, ambiguous or malformed."""


@dataclass(frozen=True)
class PeerObservation:
    public_key: str
    latest_handshake: int
    received_bytes: int
    sent_bytes: int

    def exchanged_since(self, started_at: int) -> bool:
        """Require a handshake within the test window and traffic in both directions."""
        return self.latest_handshake >= started_at and self.received_bytes > 0 and self.sent_bytes > 0


def parse_peer_dump(dump: str, expected_public_key: str) -> PeerObservation:
    """Parse a single peer from ``wg show IFACE dump`` without exposing keys.

    Reject ambiguous peers and incomplete output rather than interpreting an
    absent handshake or zero counters as success.
    """
    if not isinstance(dump, str) or not isinstance(expected_public_key, str) or not expected_public_key:
        raise ObservationError("invalid peer observation input")
    lines = dump.splitlines()
    if len(lines) < 2:
        raise ObservationError("WireGuard peer observation is incomplete")
    matches = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 8:
            raise ObservationError("malformed WireGuard peer observation")
        if fields[0] == expected_public_key:
            try:
                handshake, received, sent = (int(fields[index]) for index in (4, 5, 6))
            except ValueError as exc:
                raise ObservationError("non-numeric WireGuard peer counters") from exc
            if min(handshake, received, sent) < 0:
                raise ObservationError("negative WireGuard peer counters")
            matches.append(PeerObservation(fields[0], handshake, received, sent))
    if len(matches) != 1:
        raise ObservationError("expected exactly one matching WireGuard peer")
    return matches[0]


def require_fresh_exchange(
    dump: str, expected_public_key: str, started_at: int, *, now: int | None = None
) -> PeerObservation:
    """Validate fresh two-way peer activity for an explicitly bounded test."""
    if type(started_at) is not int or started_at <= 0:
        raise ObservationError("invalid test start timestamp")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < started_at:
        raise ObservationError("invalid observation timestamp")
    peer = parse_peer_dump(dump, expected_public_key)
    if peer.latest_handshake > current or not peer.exchanged_since(started_at):
        raise ObservationError("no fresh bidirectional WireGuard exchange observed")
    return peer
