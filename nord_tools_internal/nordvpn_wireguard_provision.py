"""Validated, non-executable WireGuard provisioning specifications.

This boundary deliberately does not accept private keys or execute commands.
Credentials must be supplied to a future privileged executor through a
separate, non-serialised channel; plans are safe to inspect and log.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import ipaddress
import re


class ProvisioningError(ValueError):
    """A proposed disposable tunnel violates the provisioning contract."""


_NAMESPACE = re.compile(r"nt-[a-z0-9]{8,24}\Z")
_INTERFACE = re.compile(r"ntwg[0-9a-f]{4,10}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")


@dataclass(frozen=True)
class TunnelSpecification:
    """Public, validated tunnel metadata; never contains a private key."""

    namespace: str
    interface: str
    peer_public_key: str
    endpoint_address: str
    endpoint_port: int
    tunnel_address: str
    peer_allowed_ips: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, str) or not _NAMESPACE.fullmatch(self.namespace):
            raise ProvisioningError("invalid disposable namespace name")
        if not isinstance(self.interface, str) or not _INTERFACE.fullmatch(self.interface):
            raise ProvisioningError("invalid disposable WireGuard interface name")
        if not isinstance(self.peer_public_key, str) or not _PUBLIC_KEY.fullmatch(self.peer_public_key):
            raise ProvisioningError("invalid WireGuard peer public key encoding")
        # WireGuard public keys encode exactly 32 bytes, with canonical padding.
        try:
            decoded = base64.b64decode(self.peer_public_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ProvisioningError("invalid WireGuard peer public key encoding") from exc
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != self.peer_public_key:
            raise ProvisioningError("non-canonical WireGuard peer public key")
        try:
            endpoint = ipaddress.ip_address(self.endpoint_address)
            tunnel = ipaddress.ip_interface(self.tunnel_address)
        except (ValueError, TypeError) as exc:
            raise ProvisioningError("endpoint and tunnel address must be numeric IP literals") from exc
        if endpoint.is_unspecified or endpoint.is_multicast or endpoint.is_loopback:
            raise ProvisioningError("invalid peer endpoint address")
        if tunnel.ip.is_unspecified or tunnel.ip.is_multicast:
            raise ProvisioningError("invalid tunnel interface address")
        if type(self.endpoint_port) is not int or not 1 <= self.endpoint_port <= 65535:
            raise ProvisioningError("invalid peer endpoint port")
        if not isinstance(self.peer_allowed_ips, tuple) or not self.peer_allowed_ips:
            raise ProvisioningError("at least one allowed IP network is required")
        canonical = set()
        for value in self.peer_allowed_ips:
            if not isinstance(value, str):
                raise ProvisioningError("allowed IPs must be network strings")
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ProvisioningError("invalid or non-canonical allowed IP network") from exc
            if str(network) != value or value in canonical:
                raise ProvisioningError("duplicate or non-canonical allowed IP network")
            canonical.add(value)

    def public_plan(self) -> dict:
        """Return a credential-free plan; never imply that it was executed."""
        return {
            "version": 1,
            "mode": "offline_wireguard_provisioning",
            "network_changes_applied": False,
            "ownership_verified": False,
            "namespace": self.namespace,
            "interface": self.interface,
            "peer_public_key": self.peer_public_key,
            "endpoint": f"[{self.endpoint_address}]:{self.endpoint_port}"
            if ":" in self.endpoint_address
            else f"{self.endpoint_address}:{self.endpoint_port}",
            "tunnel_address": self.tunnel_address,
            "peer_allowed_ips": list(self.peer_allowed_ips),
            "requires_privileged_executor": True,
            "requires_private_key_out_of_band": True,
        }
