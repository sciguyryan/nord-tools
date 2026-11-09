"""Regression coverage for the production WireGuard B3 acceptance helpers."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

from tools import probe_production_wireguard_confinement as probe
from tools import probe_live_tunnel_replacement as replacement_probe


def binding(token, kind, identifier, scope=None):
    evidence = {"device": 1, "inode": 2} if kind == "namespace" else {"scope": scope, "ifindex": 3}
    return {"allocation_id": token, "kind": kind, "identifier": identifier, "binding": evidence}


def test_owned_namespace_uses_only_current_generation_bindings():
    old_tokens = [f"old-{index}" for index in range(4)]
    tokens = [f"new-{index}" for index in range(4)]
    resources = [
        {"allocation_id": old_tokens[0], "kind": "namespace", "identifier": "nt-old", "profile": "alpha"},
        {"allocation_id": old_tokens[1], "kind": "interface", "identifier": "ntwg-old", "profile": "alpha"},
        {"allocation_id": old_tokens[2], "kind": "interface", "identifier": "ntul-old", "profile": "alpha"},
        {"allocation_id": old_tokens[3], "kind": "interface", "identifier": "nthl-old", "profile": "alpha"},
        {"allocation_id": tokens[0], "kind": "namespace", "identifier": "nt-current", "profile": "alpha"},
        {"allocation_id": tokens[1], "kind": "interface", "identifier": "ntwg-current", "profile": "alpha"},
        {"allocation_id": tokens[2], "kind": "interface", "identifier": "ntul-current", "profile": "alpha"},
        {"allocation_id": tokens[3], "kind": "interface", "identifier": "nthl-current", "profile": "alpha"},
    ]
    journal = {
        "allocations": {"resources": resources},
        "events": [
            *({"allocation_id": token, "state": "retired"} for token in old_tokens),
            *({"allocation_id": token, "state": "active"} for token in tokens),
        ],
    }
    bindings = {
        "bindings": [
            binding(old_tokens[0], "namespace", "nt-old"),
            binding(old_tokens[1], "interface", "ntwg-old", "nt-old"),
            binding(old_tokens[2], "interface", "ntul-old", "nt-old"),
            binding(old_tokens[3], "interface", "nthl-old", "host"),
            binding(tokens[0], "namespace", "nt-current"),
            binding(tokens[1], "interface", "ntwg-current", "nt-current"),
            binding(tokens[2], "interface", "ntul-current", "nt-current"),
            binding(tokens[3], "interface", "nthl-current", "host"),
        ]
    }
    status = {
        "operator_review_required": False,
        "resources": [
            *({"allocation_id": token, "finding": "consistent_retired"} for token in old_tokens),
            *({"allocation_id": token, "finding": "verified_current"} for token in tokens),
        ],
    }

    def read_document(path: Path):
        return {"journal": journal, "bindings": bindings, "intent": {"operations": []}}[path.stem]

    config = {"journal": "journal.json", "bindings": "bindings.json", "intent": "intent.json"}
    with (
        patch.object(probe, "read", side_effect=read_document),
        patch.object(probe, "discover", return_value={}),
        patch.object(probe, "preflight_ownership", return_value=status),
    ):
        assert probe.owned_namespace(config) == ("nt-current", "ntwg-current", "ntul-current")


def test_fail_closed_checks_both_families_and_transports():
    with (
        patch.object(probe, "verify_underlay_bypass") as bypass,
        patch.object(probe, "verify_dns_unavailable") as dns,
    ):
        probe.verify_fail_closed("client", "server", 53054)

    assert bypass.call_args_list == [
        call("client", "server", "10.214.10.1", 53054, family=4, protocol="udp"),
        call("client", "server", "10.214.10.1", 53054, family=4, protocol="tcp"),
        call("client", "server", "fd42:214::1", 53054, family=6, protocol="udp"),
        call("client", "server", "fd42:214::1", 53054, family=6, protocol="tcp"),
    ]
    assert dns.call_args_list == [
        call("client", "10.250.0.1", family=4),
        call("client", "fd42:250::1", family=6),
    ]


def test_failed_establishment_must_leave_uncertain_evidence():
    config = {"journal": "journal.json", "intent": "intent.json"}

    def read_document(path: Path):
        if path.stem == "journal":
            return {"allocations": {"resources": []}}
        return {"operations": [{"outcome": "failed"}]}

    with (
        patch.object(probe, "read", side_effect=read_document),
        patch.object(probe, "discover", return_value={}),
        pytest.raises(probe.AcceptanceError, match="uncertain recovery evidence"),
    ):
        probe.verify_profile_absent(config)


def test_peer_attachment_uses_only_the_active_generation_underlay():
    journal = {
        "allocations": {
            "resources": [
                {"allocation_id": "old", "profile": "alpha", "kind": "interface", "identifier": "nthl-old"},
                {"allocation_id": "current", "profile": "alpha", "kind": "interface", "identifier": "nthl-current"},
            ]
        },
        "events": [
            {"allocation_id": "old", "state": "retired"},
            {"allocation_id": "current", "state": "active"},
        ],
    }
    bindings = {
        "bindings": [
            {"allocation_id": "old", "binding": {"scope": "host", "ifindex": 4}},
            {"allocation_id": "current", "binding": {"scope": "host", "ifindex": 5}},
        ]
    }

    def read_document(path: Path):
        return {"journal": journal, "bindings": bindings}[path.stem]

    config = {"journal": "journal.json", "bindings": "bindings.json"}
    with (
        patch.object(replacement_probe, "read", side_effect=read_document),
        patch.object(replacement_probe, "command") as command,
    ):
        replacement_probe.attach_underlay_to_peer(config, "alpha", "peer-bridge", "10.214.10.1/30")

    assert command.call_args_list == [
        call("ip", "address", "del", "10.214.10.1/30", "dev", "nthl-current"),
        call("ip", "link", "set", "nthl-current", "master", "peer-bridge"),
        call("ip", "link", "set", "nthl-current", "up"),
    ]


def test_tunnel_verification_allows_bounded_handshake_convergence():
    def command_result(*arguments, **_kwargs):
        if "peers" in arguments:
            return b"peer-key"
        return b"10.250.0.1 dev ntwg-current"

    attempts = [
        SimpleNamespace(returncode=1),
        SimpleNamespace(returncode=0),
        SimpleNamespace(returncode=0),
    ]
    with (
        patch.object(probe, "command", side_effect=command_result),
        patch.object(probe.subprocess, "run", side_effect=attempts) as ping,
        patch.object(probe.time, "monotonic", side_effect=[0, 0, 0]),
        patch.object(probe.time, "sleep"),
    ):
        probe.verify_tunnel("client", "ntwg-current", "peer-key", timeout=15)

    assert ping.call_count == 3
