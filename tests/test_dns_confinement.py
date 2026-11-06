"""Adversarial DNS route and resolver readback tests."""

import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_dns_confinement import (
    DNSConfinementError,
    verify_dns_routes,
    verify_resolver_file,
)
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy


POLICY = NamespaceResolverPolicy(("1.1.1.1", "2606:4700:4700::1111"))


def test_dns_route_requires_each_family_on_tunnel():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps([{"dev": "ntwg0"}]), "")

    with patch("subprocess.run", side_effect=run):
        verify_dns_routes("nt-test", "ntwg0", POLICY)
    assert [command[6] for command in calls] == ["-4", "-6"]


@pytest.mark.parametrize(
    "readback", [[], [{"dev": "ntul0"}], [{"dev": "ntwg0"}, {"dev": "ntul0"}], [{"type": "blackhole", "dev": "ntwg0"}]]
)
def test_dns_route_rejects_unsafe_readback(readback):
    with (
        patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(readback), "")),
        pytest.raises(DNSConfinementError),
    ):
        verify_dns_routes("nt-test", "ntwg0", POLICY)


def test_dns_route_rejects_invalid_json():
    with (
        patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "bad", "")),
        pytest.raises(DNSConfinementError),
    ):
        verify_dns_routes("nt-test", "ntwg0", POLICY)


def test_resolver_file_exact_readback(tmp_path: Path):
    root = tmp_path / "netns"
    root.mkdir(mode=0o700)
    directory = root / "nt-test"
    directory.mkdir(mode=0o700)
    (directory / "resolv.conf").write_text(POLICY.render_resolv_conf(), encoding="ascii")
    verify_resolver_file("nt-test", POLICY, root=root)
    (directory / "resolv.conf").write_text("nameserver 8.8.8.8\n", encoding="ascii")
    with pytest.raises(DNSConfinementError):
        verify_resolver_file("nt-test", POLICY, root=root)


def test_resolver_file_rejects_symlink(tmp_path: Path):
    root = tmp_path / "netns"
    root.mkdir(mode=0o700)
    directory = root / "nt-test"
    directory.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_text(POLICY.render_resolv_conf())
    (directory / "resolv.conf").symlink_to(target)
    with pytest.raises(DNSConfinementError):
        verify_resolver_file("nt-test", POLICY, root=root)


def test_dns_peer_allowed_ips_requires_both_families():
    from nord_tools_internal.nordvpn_dns_confinement import verify_dns_peer_allowed_ips

    good = "key123\t0.0.0.0/0, ::/0\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, good, "")):
        verify_dns_peer_allowed_ips("nt-test", "wgtest", POLICY)
    bad = "key123\t0.0.0.0/0\n"
    with (
        patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, bad, "")),
        pytest.raises(DNSConfinementError),
    ):
        verify_dns_peer_allowed_ips("nt-test", "wgtest", POLICY)


@pytest.mark.parametrize("output", ["", "key1 0.0.0.0/0\nkey2 ::/0\n", "key1 malformed\n"])
def test_dns_peer_allowed_ips_rejects_ambiguous_or_invalid_readback(output):
    from nord_tools_internal.nordvpn_dns_confinement import verify_dns_peer_allowed_ips

    with (
        patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")),
        pytest.raises(DNSConfinementError),
    ):
        verify_dns_peer_allowed_ips("nt-test", "wgtest", POLICY)


def test_dns_acceptance_dry_run_is_non_mutating():
    import importlib.util

    script = Path(__file__).resolve().parents[1] / "tools" / "probe_part4b_dns_acceptance.py"
    spec = importlib.util.spec_from_file_location("dns_acceptance_probe", script)
    module = importlib.util.module_from_spec(spec)
    with patch("subprocess.run", side_effect=AssertionError("dry run must not execute commands")):
        spec.loader.exec_module(module)
        assert module.main([]) == 0
