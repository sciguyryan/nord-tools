"""Production network tooling is capability-gated before mutation."""

import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_platform_compat import (
    PlatformCompatibilityError,
    verify_supported_network_platform,
)
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state
from tools import probe_platform_compatibility as probe


OUTPUTS = {
    ("ip", "-Version"): "ip utility, iproute2-7.3.0, libbpf 1.7.0\n",
    ("nft", "--version"): "nftables v1.1.7 (accepted)\n",
    ("wg", "--version"): "wireguard-tools v1.0.20260223\n",
    ("ip", "-j", "link", "show", "dev", "lo"): json.dumps([{"ifname": "lo", "ifindex": 1}]),
    ("ip", "-j", "-4", "route", "show", "table", "main"): json.dumps([{"dst": "default"}]),
    ("ip", "-j", "-6", "route", "show", "table", "main"): json.dumps([]),
    ("nft", "-j", "list", "ruleset"): json.dumps({"nftables": [{"metainfo": {}}]}),
    ("wg", "show", "all", "interfaces"): "ntwg1234\n",
}


def runner_with(changes=None):
    outputs = {**OUTPUTS, **(changes or {})}

    def run(arguments, **_kwargs):
        value = outputs[tuple(arguments)]
        if isinstance(value, BaseException):
            raise value
        return subprocess.CompletedProcess(arguments, 0, value, "")

    return run


def inspect(tmp_path: Path, changes=None):
    resolver = tmp_path / "netns"
    resolver.mkdir(mode=0o755)
    return verify_supported_network_platform(
        system=lambda: "Linux",
        release=lambda: "7.2.11-arch1-1",
        runner=runner_with(changes),
        resolver_root=resolver,
        resolver_owner=(os.geteuid(), os.getegid()),
    )


def test_accepted_profile_requires_versions_and_live_output_shapes(tmp_path):
    report = inspect(tmp_path)

    assert report["tools"] == {
        "iproute2": "7.3.0",
        "nftables": "1.1.7",
        "wireguard_tools": "1.0.20260223",
    }
    assert report["network_changes_applied"] is False
    assert len(report["capabilities"]) == 4


@pytest.mark.parametrize(
    "changes,match",
    [
        ({("ip", "-Version"): "ip utility, iproute2-7.4.0\n"}, "unsupported iproute2"),
        ({("nft", "--version"): "unknown\n"}, "unrecognised nftables"),
        ({("ip", "-j", "link", "show", "dev", "lo"): "not json"}, "invalid JSON"),
        ({("ip", "-j", "-6", "route", "show", "table", "main"): "{}"}, "route JSON"),
        ({("nft", "-j", "list", "ruleset"): '{"rules": []}'}, "nftables JSON"),
        ({("wg", "show", "all", "interfaces"): "name-is-far-too-long\n"}, "WireGuard interface"),
    ],
)
def test_unknown_versions_and_output_shapes_are_refused(tmp_path, changes, match):
    with pytest.raises(PlatformCompatibilityError, match=match):
        inspect(tmp_path, changes)


def test_non_linux_and_unaccepted_kernel_are_refused(tmp_path):
    with pytest.raises(PlatformCompatibilityError, match="Linux only"):
        verify_supported_network_platform(system=lambda: "FreeBSD", resolver_root=tmp_path)
    with pytest.raises(PlatformCompatibilityError, match="unsupported kernel"):
        verify_supported_network_platform(
            system=lambda: "Linux",
            release=lambda: "7.3.0-arch1-1",
            resolver_root=tmp_path,
        )


def test_unsafe_resolver_root_is_refused(tmp_path):
    resolver = tmp_path / "netns"
    resolver.mkdir(mode=0o777)
    resolver.chmod(0o777)
    with pytest.raises(PlatformCompatibilityError, match="resolver root is not trusted"):
        verify_supported_network_platform(
            system=lambda: "Linux",
            release=lambda: "7.2.11-arch1-1",
            runner=runner_with(),
            resolver_root=resolver,
            resolver_owner=(os.geteuid(), os.getegid()),
        )


def test_real_restoration_refuses_platform_before_creating_stores(tmp_path):
    config = {
        "version": 1,
        "policy": str(tmp_path / "policy.json"),
        "journal": str(tmp_path / "journal.json"),
        "bindings": str(tmp_path / "bindings.json"),
        "intent": str(tmp_path / "intents.json"),
        "run_record": str(tmp_path / "runs.json"),
        "tunnels": {},
    }
    with (
        patch(
            "nord_tools_internal.nordvpn_restore_executor.verify_supported_network_platform",
            side_effect=PlatformCompatibilityError("unsupported platform"),
        ) as preflight,
        patch("nord_tools_internal.nordvpn_restore_executor._real_kernel") as kernel,
        pytest.raises(PlatformCompatibilityError, match="unsupported platform"),
    ):
        restore_boot_state(config)

    preflight.assert_called_once_with()
    kernel.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_probe_dry_run_does_not_inspect_platform(capsys):
    with patch.object(probe, "verify_supported_network_platform") as inspect_platform:
        assert probe.main([]) == 0
    inspect_platform.assert_not_called()
    assert "No commands executed" in capsys.readouterr().out


def test_privileged_probe_reports_verified_profile(capsys):
    report = {"mode": "supported_network_platform", "network_changes_applied": False}
    with (
        patch.object(probe.sys, "platform", "linux"),
        patch.object(probe.os, "geteuid", return_value=0),
        patch.object(probe, "verify_supported_network_platform", return_value=report) as inspect_platform,
    ):
        assert probe.main(["--run-privileged"]) == 0
    inspect_platform.assert_called_once_with()
    assert "supported_network_platform" in capsys.readouterr().out
