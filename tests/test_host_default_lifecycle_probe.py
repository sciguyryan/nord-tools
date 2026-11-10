"""Dry-run contract for the privileged host-default lifecycle probe."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from test_host_executor import PLAN
from tools import probe_host_domain_acceptance as host_acceptance


def test_host_lifecycle_probe_defaults_to_preview(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(Path("tools/probe_host_default_lifecycle.py")),
            "--plan",
            str(plan),
            "--store",
            str(tmp_path / "host.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == "host_default_dry_run"
    assert report["network_changes_applied"] is False
    assert not (tmp_path / "host.json").exists()


def test_host_lifecycle_probe_reports_missing_plan_without_traceback(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(Path("tools/probe_host_default_lifecycle.py")),
            "--plan",
            str(tmp_path / "missing.json"),
            "--store",
            str(tmp_path / "host.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 2
    assert "cannot read a valid host plan" in result.stderr
    assert "Traceback" not in result.stderr


def test_host_domain_acceptance_defaults_to_a_non_mutating_preview():
    result = subprocess.run(
        [sys.executable, str(Path("tools/probe_host_domain_acceptance.py"))],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "DRY RUN: D1 host-domain" in result.stdout
    assert "interrupts remote guest management" in result.stdout


def test_host_domain_resolver_check_uses_a_non_special_query_name(tmp_path):
    response = subprocess.CompletedProcess(["resolvectl"], 1, "", "not found")
    with (
        patch.object(host_acceptance, "dns_event_count", side_effect=[0, 1, 1]),
        patch.object(host_acceptance.subprocess, "run", return_value=response) as run,
    ):
        host_acceptance.verify_resolved_packet_path(tmp_path / "dns.jsonl", "abc123")
    assert run.call_args.args[0] == ["resolvectl", "query", "--type=A", "abc123.d1.nordtools"]


def test_host_domain_underlay_observer_does_not_bind_the_wireguard_udp_port():
    assert "socket.AF_PACKET" in host_acceptance.UNDERLAY_LISTENER
    assert "sock.bind((interface, 0))" in host_acceptance.UNDERLAY_LISTENER
    assert "sock.bind((address, port))" not in host_acceptance.UNDERLAY_LISTENER


def test_host_domain_static_underlay_disables_ipv6_address_generation():
    source = Path("tools/probe_host_domain_acceptance.py").read_text(encoding="utf-8")
    assert 'command("ip", "link", "set", host_link, "addrgenmode", "none")' in source
    assert 'command("ip", "-n", namespace, "link", "set", peer_link, "addrgenmode", "none")' in source
