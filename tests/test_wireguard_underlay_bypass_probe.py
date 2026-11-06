"""Regression checks for expected firewall refusal of a UDP bypass attempt."""

import io
import subprocess
from unittest.mock import Mock, patch

import pytest

from tools import probe_wireguard_dns_acceptance as probe


def _listener():
    process = Mock()
    process.stdout = io.StringIO("READY\n")
    process.stderr = io.StringIO("")
    process.poll.return_value = 0
    process.wait.return_value = 0  # Timeout: no bypass packet arrived.
    return process


@pytest.mark.parametrize("output", ["", "BLOCKED\n"])
def test_underlay_probe_accepts_silent_drop_or_explicit_kernel_refusal(output):
    with (
        patch.object(probe.subprocess, "Popen", return_value=_listener()),
        patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")),
        patch.object(probe, "_verify_base_chains"),
    ):
        probe._verify_application_underlay_refusal("client", "server", "underlay")


def test_underlay_probe_rejects_unexpected_sender_failure():
    with (
        patch.object(probe.subprocess, "Popen", return_value=_listener()),
        patch.object(
            probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, "", "unexpected socket error")
        ),
        pytest.raises(probe.DNSAcceptanceError, match="unexpected socket error"),
    ):
        probe._verify_application_underlay_refusal("client", "server", "underlay")


def test_underlay_probe_rejects_delivered_packet():
    process = _listener()
    process.wait.return_value = 3  # Listener received bypass packet.
    with (
        patch.object(probe.subprocess, "Popen", return_value=process),
        patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")),
        pytest.raises(probe.DNSAcceptanceError, match="escaped to the underlay"),
    ):
        probe._verify_application_underlay_refusal("client", "server", "underlay")
