"""Deterministic application DNS and underlay refusal regression contracts."""

from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from tools import production_application_dns as application


def test_dns_requires_successful_application_response():
    with patch.object(application, "_execute", return_value=CompletedProcess([], 0, "", "")) as execute:
        application.verify_application_dns("owned-ns", "fd42:250::1", family=6)
    assert execute.call_args.args[2:] == ("fd42:250::1", "6")


def test_dns_refuses_failed_or_malformed_response():
    with (
        patch.object(application, "_execute", return_value=CompletedProcess([], 3, "", "bad response")),
        pytest.raises(application.ApplicationConfinementError, match="IPv4 application DNS response failed"),
    ):
        application.verify_application_dns("owned-ns", "10.250.0.1")


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_bypass_listener_must_time_out(protocol):
    listener = MagicMock()
    listener.stdout.readline.return_value = "READY\n"
    listener.wait.return_value = 0
    listener.poll.return_value = 0
    with (
        patch.object(application.subprocess, "Popen", return_value=listener),
        patch.object(application, "_execute", return_value=CompletedProcess([], 0, "", "")),
    ):
        application.verify_underlay_bypass("owned-ns", "peer-ns", "10.214.10.1", 53053, protocol=protocol)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_bypass_delivery_is_failure(protocol):
    listener = MagicMock()
    listener.stdout.readline.return_value = "READY\n"
    listener.wait.return_value = 3
    listener.poll.return_value = 3
    with (
        patch.object(application.subprocess, "Popen", return_value=listener),
        patch.object(application, "_execute", return_value=CompletedProcess([], 0, "", "")),
        pytest.raises(application.ApplicationConfinementError, match="escaped onto underlay"),
    ):
        application.verify_underlay_bypass("owned-ns", "peer-ns", "10.214.10.1", 53053, protocol=protocol)


def test_invalid_bypass_parameters_refused_before_launch():
    with pytest.raises(ValueError, match="unsupported protocol"):
        application.verify_underlay_bypass("owned-ns", "peer-ns", "10.214.10.1", 53053, protocol="raw")


@pytest.mark.parametrize("family,resolver", [(4, "10.250.0.1"), (6, "fd42:250::1")])
def test_tunnel_loss_must_refuse_successful_dns(family, resolver):
    with (
        patch.object(application, "_execute", return_value=CompletedProcess([], 0, "", "")),
        pytest.raises(application.ApplicationConfinementError, match="unexpectedly succeeded"),
    ):
        application.verify_dns_unavailable("owned-ns", resolver, family=family)


@pytest.mark.parametrize("family,resolver", [(4, "10.250.0.1"), (6, "fd42:250::1")])
def test_tunnel_loss_accepts_dns_failure(family, resolver):
    with patch.object(application, "_execute", return_value=CompletedProcess([], 1, "", "timeout")):
        application.verify_dns_unavailable("owned-ns", resolver, family=family)


@pytest.mark.parametrize("socket_errno", [1, 13, 22, 101, 113])
def test_blocked_tcp_socket_errors_are_classified_by_listener_not_errno(socket_errno):
    """Linux may return different socket errors for a blocked TCP connect."""
    import subprocess
    import sys

    shim = f"""
import errno
import socket
class BlockedSocket:
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def settimeout(self, value): pass
    def connect(self, address): raise OSError({socket_errno}, 'blocked by policy')
socket.socket = lambda *args: BlockedSocket()
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", shim + application.UNDERLAY_CLIENT, "4", "tcp", "10.214.10.1", "53053"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "BLOCKED_SOCKET_ERROR:" in result.stderr
