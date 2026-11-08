"""Static and negative-path contracts for production-profile acceptance."""

from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from tools import probe_production_wireguard_confinement as probe
from tools.probe_provisioning_integration import STAGES


def test_production_stage_is_last():
    assert STAGES[-1][1] == "probe_production_wireguard_confinement.py"
    assert STAGES[-1][2] == ("--run-privileged",)


def test_dry_run_does_not_mutate(capsys):
    assert probe.main([]) == 0
    assert "DRY RUN" in capsys.readouterr().out


def test_ipv6_packet_failure_is_not_accepted():
    def command(*args, **kwargs):
        if "ping" in args and "-6" in args:
            raise subprocess.CalledProcessError(1, args)
        if "peers" in args:
            return b"pinned-peer\n"
        return b"fd42:250::1 dev ntwg123\n" if "-6" in args else b"10.250.0.1 dev ntwg123\n"

    with (
        patch.object(probe, "command", side_effect=command),
        pytest.raises(probe.AcceptanceError, match="production -6 tunnel traffic"),
    ):
        probe.verify_tunnel("ntns123", "ntwg123", "pinned-peer")


def test_probe_is_packaged():
    assert (Path(probe.__file__).parent / "probe_production_wireguard_confinement.py").is_file()
