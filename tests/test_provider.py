"""Secure provider import, rotation and deterministic selection boundaries."""

import base64
import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nordvpn_manage
from nord_tools_internal.nordvpn_provider import (
    ProviderError,
    import_provider_configuration,
    parse_nordvpn_wireguard,
    read_provider_configuration,
    select_provider_servers,
)
from nord_tools_internal.nordvpn_startup import render_startup_unit, validate_startup_config


PRIVATE = base64.b64encode(bytes(range(32))).decode("ascii")
PEER = base64.b64encode(bytes(range(32, 64))).decode("ascii")
CLIENT = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")


def wireguard(private=PRIVATE, *, extra="") -> bytes:
    return (
        "[Interface]\n"
        f"PrivateKey = {private}\n"
        "Address = 10.5.0.2/32, fd00::2/128\n"
        "DNS = 10.5.0.1, fd00::1\n"
        f"{extra}"
        "[Peer]\n"
        f"PublicKey = {PEER}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = vpn.example:51820\n"
    ).encode()


def resolver(host, port, *, type):
    assert (host, port, type) == ("vpn.example", 51820, __import__("socket").SOCK_DGRAM)
    return [(2, 2, 17, "", ("203.0.113.8", port)), (2, 2, 17, "", ("203.0.113.7", port))]


def runner(arguments, **kwargs):
    assert arguments == ["wg", "pubkey"]
    assert kwargs["input"] == PRIVATE.encode() + b"\n"
    return subprocess.CompletedProcess(arguments, 0, CLIENT.encode() + b"\n", b"")


def policy(selection):
    return {
        "version": 1,
        "defaults": {"vpn": "primary"},
        "vpn_profiles": {"primary": {"selection": selection}},
        "applications": {},
    }


class ProviderImportTests(unittest.TestCase):
    def test_management_command_is_persistent_and_secret_free(self):
        report = {"executed": False, "secret_material_reported": False}
        output = io.StringIO()
        arguments = [
            "provider-import",
            "--configuration",
            "/secure/provider.conf",
            "--server",
            "gb123.nordvpn.com",
            "--catalogue",
            "/secure/catalogue.json",
            "--credential",
            "/secure/gb123.key",
        ]
        with (
            patch.object(nordvpn_manage, "read_provider_configuration", return_value=b"private input") as read,
            patch.object(nordvpn_manage, "import_provider_configuration", return_value=report) as imported,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(nordvpn_manage.main(arguments), 0)
        read.assert_called_once_with("/secure/provider.conf")
        self.assertEqual(imported.call_args.kwargs["server"], "gb123.nordvpn.com")
        self.assertEqual(json.loads(output.getvalue())["scope"], "persistent")

    def test_parser_sanitises_and_resolves_deterministically(self):
        entry, secret = parse_nordvpn_wireguard(wireguard(), "gb123.nordvpn.com", resolver=resolver)
        self.assertEqual(entry["endpoint_address"], "203.0.113.7")
        self.assertNotIn("private", json.dumps(entry).lower())
        self.assertEqual(bytes(secret), PRIVATE.encode())

    def test_parser_refuses_active_or_ambiguous_configuration(self):
        for payload in (
            wireguard(extra="PostUp = arbitrary command\n"),
            wireguard().replace(b"AllowedIPs = 0.0.0.0/0, ::/0", b"AllowedIPs = 0.0.0.0/0"),
            wireguard().replace(b"PublicKey = ", b"PublicKey = invalid\n# "),
        ):
            with self.subTest(payload=payload), self.assertRaises(ProviderError):
                parse_nordvpn_wireguard(payload, "gb123.nordvpn.com", resolver=resolver)

    def test_import_and_explicit_rotation_never_report_secret_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalogue = root / "catalogue.json"
            credential = root / "gb123.key"
            preview = import_provider_configuration(
                wireguard(),
                server="gb123.nordvpn.com",
                catalogue_path=catalogue,
                credential_path=credential,
                resolver=resolver,
                runner=runner,
            )
            self.assertFalse(catalogue.exists())
            self.assertNotIn(PRIVATE, json.dumps(preview))
            result = import_provider_configuration(
                wireguard(),
                server="gb123.nordvpn.com",
                catalogue_path=catalogue,
                credential_path=credential,
                resolver=resolver,
                runner=runner,
                execute=True,
            )
            self.assertFalse(result["secret_material_reported"])
            self.assertEqual(os.stat(credential).st_mode & 0o777, 0o600)
            self.assertNotIn(PRIVATE, catalogue.read_text())
            with self.assertRaises(ProviderError):
                import_provider_configuration(
                    wireguard(),
                    server="gb123.nordvpn.com",
                    catalogue_path=catalogue,
                    credential_path=credential,
                    resolver=resolver,
                    runner=runner,
                    execute=True,
                )
            rotated = import_provider_configuration(
                wireguard(),
                server="gb123.nordvpn.com",
                catalogue_path=catalogue,
                credential_path=credential,
                resolver=resolver,
                runner=runner,
                rotate=True,
                execute=True,
            )
            self.assertTrue(rotated["rotated"])

    def test_source_must_be_private_and_caller_owned(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "provider.conf"
            source.write_bytes(wireguard())
            source.chmod(0o600)
            self.assertEqual(read_provider_configuration(source), wireguard())
            source.chmod(0o644)
            with self.assertRaises(ProviderError):
                read_provider_configuration(source)


class ProviderSelectionTests(unittest.TestCase):
    def catalogue(self):
        servers = []
        for server, endpoint in (("gb123.nordvpn.com", "203.0.113.7"), ("gb124.nordvpn.com", "203.0.113.8")):
            entry, secret = parse_nordvpn_wireguard(wireguard(), server, resolver=resolver)
            secret[:] = b"\x00" * len(secret)
            entry.update(client_public_key=CLIENT, credential=f"/secure/{server}.key")
            entry["endpoint_address"] = endpoint
            servers.append(entry)
        return {"version": 1, "provider": "nordvpn", "servers": servers}

    def test_pinned_country_and_fastest_selection(self):
        catalogue = self.catalogue()
        self.assertEqual(
            select_provider_servers(
                policy({"mode": "pinned", "server": "gb124"}), catalogue, None, max_report_age_seconds=60
            )["primary"]["server"],
            "gb124.nordvpn.com",
        )
        self.assertEqual(
            select_provider_servers(
                policy({"mode": "country", "country": "GB"}), catalogue, None, max_report_age_seconds=60
            )["primary"]["server"],
            "gb123.nordvpn.com",
        )
        now = datetime.datetime(2026, 11, 11, tzinfo=datetime.timezone.utc)
        report = {
            "schema_version": 1,
            "finished_at": now.isoformat(),
            "ranking": [
                {
                    "server": "gb124.nordvpn.com",
                    "protocol": "udp",
                    "port": 51820,
                    "received": 3,
                    "loss_pct": 0,
                    "median_ms": 4,
                },
                {
                    "server": "gb123.nordvpn.com",
                    "protocol": "udp",
                    "port": 51820,
                    "received": 3,
                    "loss_pct": 0,
                    "median_ms": 8,
                },
            ],
        }
        selected = select_provider_servers(
            policy({"mode": "fastest", "filter": "country:gb&protocol:udp"}),
            catalogue,
            report,
            max_report_age_seconds=60,
            now=now,
        )
        self.assertEqual(selected["primary"]["server"], "gb124.nordvpn.com")
        with self.assertRaises(ProviderError):
            select_provider_servers(
                policy({"mode": "fastest", "filter": "country:gb"}),
                catalogue,
                report,
                max_report_age_seconds=0,
                now=now + datetime.timedelta(seconds=1),
            )


class ProviderStartupTests(unittest.TestCase):
    def test_unit_loads_imported_key_through_systemd_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalogue_path = root / "catalogue.json"
            catalogue_path.write_text(json.dumps(ProviderSelectionTests().catalogue()))
            catalogue_path.chmod(0o600)
            config = {
                "version": 1,
                "policy": str(root / "policy.json"),
                "journal": str(root / "journal.json"),
                "bindings": str(root / "bindings.json"),
                "run_record": str(root / "runs.json"),
                "tunnels": {
                    "primary": {"underlay": {"namespace_address": "192.0.2.2/30", "host_address": "192.0.2.1/30"}}
                },
                "provider": {"catalogue": str(catalogue_path), "max_report_age_seconds": 60},
            }
            checked = validate_startup_config(config)
            unit = render_startup_unit(checked, str(root / "startup.json"), script_path="/opt/nordvpn_manage.py")
            self.assertIn("LoadCredential=ntprovider-gb123:", unit)
            self.assertNotIn(PRIVATE, unit)


if __name__ == "__main__":
    unittest.main()
