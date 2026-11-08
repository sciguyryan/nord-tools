"""Offline tests for the experimental disposable WireGuard session."""

import base64
import os
from unittest import TestCase
from unittest.mock import Mock, patch

from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification
from nord_tools_internal.nordvpn_wireguard_session import SessionError, configure_disposable_wireguard


class SessionTests(TestCase):
    def setUp(self):
        self.spec = TunnelSpecification(
            "nt-0123456789",
            "ntwg1234",
            base64.b64encode(bytes(range(32))).decode(),
            "198.51.100.2",
            51820,
            ("10.42.0.2/32", "2001:db8::2/128"),
            ("10.42.0.1/32",),
        )
        self.owned = OwnedNamespace(self.spec.namespace, 5, 1, 2)
        self.key = base64.b64encode(bytes(range(32)))

    def execute(self, key=None, spec=None):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, self.key if key is None else key)
        finally:
            os.close(write_fd)
        try:
            configure_disposable_wireguard(self.spec if spec is None else spec, self.owned, read_fd)
        finally:
            os.close(read_fd)

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_command_sequence_and_no_key_in_arguments(self, verify, run, index):
        self.execute()
        self.assertEqual(run.call_count, 5)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0][:5], ["ip", "-n", self.spec.namespace, "link", "add"])
        self.assertIn("private-key", commands[1])
        self.assertNotIn("private-key " + self.key.decode(), repr(commands))
        self.assertNotIn(self.key.decode(), repr(commands[0] + commands[2] + commands[3] + commands[4]))
        self.assertEqual([commands[2][5], commands[3][5]], list(self.spec.tunnel_addresses))
        self.assertEqual(commands[-1][-1], "up")
        self.assertGreaterEqual(verify.call_count, 4)

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_invalid_key_never_mutates(self, verify, run, index):
        with self.assertRaises(ValueError):
            self.execute(b"bad")
        run.assert_not_called()

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_mismatched_namespace_never_mutates(self, verify, run, index):
        self.owned.name = "nt-ffffffff"
        with self.assertRaises(SessionError):
            self.execute()
        run.assert_not_called()

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_failed_creation_does_not_attempt_further_commands(self, verify, run, index):
        run.side_effect = SessionError("failed")
        with self.assertRaises(SessionError):
            self.execute()
        run.assert_called_once()

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_failed_second_address_does_not_raise_interface(self, verify, run, index):
        run.side_effect = [None, None, None, SessionError("failed")]
        with self.assertRaises(SessionError):
            self.execute()
        self.assertEqual(run.call_count, 4)
        self.assertEqual(run.call_args.args[0][5], "2001:db8::2/128")

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_identity_change_halts_sequence(self, verify, run, index):
        verify.side_effect = [None, None, SessionError("identity changed")]
        with self.assertRaises(SessionError):
            self.execute()
        run.assert_called_once()

    @patch("nord_tools_internal.nordvpn_wireguard_session.subprocess.run")
    def test_command_errors_do_not_echo_subprocess_output(self, run):
        from nord_tools_internal.nordvpn_wireguard_session import _run

        run.return_value = Mock(returncode=1, stdout=b"private", stderr=b"secret")
        with self.assertRaisesRegex(SessionError, "command failed") as error:
            _run(["wg", "show"])
        self.assertNotIn("secret", str(error.exception))

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", side_effect=[12, 13])
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_replaced_interface_refuses_address_and_activation(self, verify, run, index):
        with self.assertRaisesRegex(SessionError, "identity changed"):
            self.execute()
        self.assertEqual(run.call_count, 2)

    @patch(
        "nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", side_effect=RuntimeError("missing")
    )
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_missing_new_interface_refuses_configuration(self, verify, run, index):
        with self.assertRaisesRegex(SessionError, "could not be verified"):
            self.execute()
        run.assert_called_once()

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=0)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_invalid_new_interface_index_refuses_configuration(self, verify, run, index):
        with self.assertRaisesRegex(SessionError, "invalid kernel index"):
            self.execute()
        run.assert_called_once()

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_keepalive_configuration_is_explicit(self, verify, run, index):
        from dataclasses import replace

        self.execute(spec=replace(self.spec, persistent_keepalive_seconds=25))
        configuration = run.call_args_list[1].args[0]
        self.assertEqual(configuration[-2:], ["persistent-keepalive", "25"])
        self.assertTrue(configuration[configuration.index("private-key") + 1].startswith("/proc/self/fd/"))

    @patch("nord_tools_internal.nordvpn_wireguard_session.namespace_interface_index", return_value=12)
    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_default_keepalive_does_not_modify_peer_setting(self, verify, run, index):
        self.execute()
        self.assertNotIn("persistent-keepalive", run.call_args_list[1].args[0])
