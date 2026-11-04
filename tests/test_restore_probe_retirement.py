"""Retirement acceptance must verify absence through a successful host inventory."""

from unittest import mock

import pytest

from tools.probe_restore_startup import ProbeError, verify_retired_resources


def test_retired_veth_is_verified_without_deleting_host_link():
    def inventory(*args):
        if args == ("ip", "netns", "list"):
            return b"other-namespace\n"
        assert args == ("ip", "-j", "link", "show")
        return b'[ {"ifname": "lo"}, {"ifname": "nordlynx"} ]'

    with (
        mock.patch("tools.probe_restore_startup.command", side_effect=inventory) as run,
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
    ):
        verify_retired_resources("nt-example", "veth-test")
    assert run.call_count == 2


def test_existing_host_link_is_not_deleted():
    with (
        mock.patch("tools.probe_restore_startup.command", side_effect=[b"", b'[{"ifname":"veth-test"}]']),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.time.monotonic", side_effect=[0, 3]),
        pytest.raises(ProbeError, match="remains"),
    ):
        verify_retired_resources("nt-example", "veth-test")


def test_unrelated_namespaces_do_not_block_retirement():
    with (
        mock.patch("tools.probe_restore_startup.command", side_effect=[b"other-namespace (id: 1)\n", b"[]"]),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
    ):
        verify_retired_resources("nt-example", "veth-test")


def test_target_namespace_still_present_is_rejected():
    with (
        mock.patch("tools.probe_restore_startup.command", return_value=b"nt-example (id: 1)\n"),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        pytest.raises(ProbeError, match="namespace remains"),
    ):
        verify_retired_resources("nt-example", "veth-test")


@pytest.mark.parametrize("payload", [b"not json", b"{}", b"[{}]", b'[{"ifname":7}]'])
def test_invalid_host_inventory_is_not_treated_as_absence(payload):
    with (
        mock.patch("tools.probe_restore_startup.command", side_effect=[b"", payload]),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        pytest.raises(ProbeError, match="absence could not be established"),
    ):
        verify_retired_resources("nt-example", "veth-test")


def test_failed_host_inventory_is_not_treated_as_absence():
    with (
        mock.patch("tools.probe_restore_startup.command", side_effect=[b"", ProbeError("ip failed")]),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        pytest.raises(ProbeError, match="absence could not be established"),
    ):
        verify_retired_resources("nt-example", "veth-test")


def test_transient_host_peer_disappears_after_namespace_retirement():
    with (
        mock.patch(
            "tools.probe_restore_startup.command",
            side_effect=[
                b"",
                b'[ {"ifname":"veth-test", "ifindex":28} ]',
                b"[]",
            ],
        ) as run,
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.time.sleep") as sleep,
    ):
        verify_retired_resources("nt-example", "veth-test", 28)
    assert run.call_count == 3
    sleep.assert_called_once_with(0.1)


def test_reused_host_name_is_rejected_without_retry_or_deletion():
    with (
        mock.patch(
            "tools.probe_restore_startup.command",
            side_effect=[
                b"",
                b'[ {"ifname":"veth-test", "ifindex":99} ]',
            ],
        ) as run,
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.time.sleep") as sleep,
        pytest.raises(ProbeError, match="identity changed"),
    ):
        verify_retired_resources("nt-example", "veth-test", 28)
    assert run.call_count == 2
    sleep.assert_not_called()


def test_invalid_inventory_during_retirement_wait_fails_closed():
    with (
        mock.patch(
            "tools.probe_restore_startup.command",
            side_effect=[
                b"",
                b'[ {"ifname":"veth-test", "ifindex":28} ]',
                b"not json",
            ],
        ),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.time.sleep"),
        pytest.raises(ProbeError, match="absence could not be established"),
    ):
        verify_retired_resources("nt-example", "veth-test", 28)
