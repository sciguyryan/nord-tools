"""Absent resources are accounted for once at durable retirement, not at observation."""

from unittest.mock import Mock

from nord_tools_internal.nordvpn_cleanup_executor import _delete_host_interface, _delete_namespace


def test_already_absent_host_link_does_not_append_premature_report():
    helpers = Mock()
    helpers.observe.return_value = {"host_interfaces": [], "namespace_details": []}
    deletions = []
    _delete_host_interface("allocation", {"identifier": "host0", "profile": "p"}, {"ifindex": 12}, helpers, deletions)
    assert deletions == []
    helpers.delete_host_interface.assert_not_called()


def test_already_absent_namespace_does_not_append_premature_report():
    helpers = Mock()
    helpers.netns_identity.return_value = None
    deletions = []
    _delete_namespace("allocation", {"identifier": "nt-absent", "profile": "p"}, {}, helpers, False, deletions)
    assert deletions == []
    helpers.delete_namespace.assert_not_called()
