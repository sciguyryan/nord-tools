"""Direct mode is explicit host routing, never a VPN fallback or allocation."""

from unittest.mock import MagicMock, patch

import pytest

from nord_tools_internal.nordvpn_application_executor import (
    launch_direct_application,
    launch_provisioned_application,
)
from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError
from nord_tools_internal.nordvpn_management_views import topology_graph
from nord_tools_internal.nordvpn_profiles import ProfileError, validate_policy
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups
from nord_tools_internal.nordvpn_sharing_lifecycle import plan_consumer_release

POLICY = {
    "version": 1,
    "defaults": {"vpn": "primary"},
    "vpn_profiles": {"primary": {"selection": {"mode": "country", "country": "GB"}}},
    "applications": {
        "ordinary": {"executable": "/usr/bin/true"},
        "bypass": {"executable": "/usr/bin/true", "vpn": "direct"},
    },
}


def test_explicit_direct_and_default_are_distinct():
    direct = plan_application(POLICY, "bypass", ("--example",))
    default = plan_application(POLICY, "ordinary")
    assert (direct.profile, direct.sharing, direct.inherited) == ("direct", "direct", False)
    assert direct.allocation_key != default.allocation_key
    assert default.profile == "primary" and default.inherited
    assert validate_policy(POLICY)["applications"]["bypass"]["vpn"] == "direct"
    assert "host network policy" in topology_graph(POLICY)
    assert "bypass" in topology_graph(POLICY)


def test_direct_is_not_a_vpn_resource_consumer():
    groups = resolve_ownership_groups(POLICY)
    assert len(groups) == 1
    assert groups[0].consumers == ("ordinary",)
    with pytest.raises(ProfileError, match="no VPN consumer references"):
        plan_consumer_release(POLICY, ("bypass",))


def test_reserved_profile_name_and_unknown_routing_rejected():
    invalid = {**POLICY, "vpn_profiles": {**POLICY["vpn_profiles"], "direct": POLICY["vpn_profiles"]["primary"]}}
    with pytest.raises(ProfileError, match="reserved"):
        validate_policy(invalid)
    invalid = {**POLICY, "applications": {"bypass": {"executable": "/bin/true", "vpn": "unknown"}}}
    with pytest.raises(ProfileError, match="unknown VPN"):
        validate_policy(invalid)
    invalid = {**POLICY, "defaults": {"vpn": "direct"}}
    with pytest.raises(ProfileError, match="existing profile"):
        validate_policy(invalid)


def test_direct_requires_explicit_root_and_nonroot_target():
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=1000),
        pytest.raises(ConsumerReferenceError, match="requires root"),
    ):
        launch_direct_application(POLICY, "bypass", (), uid=1000, gid=1000)
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        pytest.raises(ConsumerReferenceError, match="requires root"),
    ):
        launch_direct_application(POLICY, "bypass", (), uid=0, gid=1000)


def test_direct_launcher_does_not_use_namespace_or_shell():
    process = MagicMock()
    process.__enter__.return_value = process
    process.wait.return_value = 23
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        patch("nord_tools_internal.nordvpn_desktop_environment.pwd.getpwuid") as account,
        patch("nord_tools_internal.nordvpn_application_executor.subprocess.Popen", return_value=process) as popen,
    ):
        account.return_value.pw_dir = "/home/example"
        account.return_value.pw_name = "example"
        assert launch_direct_application(POLICY, "bypass", ("--example",), uid=1000, gid=1000) == 23
    args, kwargs = popen.call_args
    assert args[0] == ["/usr/bin/true", "--example"]
    assert kwargs["shell"] is False
    assert kwargs["user"] == 1000 and kwargs["group"] == 1000
    assert kwargs["extra_groups"] == []
    assert kwargs["env"]["HOME"] == "/home/example"
    assert "LD_PRELOAD" not in kwargs["env"]


def test_vpn_launcher_refuses_direct_even_if_called_directly():
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        pytest.raises(ConsumerReferenceError, match="cannot use VPN namespace leases"),
    ):
        launch_provisioned_application(
            POLICY,
            "bypass",
            (),
            runtime_consumers="x",
            journal_path="x",
            bindings_path="x",
            intent_path="x",
            observe=lambda: {},
            uid=1000,
            gid=1000,
        )
