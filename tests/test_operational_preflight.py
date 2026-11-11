"""Dependency, platform and privilege checks precede production mutation."""

from __future__ import annotations

import contextlib
import io
import json
from unittest.mock import Mock, patch

import pytest

import nordvpn_manage
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup
from nord_tools_internal.nordvpn_host_executor import activate_host_protection, deactivate_host_protection
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_operational_preflight import (
    verify_execution_runtime,
    verify_operational_preflight,
)
from nord_tools_internal.nordvpn_recovery_executor import plan_recovery
from nord_tools_internal.nordvpn_registry import RegistryError
from test_host_executor import BOOT, FakeHost, PLAN


def platform_report():
    return {"mode": "supported_network_platform", "network_changes_applied": False}


def commands(_name):
    return "/usr/bin/tool"


def test_namespace_preflight_combines_runtime_privilege_and_platform_checks():
    inspect_platform = Mock(return_value=platform_report())

    runtime = verify_execution_runtime(
        "namespace",
        effective_uid=lambda: 0,
        python_version=(3, 13, 1),
        executable=commands,
    )
    assert runtime["dependencies"] == ["ip", "nft", "wg"]

    report = verify_operational_preflight(
        "namespace",
        effective_uid=lambda: 0,
        python_version=(3, 13, 1),
        executable=commands,
        platform_inspector=inspect_platform,
    )

    assert report["supported"] is True
    assert report["operational_mode"] == "namespace"
    assert report["network_changes_applied"] is False
    assert report["mutation_authorised"] is False
    inspect_platform.assert_called_once_with()


def test_runtime_preflight_refuses_missing_mode_dependency():
    with pytest.raises(RegistryError, match="resolvectl"):
        verify_execution_runtime(
            "host-default",
            effective_uid=lambda: 0,
            python_version=(3, 13),
            executable=lambda name: None if name == "resolvectl" else f"/usr/bin/{name}",
        )


@pytest.mark.parametrize(
    "mode,uid,version,match",
    [
        ("unknown", 0, (3, 13), "unsupported operational"),
        ("namespace", 1000, (3, 13), "requires Linux root"),
        ("namespace", 0, (3, 9), "Python 3.10"),
    ],
)
def test_unsupported_mode_runtime_or_privilege_refuses_before_platform_inspection(mode, uid, version, match):
    inspect_platform = Mock()
    with pytest.raises(RegistryError, match=match):
        verify_operational_preflight(
            mode,
            effective_uid=lambda: uid,
            python_version=version,
            executable=commands,
            platform_inspector=inspect_platform,
        )
    inspect_platform.assert_not_called()


def test_host_default_requires_plan_and_combines_both_read_only_inspections():
    host_plan = object()
    inspect_host = Mock(return_value={"mode": "host_platform_compatibility", "supported": True})
    report = verify_operational_preflight(
        "host-default",
        host_plan=host_plan,
        effective_uid=lambda: 0,
        python_version=(3, 13),
        executable=commands,
        platform_inspector=lambda: platform_report(),
        host_inspector=inspect_host,
    )
    assert report["host"]["supported"] is True
    assert report["host_inventory_checked"] is True
    inspect_host.assert_called_once_with(host_plan)


def test_host_executor_preflight_can_defer_inventory_to_locked_lifecycle_check():
    inspect_host = Mock()
    report = verify_operational_preflight(
        "host-default",
        host_plan=object(),
        effective_uid=lambda: 0,
        python_version=(3, 13),
        executable=commands,
        platform_inspector=lambda: platform_report(),
        host_inspector=inspect_host,
        include_host_inventory=False,
    )
    assert report["host"] is None
    assert report["host_inventory_checked"] is False
    inspect_host.assert_not_called()


def test_management_command_reports_preflight_without_authorising_mutation(tmp_path):
    plan = tmp_path / "host.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    report = {
        "mode": "operational_preflight",
        "operational_mode": "host-default",
        "network_changes_applied": False,
        "mutation_authorised": False,
    }
    output = io.StringIO()
    with (
        patch(
            "nord_tools_internal.nordvpn_operational_preflight.verify_operational_preflight",
            return_value=report,
        ) as inspect,
        contextlib.redirect_stdout(output),
    ):
        assert nordvpn_manage.main(["operational-preflight", "--mode", "host-default", "--host-plan", str(plan)]) == 0
    assert json.loads(output.getvalue())["mutation_authorised"] is False
    inspect.assert_called_once()


def test_host_activation_uses_full_admission_before_constructing_kernel():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch("nord_tools_internal.nordvpn_host_executor.verify_execution_runtime"),
        patch(
            "nord_tools_internal.nordvpn_host_executor.verify_operational_preflight",
            side_effect=RegistryError("unsupported host platform"),
        ) as preflight,
        patch("nord_tools_internal.nordvpn_host_executor._kernel") as kernel,
        pytest.raises(RegistryError, match="unsupported host platform"),
    ):
        activate_host_protection(plan, "missing-store", 3)
    preflight.assert_called_once_with("host-default", host_plan=plan, include_host_inventory=False)
    kernel.assert_not_called()


def test_host_activation_retry_inside_observed_barrier_skips_broad_platform_probe(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    store = tmp_path / "host-store.json"
    activate_host_protection(plan, store, 3, kernel=fake.kernel(), boot_id=BOOT)

    with (
        patch("nord_tools_internal.nordvpn_host_executor.verify_execution_runtime") as runtime,
        patch("nord_tools_internal.nordvpn_host_executor.verify_operational_preflight") as full_preflight,
        patch("nord_tools_internal.nordvpn_host_executor._kernel", return_value=fake.kernel()),
    ):
        result = activate_host_protection(plan, store, 3, boot_id=BOOT)

    assert result["state"] == "active_verified"
    runtime.assert_called_once_with("host-default")
    full_preflight.assert_not_called()


def test_host_retirement_uses_bounded_runtime_gate_before_constructing_kernel():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch(
            "nord_tools_internal.nordvpn_host_executor.verify_execution_runtime",
            side_effect=RegistryError("missing runtime dependency"),
        ) as runtime,
        patch("nord_tools_internal.nordvpn_host_executor.verify_operational_preflight") as full_preflight,
        patch("nord_tools_internal.nordvpn_host_executor._kernel") as kernel,
        pytest.raises(RegistryError, match="missing runtime dependency"),
    ):
        deactivate_host_protection(plan, "missing-store", expose_host_egress=True)
    runtime.assert_called_once_with("host-default")
    full_preflight.assert_not_called()
    kernel.assert_not_called()


@pytest.mark.parametrize(
    "target,invoke",
    [
        (
            "nord_tools_internal.nordvpn_cleanup_executor.verify_operational_preflight",
            lambda: plan_cleanup(
                "missing-journal",
                "missing-bindings",
                intent_path="missing-intents",
                desired_policy={"vpn_profiles": {}},
                execute=True,
            ),
        ),
        (
            "nord_tools_internal.nordvpn_recovery_executor.verify_operational_preflight",
            lambda: plan_recovery("missing-journal", "missing-bindings", "missing-intents", execute=True),
        ),
    ],
)
def test_real_cleanup_and_recovery_refuse_preflight_before_opening_state(target, invoke):
    with (
        patch(target, side_effect=RegistryError("unsupported execution environment")) as preflight,
        pytest.raises(RegistryError, match="unsupported execution environment"),
    ):
        invoke()
    preflight.assert_called_once_with("namespace")
