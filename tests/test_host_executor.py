"""Host-default plan, transaction and lifecycle regression coverage."""

from __future__ import annotations

import copy
import json

import pytest

from nord_tools_internal.nordvpn_host_executor import (
    HostKernel,
    HostProtectionError,
    activate_host_protection,
    deactivate_host_protection,
    prepare_host_boot_barrier,
    preview_host_protection,
    recover_host_protection,
)
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_host_store import read_host_store
from nord_tools_internal.nordvpn_registry import RegistryError
import nordvpn_manage


PLAN = {
    "generation": "default-1",
    "interface": "ntwg-host",
    "peer_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "endpoint_address": "198.51.100.2",
    "endpoint_port": 51820,
    "tunnel_addresses": ["10.7.0.2/32", "2001:db8:1::2/128"],
    "dns_servers": ["10.7.0.1", "2001:db8:1::1"],
    "egress_interface": "eth0",
    "egress_ifindex": 2,
    "egress_source_address": "198.51.100.10",
    "route_table": 51820,
    "endpoint_rule_priority": 100,
    "tunnel_rule_priority": 110,
    "fwmark": 51820,
    "resolver_mode": "systemd-resolved",
    "firewall_family": "inet",
    "firewall_table": "nord_tools_host",
    "firewall_priority": -200,
    "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
    "version": 1,
}
BOOT = "12345678-1234-1234-1234-123456789abc"
NEXT_BOOT = "22345678-1234-1234-1234-123456789abc"


class FakeHost:
    def __init__(self, *, handshake: bool = True, fail: str | None = None):
        self.present: set[str] = set()
        self.calls: list[str] = []
        self.handshake = handshake
        self.fail = fail
        self.conflicts: list[str] = []

    def inventory(self) -> dict:
        return {
            "boot_id": BOOT,
            "links": [{"name": "eth0", "index": 2, "kind": "ether"}],
            "resolver_manager": "systemd-resolved",
            "conflicts": self.conflicts,
            "owned_resources": [{"kind": name, "state": "present"} for name in sorted(self.present)],
        }

    def install(self, name: str) -> dict:
        self.calls.append(name)
        if self.fail == name:
            raise HostProtectionError(f"injected {name} failure")
        self.present.add(name)
        return {"identity": name}

    def remove(self, name: str) -> dict:
        self.calls.append(f"remove_{name}")
        if self.fail == f"remove_{name}":
            raise HostProtectionError(f"injected {name} retirement failure")
        self.present.remove(name)
        return {"removed": name}

    def state(self, name: str, evidence: dict, plan: HostProtectionPlan) -> str:
        return "present" if name in self.present else "absent"

    def kernel(self) -> HostKernel:
        return HostKernel(
            inventory=self.inventory,
            install_barrier=lambda plan: self.install("barrier"),
            install_endpoint=lambda plan: self.install("endpoint"),
            install_wireguard=lambda plan, fd: self.install("wireguard"),
            install_routes=lambda plan: self.install("routes"),
            install_resolver=lambda plan: self.install("resolver"),
            verify_ready=lambda plan: {
                "barrier": "barrier" in self.present,
                "wireguard": "wireguard" in self.present,
                "routes": "routes" in self.present,
                "resolver": "resolver" in self.present,
                "handshake": self.handshake,
            },
            resource_state=self.state,
            observe_resource=lambda name, plan: (
                ("present", {"identity": name}) if name in self.present else ("absent", None)
            ),
            remove_resolver=lambda plan, evidence: self.remove("resolver"),
            remove_routes=lambda plan, evidence: self.remove("routes"),
            remove_wireguard=lambda plan, evidence: self.remove("wireguard"),
            remove_endpoint=lambda plan, evidence: self.remove("endpoint"),
            remove_barrier=lambda plan, evidence: self.remove("barrier"),
        )


def test_executable_plan_is_closed_dual_stack_and_dry_run_only():
    plan = HostProtectionPlan.from_mapping(PLAN)
    preview = preview_host_protection(plan)
    assert preview["steps"][0] == "barrier"
    assert preview["network_changes_applied"] is False
    assert preview["mutation_authorised"] is False
    assert len(plan.fingerprint()) == 64


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tunnel_addresses", ["10.7.0.2/32"]),
        ("tunnel_addresses", ["10.7.0.2/32", "10.8.0.2/32"]),
        ("dns_servers", ["10.7.0.1"]),
        ("egress_ifindex", True),
        ("resolver_mode", "resolv.conf"),
        ("firewall_table", "foreign"),
        ("endpoint_rule_priority", 120),
        ("endpoint_address", "2001:db8::2"),
    ],
)
def test_executable_plan_rejects_incomplete_or_ambiguous_input(field, value):
    document = copy.deepcopy(PLAN)
    document[field] = value
    with pytest.raises(RegistryError):
        HostProtectionPlan.from_mapping(document)


def test_executable_plan_rejects_unknown_fields():
    document = copy.deepcopy(PLAN)
    document["fallback"] = "direct"
    with pytest.raises(RegistryError):
        HostProtectionPlan.from_mapping(document)


def test_management_host_plan_is_mutation_free(tmp_path, capsys):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(PLAN), encoding="utf-8")
    store = tmp_path / "host.json"
    assert nordvpn_manage.main(["host-plan", "--host-plan", str(plan_path), "--host-store", str(store)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "host_default_dry_run"
    assert result["network_changes_applied"] is False
    assert not store.exists()


def test_activation_records_each_observation_after_barrier(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    status = activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    assert fake.calls == ["barrier", "endpoint", "wireguard", "routes", "resolver"]
    assert status["state"] == "active_verified"
    assert status["ordinary_host_egress_blocked"] is True
    record = read_host_store(tmp_path / "host.json")["record"]
    assert record["outcome"] == "active"
    assert [step["state"] for step in record["steps"]] == ["observed"] * 5


def test_early_boot_barrier_precedes_network_activation(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    report = prepare_host_boot_barrier(plan, tmp_path / "host.json", kernel=fake.kernel(), boot_id=BOOT)
    assert report["ordinary_host_egress_blocked"] is True
    assert fake.calls == ["barrier"]
    status = activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    assert status["state"] == "active_verified"
    assert fake.calls == ["barrier", "endpoint", "wireguard", "routes", "resolver"]


def test_new_boot_archives_absent_resources_before_new_barrier(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    fake.present.clear()  # Kernel networking objects do not survive this simulated reboot.
    prepare_host_boot_barrier(plan, tmp_path / "host.json", kernel=fake.kernel(), boot_id=NEXT_BOOT)
    store = read_host_store(tmp_path / "host.json")
    assert store["record"]["boot_id"] == NEXT_BOOT
    assert [item["boot_id"] for item in store["history"]] == [BOOT]
    assert fake.calls.count("barrier") == 2


def test_new_boot_refuses_a_resource_that_did_survive(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    with pytest.raises(HostProtectionError):
        prepare_host_boot_barrier(plan, tmp_path / "host.json", kernel=fake.kernel(), boot_id=NEXT_BOOT)
    assert fake.calls.count("barrier") == 1


def test_unavailable_tunnel_keeps_verified_barrier(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost(handshake=False)
    status = activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    assert status["state"] == "protected_tunnel_unavailable"
    assert status["ordinary_host_egress_blocked"] is True


def test_failure_after_barrier_is_durable_and_does_not_continue(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost(fail="wireguard")
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    assert fake.calls == ["barrier", "endpoint", "wireguard"]
    record = read_host_store(tmp_path / "host.json")["record"]
    assert record["ordinary_egress_blocked"] is True
    assert record["outcome"] == "uncertain"
    assert record["steps"][-1]["state"] == "uncertain"


@pytest.mark.parametrize("failed", ["barrier", "endpoint", "wireguard", "routes", "resolver"])
def test_each_activation_boundary_stops_before_later_mutation(tmp_path, failed):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost(fail=failed)
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    assert fake.calls[-1] == failed
    assert (
        fake.calls == list(("barrier", "endpoint", "wireguard", "routes", "resolver"))[: fake.calls.index(failed) + 1]
    )
    record = read_host_store(tmp_path / "host.json")["record"]
    assert record["outcome"] == "uncertain"
    assert record["ordinary_egress_blocked"] is (failed != "barrier")


def test_conflicting_inventory_refuses_before_durable_or_kernel_mutation(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    fake.conflicts = ["NetworkManager"]
    store = tmp_path / "host.json"
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, store, 7, kernel=fake.kernel(), boot_id=BOOT)
    assert fake.calls == []
    assert not store.exists()


def test_deactivation_requires_exposure_authority_and_retires_barrier_last(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    with pytest.raises(HostProtectionError):
        deactivate_host_protection(plan, tmp_path / "host.json", expose_host_egress=False, kernel=fake.kernel())
    status = deactivate_host_protection(plan, tmp_path / "host.json", expose_host_egress=True, kernel=fake.kernel())
    assert fake.calls[-5:] == [
        "remove_resolver",
        "remove_routes",
        "remove_wireguard",
        "remove_endpoint",
        "remove_barrier",
    ]
    assert status["state"] == "absent"
    assert status["ordinary_host_egress_blocked"] is False


@pytest.mark.parametrize(
    "failed",
    ["remove_resolver", "remove_routes", "remove_wireguard", "remove_endpoint", "remove_barrier"],
)
def test_each_retirement_failure_preserves_barrier_and_stops(tmp_path, failed):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    fake.fail = failed
    with pytest.raises(HostProtectionError):
        deactivate_host_protection(plan, tmp_path / "host.json", expose_host_egress=True, kernel=fake.kernel())
    assert fake.calls[-1] == failed
    assert "barrier" in fake.present
    record = read_host_store(tmp_path / "host.json")["record"]
    assert record["outcome"] == "uncertain"
    assert record["ordinary_egress_blocked"] is True


def test_recovery_is_read_only_by_default_and_never_removes_barrier(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost(fail="wireguard")
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    calls = list(fake.calls)
    report = recover_host_protection(plan, tmp_path / "host.json", kernel=fake.kernel())
    assert fake.calls == calls
    assert report["automatic_barrier_removal"] is False
    assert report["ordinary_host_egress_blocked"] is True


def test_recovery_certifies_absence_before_retry(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost(fail="wireguard")
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    fake.fail = None
    recovered = recover_host_protection(plan, tmp_path / "host.json", kernel=fake.kernel(), execute=True)
    assert recovered["ordinary_host_egress_blocked"] is True
    status = activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    assert status["state"] == "active_verified"
    assert fake.calls.count("barrier") == 1


def test_recovery_certifies_present_resource_before_retirement_retry(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    activate_host_protection(plan, tmp_path / "host.json", 7, kernel=fake.kernel(), boot_id=BOOT)
    fake.fail = "remove_routes"
    with pytest.raises(HostProtectionError):
        deactivate_host_protection(plan, tmp_path / "host.json", expose_host_egress=True, kernel=fake.kernel())
    fake.fail = None
    recovered = recover_host_protection(plan, tmp_path / "host.json", kernel=fake.kernel(), execute=True)
    assert recovered["ordinary_host_egress_blocked"] is True
    status = deactivate_host_protection(plan, tmp_path / "host.json", expose_host_egress=True, kernel=fake.kernel())
    assert status["state"] == "absent"
    assert fake.calls.count("remove_resolver") == 1
    assert fake.calls.count("remove_routes") == 2
