"""Tests for the offline networking feasibility model."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nord_tools_internal.nordvpn_profiles import ProfileError
from nordvpn_topology import compile_topology


POLICY = {
    "version": 1,
    "defaults": {"vpn": "primary"},
    "vpn_profiles": {
        "primary": {"selection": {"mode": "country", "country": "AD"}},
        "discord": {"selection": {"mode": "country", "country": "GB"}},
        "private": {"selection": {"mode": "pinned", "server": "gb123.nordvpn.com"}, "sharing": "isolated"},
    },
    "applications": {
        "discord": {"executable": "/usr/bin/discord", "vpn": "discord"},
        "other": {"executable": "/usr/bin/other", "vpn": "discord"},
    },
}


class TopologyTests(unittest.TestCase):
    def test_host_default_and_override_namespaces(self):
        topology = compile_topology(POLICY)
        domains = {entry["profile"]: entry for entry in topology["domains"]}
        self.assertEqual(domains["primary"]["kind"], "host")
        self.assertEqual(domains["discord"]["kind"], "namespace")
        self.assertEqual(domains["discord"]["applications"], ["discord", "other"])
        self.assertEqual(domains["private"]["kind"], "namespace")
        self.assertEqual(topology["unlisted_applications"], {"profile": "primary", "kind": "host"})
        self.assertEqual(topology["default_optimisation_scope"], ["primary"])
        self.assertFalse(topology["runtime_enforcement"])

    def test_all_domains_require_fail_closed_networking(self):
        for domain in compile_topology(POLICY)["domains"]:
            self.assertTrue(all(domain["requirements"].values()))

    def test_profile_name_not_application_name_determines_sharing(self):
        changed = copy.deepcopy(POLICY)
        changed["applications"]["other"]["vpn"] = "private"
        domains = {entry["profile"]: entry for entry in compile_topology(changed)["domains"]}
        self.assertEqual(domains["discord"]["applications"], ["discord"])
        self.assertEqual(domains["private"]["applications"], ["other"])

    def test_invalid_assignment_fails_before_any_plan(self):
        changed = copy.deepcopy(POLICY)
        changed["applications"]["discord"]["vpn"] = "missing"
        with self.assertRaises(ProfileError):
            compile_topology(changed)

    def test_compilation_does_not_mutate_input(self):
        original = copy.deepcopy(POLICY)
        compile_topology(POLICY)
        self.assertEqual(POLICY, original)

    def test_cli_outputs_explicitly_non_executable_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(POLICY), encoding="utf-8")
            self._assert_cli_output(path)

    def _assert_cli_output(self, path):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(root / "nordvpn_topology.py"), "--policy", str(path)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "design_only")
        self.assertFalse(data["runtime_enforcement"])
