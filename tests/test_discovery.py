"""Deterministic and adversarial read-only discovery tests."""

import json
import subprocess
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_discovery import DiscoveryError, discover
from nordvpn_manage import main


class DiscoveryTests(unittest.TestCase):
    def runner(
        self,
        namespaces=None,
        links=None,
        *,
        code=0,
        routes=None,
        namespace_links=None,
        namespace_routes=None,
        ipv6_routes=None,
        namespace_ipv6_routes=None,
        nftables=None,
        namespace_nftables=None,
    ):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            if command[:3] == ["nft", "-j", "list"]:
                return subprocess.CompletedProcess(
                    command, code, json.dumps({"nftables": nftables if nftables is not None else []}), "failure"
                )
            if command[:3] == ["ip", "netns", "exec"]:
                return subprocess.CompletedProcess(
                    command,
                    code,
                    json.dumps({"nftables": namespace_nftables if namespace_nftables is not None else []}),
                    "failure",
                )
            if command[2:4] == ["netns", "list"]:
                value = namespaces
            elif command[2:4] == ["link", "show"]:
                value = links
            elif command[2:4] == ["-6", "route"]:
                value = ipv6_routes if ipv6_routes is not None else []
            elif command[2:4] == ["route", "show"]:
                value = routes if routes is not None else []
            elif command[2] == "-n" and command[4:6] == ["-6", "route"]:
                value = namespace_ipv6_routes if namespace_ipv6_routes is not None else []
            elif command[2] == "-n" and command[4:6] == ["link", "show"]:
                value = namespace_links if namespace_links is not None else []
            else:
                value = namespace_routes if namespace_routes is not None else []
            return subprocess.CompletedProcess(command, code, json.dumps(value), "failure")

        return run, calls

    def test_sorted_observations_and_no_mutations(self):
        run, calls = self.runner(
            [{"name": "z"}, {"name": "a"}], [{"ifname": "wg1", "ifindex": 9}, {"ifname": "lo", "ifindex": 1}]
        )
        result = discover(system=lambda: "Linux", runner=run)
        self.assertEqual(result["namespaces"], ["a", "z"])
        self.assertEqual([x["name"] for x in result["host_interfaces"]], ["lo", "wg1"])
        self.assertFalse(result["ownership_verified"])
        self.assertEqual(result["host_nftables"], [])
        self.assertFalse(result["safe_to_delete"])
        self.assertEqual([x["name"] for x in result["namespace_details"]], ["a", "z"])
        self.assertEqual(
            [c[0] for c in calls],
            [
                ["ip", "-j", "netns", "list"],
                ["ip", "-j", "link", "show"],
                ["ip", "-j", "route", "show", "table", "all"],
                ["ip", "-j", "-6", "route", "show", "table", "all"],
                ["nft", "-j", "list", "ruleset"],
                ["ip", "-j", "-n", "a", "link", "show"],
                ["ip", "-j", "-n", "a", "route", "show", "table", "all"],
                ["ip", "-j", "-n", "a", "-6", "route", "show", "table", "all"],
                ["ip", "netns", "exec", "a", "nft", "-j", "list", "ruleset"],
                ["ip", "-j", "-n", "z", "link", "show"],
                ["ip", "-j", "-n", "z", "route", "show", "table", "all"],
                ["ip", "-j", "-n", "z", "-6", "route", "show", "table", "all"],
                ["ip", "netns", "exec", "z", "nft", "-j", "list", "ruleset"],
            ],
        )
        self.assertTrue(all(c[1]["timeout"] == 10 for c in calls))

    def test_namespace_and_host_route_observations(self):
        run, _ = self.runner(
            [{"name": "vpn-a"}],
            [{"ifname": "lo", "ifindex": 1}],
            routes=[{"dst": "default", "gateway": "192.0.2.1"}],
            namespace_links=[{"ifname": "wg0", "ifindex": 3}],
            namespace_routes=[{"dst": "default", "dev": "wg0"}],
        )
        result = discover(system=lambda: "Linux", runner=run)
        self.assertEqual(result["host_routes"][0]["gateway"], "192.0.2.1")
        self.assertEqual(result["namespace_details"][0]["interfaces"][0]["name"], "wg0")
        self.assertEqual(result["namespace_details"][0]["routes"][0]["dev"], "wg0")
        self.assertFalse(result["ownership_verified"])

    def test_invalid_route_and_duplicate_indices_fail_closed(self):
        for options in (
            {"routes": [{"dev": "wg0"}]},
            {"namespace_routes": [{"dst": None}], "namespaces": [{"name": "x"}]},
            {"links": [{"ifname": "a", "ifindex": 1}, {"ifname": "b", "ifindex": 1}]},
        ):
            with self.subTest(options=options), self.assertRaises(DiscoveryError):
                discover(system=lambda: "Linux", runner=self.runner(**{"namespaces": [], "links": [], **options})[0])

    def test_ipv6_and_firewall_observations_are_not_ownership(self):
        run, _ = self.runner(
            namespaces=[{"name": "vpn-a"}],
            links=[],
            ipv6_routes=[{"dst": "default", "dev": "wg0"}],
            namespace_ipv6_routes=[{"dst": "2001:db8::/32", "dev": "wg1"}],
            nftables=[{"metainfo": {"version": "1"}}, {"table": {"family": "inet", "name": "filter"}}],
            namespace_nftables=[{"table": {"family": "inet", "name": "isolation"}}],
        )
        result = discover(system=lambda: "Linux", runner=run)
        self.assertEqual(result["host_ipv6_routes"][0]["dev"], "wg0")
        self.assertEqual(result["namespace_details"][0]["ipv6_routes"][0]["dst"], "2001:db8::/32")
        self.assertEqual(result["namespace_details"][0]["nftables"][0]["table"]["name"], "isolation")
        self.assertFalse(result["safe_to_delete"])

    def test_bad_firewall_payload_fails_closed(self):
        run, _ = self.runner([], [])

        def invalid(command, **kwargs):
            if command[:3] == ["nft", "-j", "list"]:
                return subprocess.CompletedProcess(command, 0, '{"nftables": {}}', "")
            return run(command, **kwargs)

        with self.assertRaisesRegex(DiscoveryError, "unexpected JSON structure"):
            discover(system=lambda: "Linux", runner=invalid)

    def test_rejects_non_linux_without_invoking_ip(self):
        run, calls = self.runner([], [])
        with self.assertRaisesRegex(DiscoveryError, "Linux only"):
            discover(system=lambda: "Windows", runner=run)
        self.assertEqual(calls, [])

    def test_rejects_bad_or_duplicate_observations(self):
        cases = [
            ([{"name": "x"}, {"name": "x"}], []),
            ([{}], []),
            ([], [{"ifname": "lo", "ifindex": True}]),
            ([], [{"ifname": "lo", "ifindex": 1}, {"ifname": "lo", "ifindex": 2}]),
        ]
        for ns, links in cases:
            with self.subTest(ns=ns, links=links), self.assertRaises(DiscoveryError):
                discover(system=lambda: "Linux", runner=self.runner(ns, links)[0])

    def test_fails_closed_on_missing_binary_and_command_failure(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError("ip")

        with self.assertRaises(DiscoveryError):
            discover(system=lambda: "Linux", runner=missing)
        with self.assertRaises(DiscoveryError):
            discover(system=lambda: "Linux", runner=self.runner([], [], code=1)[0])

    def test_command_dispatch_does_not_require_saved_policy(self):
        with (
            patch("nordvpn_manage.discover", return_value={"mode": "live_read_only"}) as discovery,
            patch("builtins.print") as printer,
        ):
            self.assertEqual(main(["discover"]), 0)
        discovery.assert_called_once_with()
        self.assertIn("live_read_only", printer.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
