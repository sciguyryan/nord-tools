"""Offline pipeline invariants using synthetic OpenVPN profiles and archives."""

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import nordvpn_benchmark as benchmark
from nordvpn_filter import compile_filter
from nordvpn_regions import load_region_lists


PROFILE = "client\nproto udp\nremote 192.0.2.10 53\n"


class EarlySelectionTests(unittest.TestCase):
    def test_boolean_country_predicates_match_full_evaluation(self):
        regions = load_region_lists()
        expressions = (
            "uk",
            "gb",
            "!(uk|us)",
            "!uk|!us",
            "(uk|nl)&!us",
            "list:low-ads|country:nl",
            "!(list:low-ads|gb)",
        )
        for expression in expressions:
            early = benchmark.country_prefilter([expression], regions)
            full = compile_filter(expression, regions)
            for prefix in ("uk", "gb", "us", "nl", "ad", "al", "zz"):
                filename = f"{prefix}123.nordvpn.com.udp_2.6.ovpn"
                endpoint = benchmark.Endpoint(filename, "192.0.2.10", 53, "udp", f"{prefix}123.nordvpn.com")
                with self.subTest(expression=expression, prefix=prefix):
                    self.assertEqual(early(filename), full(endpoint))

    def test_multiple_filters_are_conjoined(self):
        regions = load_region_lists()
        early = benchmark.country_prefilter(["uk|nl", "!nl"], regions)
        self.assertTrue(early("uk2.nordvpn.com.udp_2.6.ovpn"))
        self.assertFalse(early("nl2.nordvpn.com.udp_2.6.ovpn"))
        self.assertFalse(early("us2.nordvpn.com.udp_2.6.ovpn"))

    def test_mixed_fields_and_unknown_filenames_are_conservative(self):
        regions = load_region_lists()
        for expression in ("uk|port:443", "country:us&protocol:tcp", "host:*.nordvpn.com&nl"):
            with self.subTest(expression=expression):
                early = benchmark.country_prefilter([expression], regions)
                self.assertTrue(early("ad1.nordvpn.com.udp_2.6.ovpn"))
        self.assertTrue(benchmark.country_prefilter(["uk"], regions)("custom.ovpn"))

    def test_excluded_local_profile_is_not_parsed_or_probed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uk1.nordvpn.com.udp_2.6.ovpn").write_text(PROFILE)
            (root / "us1.nordvpn.com.udp_2.6.ovpn").write_text("malformed remote 123")
            measurement = benchmark.Measurement("192.0.2.10", 2, [10.0, 11.0])
            with (
                patch.object(benchmark.shutil, "which", return_value="/usr/bin/ping"),
                patch("nordvpn_connection.benchmark_preflight", return_value=True),
                patch.object(benchmark, "parse_profile", wraps=benchmark.parse_profile) as parse,
                patch.object(benchmark, "execute_stage", return_value={"192.0.2.10": measurement}) as stage,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(benchmark.main(["--config-dir", directory, "--filter=uk", "--quiet"]), 0)
            self.assertEqual(parse.call_count, 1)
            self.assertEqual(parse.call_args.args[0].name, "uk1.nordvpn.com.udp_2.6.ovpn")
            self.assertEqual(stage.call_count, 2)
            self.assertEqual(stage.call_args_list[0].args[0], ["192.0.2.10"])

    def test_archive_extraction_skips_excluded_and_respects_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                for country in ("uk", "us", "ad"):
                    for transport in ("udp", "tcp"):
                        archive.writestr(f"ovpn_{transport}/{country}1.nordvpn.com.{transport}_2.6.ovpn", PROFILE)
            with patch.object(benchmark, "urlopen", return_value=io.BytesIO(buffer.getvalue())):
                benchmark.extract_archive(
                    root,
                    lambda _message: None,
                    "udp",
                    benchmark.country_prefilter(["list:low-ads"], load_region_lists()),
                )
            names = [item.name for item in (root / "profiles").glob("*.ovpn")]
            self.assertEqual(len(names), 1)
            self.assertIn("ad1.nordvpn.com.udp", names[0])
            self.assertFalse((root / "nordvpn.zip").exists())


class ExportAndCatalogueTests(unittest.TestCase):
    def test_distinct_ranking_keeps_lossless_configurations(self):
        endpoints = [
            benchmark.Endpoint(f"uk1-{port}.ovpn", "192.0.2.10", port, "udp", "uk1.nordvpn.com") for port in (53, 1194)
        ]
        endpoints.append(benchmark.Endpoint("nl2.ovpn", "192.0.2.11", 53, "udp", "nl2.nordvpn.com"))
        measurements = {
            address: benchmark.Measurement(address, 3, [10, 11, 12]) for address in ("192.0.2.10", "192.0.2.11")
        }
        records = benchmark.records_for(endpoints, measurements)
        self.assertEqual(len(records), 3)
        self.assertEqual(len(benchmark.distinct_servers(records)), 2)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            benchmark.export(records, output, "json", True)
            self.assertEqual(len(json.loads(output.read_text())), 3)

    def test_custom_region_aliases_normalise_and_detect_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.json"
            path.write_text(json.dumps({"britain": {"description": "Test", "countries": ["uk"]}}))
            self.assertEqual(load_region_lists(path)["britain"]["countries"], ["gb"])
            path.write_text(json.dumps({"britain": {"description": "Test", "countries": ["uk", "gb"]}}))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_region_lists(path)


if __name__ == "__main__":
    unittest.main()
