import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordvpn_benchmark as b


class BenchmarkTests(unittest.TestCase):
    def test_archive_transport_filtering(self):
        import zipfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "nordvpn.zip", "w") as z:
                z.writestr("ovpn_udp/ae72.nordvpn.com.udp_2.6.ovpn", "proto udp\nremote 127.0.0.1 53\n")
                z.writestr("ovpn_tcp/ae72.nordvpn.com.tcp_2.6.ovpn", "proto tcp\nremote 127.0.0.1 443\n")
            from unittest.mock import patch
            import io

            with patch.object(b, "urlopen", return_value=io.BytesIO((root / "nordvpn.zip").read_bytes())):
                b.extract_archive(root, lambda message: None, "udp")
            profiles = list((root / "profiles").glob("*.ovpn"))
            self.assertEqual(len(profiles), 1)
            self.assertEqual(b.parse_profile(profiles[0])[0].protocol, "udp")

    def test_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ae72.nordvpn.com.udp_2.6.ovpn"
            path.write_text("client\nproto udp\nremote 146.70.238.179 53\n<ca>\nremote fake 22\n</ca>\n")
            result = b.parse_profile(path)
            self.assertEqual((result[0].host, result[0].port, result[0].protocol), ("146.70.238.179", 53, "udp"))

    def test_measurement(self):
        result = b.Measurement("127.0.0.1", 5, [10.0, 11.0, 50.0, 12.0])
        self.assertEqual(result.median, 11.5)
        self.assertEqual(result.jitter, 1.0)
        self.assertEqual(result.loss, 20.0)

    def test_ping_parsing(self):
        with patch.object(b.subprocess, "run") as run:
            run.return_value.stdout = "64 bytes from host: time=1.24 ms\n64 bytes from host: time=2.51 ms"
            result = b.ping("127.0.0.1", 3, 1)
            self.assertEqual(result.samples, [1.24, 2.51])
            self.assertAlmostEqual(result.loss, 100 / 3)

    def test_render(self):
        self.assertIn("┌", b.render_table(["a"], [["b"]]))
        self.assertIn("+", b.render_table(["a"], [["b"]], True))

    def test_mean_and_coloured_table(self):
        measurement = b.Measurement("127.0.0.1", 3, [10.0, 20.0, 30.0])
        self.assertEqual(measurement.mean, 20.0)
        record = b.records_for([b.Endpoint("a.ovpn", "127.0.0.1", 53, "udp", "a.ovpn")], {"127.0.0.1": measurement})[0]
        self.assertEqual(record["mean_ms"], 20.0)
        plain = b.format_results([record], 1, False)
        coloured = b.format_results([record], 1, False, colour=True)
        accessible = b.format_results([record], 1, False, colour=True, colourblind=True)
        self.assertIn("20.00 ms", plain)
        self.assertNotIn("\x1b[", plain)
        self.assertIn("\x1b[38;2;", coloured)
        self.assertNotEqual(coloured, accessible)
        self.assertEqual(b.ANSI_ESCAPE.sub("", coloured), plain)
        self.assertEqual(b.ANSI_ESCAPE.sub("", accessible), plain)
        self.assertEqual(
            [len(line) for line in plain.splitlines()],
            [len(line) for line in b.ANSI_ESCAPE.sub("", coloured).splitlines()],
        )

    def test_palette_boundaries(self):
        self.assertEqual(b.latency_rgb(0), b.latency_rgb(-5))
        self.assertEqual(b.latency_rgb(250), b.latency_rgb(999))
        self.assertNotEqual(b.latency_rgb(40), b.latency_rgb(40, True))
        self.assertEqual(b.colour_latency("—", None, enabled=True), "—")

    def test_colour_flags(self):
        with (
            patch.object(b.shutil, "which", return_value="ping"),
            patch("nordvpn_connection.benchmark_preflight", return_value=True),
            patch.object(b, "execute_stage", return_value={"127.0.0.1": b.Measurement("127.0.0.1", 3, [10, 11, 12])}),
            patch.object(b, "terminal_colour_enabled", return_value=True),
            tempfile.TemporaryDirectory() as directory,
        ):
            Path(directory, "server.ovpn").write_text("proto udp\nremote 127.0.0.1 53\n")
            import io
            from contextlib import redirect_stdout

            for flag in ("--colourblind", "--colorblind"):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(b.main(["--config-dir", directory, flag, "--quiet"]), 0)
                self.assertIn("\x1b[38;2;", output.getvalue())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(b.main(["--config-dir", directory, "--no-colour", "--quiet"]), 0)
            self.assertNotIn("\x1b[", output.getvalue())

    def test_ranking(self):
        reliable = b.Measurement("a", 3, [20, 21, 22])
        unreliable = b.Measurement("b", 3, [1])
        self.assertLess(b.rank(reliable), b.rank(unreliable))


if __name__ == "__main__":
    unittest.main()


class FilterTests(unittest.TestCase):
    def setUp(self):
        from nordvpn_filter import compile_filter, server_identity

        self.compile = compile_filter
        self.identity = server_identity
        self.uk = b.Endpoint("09150-uk2108.nordvpn.com.udp_2.6.ovpn", "89.34.98.86", 53, "udp", "uk2108.nordvpn.com")
        self.us = b.Endpoint("us17.ovpn", "1.2.3.4", 443, "tcp", "us17.nordvpn.com")
        self.nl = b.Endpoint("nl1.ovpn", "1.2.3.5", 53, "udp", "nl1.nordvpn.com")

    def test_canonical_identity_and_export(self):
        self.assertEqual(self.identity(self.uk.file), "uk2108.nordvpn.com")
        self.assertEqual(self.identity("uk715.nordvpn.com.tcp_2.6.ovpn"), "uk715.nordvpn.com")
        row = b.records_for([self.uk], {self.uk.host: b.Measurement(self.uk.host, 2, [6.1, 6.2])})[0]
        self.assertEqual(row["server"], "uk2108.nordvpn.com")
        self.assertEqual(row["config_file"], self.uk.file)
        self.assertIn("uk2108.nordvpn.com", b.format_results([row], 1, True))
        self.assertNotIn("09150-", b.format_results([row], 1, True))

    def test_boolean_precedence_and_negation(self):
        self.assertTrue(self.compile("!uk|!us")(self.uk))
        self.assertFalse(self.compile("!(uk|us)")(self.uk))
        self.assertFalse(self.compile("!(uk|us)")(self.us))
        self.assertTrue(self.compile("!(uk|us)")(self.nl))
        self.assertTrue(self.compile("(uk|nl)&protocol:udp")(self.uk))
        self.assertFalse(self.compile("(uk|nl)&protocol:udp")(self.us))
        self.assertTrue(self.compile("server:uk* & port:53")(self.uk))
        self.assertTrue(self.compile("host:*.nordvpn.com")(self.uk))

    def test_invalid_expressions(self):
        from nordvpn_filter import FilterSyntaxError

        for expression in ("", "uk|", "!(uk|us", "uk&)", "country:usa", "port:99999", "protocol:icmp", "foo", "uk us"):
            with self.subTest(expression=expression), self.assertRaises(FilterSyntaxError):
                self.compile(expression)

    def test_filter_applies_before_probes(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(b.shutil, "which", return_value="ping"),
            patch("nordvpn_connection.benchmark_preflight", return_value=True),
            patch.object(b, "execute_stage") as stage,
        ):
            path = Path(directory) / "09150-uk2108.nordvpn.com.udp_2.6.ovpn"
            path.write_text("proto udp\nremote 89.34.98.86 53\n")
            import contextlib
            import io

            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                b.main(["--config-dir", directory, "--filter=!(uk|us)"])
            self.assertEqual(error.exception.code, 2)
            stage.assert_not_called()


class RegionAndRankingTests(unittest.TestCase):
    def test_country_lookup_and_alias(self):
        from nordvpn_regions import country_name

        self.assertEqual(country_name("nl828.nordvpn.com"), "Netherlands")
        self.assertEqual(country_name("uk2108.nordvpn.com"), "United Kingdom")
        self.assertEqual(country_name("custom.example"), "Unknown")

    def test_curated_region_filter_and_override(self):
        import json
        from nordvpn_regions import load_region_lists
        from nordvpn_filter import compile_filter

        regions = load_region_lists()
        self.assertEqual(
            regions["low-ads"]["countries"],
            ["ad", "al", "ao", "bn", "bs", "bt", "bz", "gl", "im", "je", "mc", "mm", "mn", "mz", "pg", "tt", "uz"],
        )
        endpoint = b.Endpoint("ad12.ovpn", "1.2.3.4", 53, "udp", "ad12.nordvpn.com")
        self.assertTrue(compile_filter("list:low-ads", regions)(endpoint))
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "regions.json"
            file.write_text(json.dumps({"low-ads": {"description": "Custom", "countries": ["nl"]}}))
            overridden = load_region_lists(file)
            self.assertFalse(compile_filter("list:low-ads", overridden)(endpoint))
            file.write_text(json.dumps({"bad": {"description": "Duplicate", "countries": ["nl", "nl"]}}))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_region_lists(file)

    def test_distinct_server_ranking_retains_full_export_records(self):
        endpoints = [b.Endpoint("nl828.ovpn", "1.2.3.4", port, "udp", "nl828.nordvpn.com") for port in (53, 1231, 1232)]
        endpoints.append(b.Endpoint("nl825.ovpn", "1.2.3.5", 53, "udp", "nl825.nordvpn.com"))
        measurements = {host: b.Measurement(host, 3, [10, 11, 12]) for host in ("1.2.3.4", "1.2.3.5")}
        records = b.records_for(endpoints, measurements)
        self.assertEqual(len(records), 4)
        distinct = b.distinct_servers(records)
        self.assertEqual(len(distinct), 2)
        self.assertIn("Netherlands", b.format_results(distinct, 2, True))


class CuratedLowAdsTests(unittest.TestCase):
    def test_builtin_list_matches_verified_nordvpn_shortlist(self):
        from nordvpn_regions import load_region_lists

        group = load_region_lists()["low-ads"]
        self.assertEqual(
            set(group["countries"]),
            {"ad", "al", "ao", "bn", "bs", "bt", "bz", "gl", "im", "je", "mc", "mm", "mn", "mz", "pg", "tt", "uz"},
        )

    def test_low_ads_codes_are_sorted_unique_and_iso_recognised(self):
        from nordvpn_regions import load_region_lists, normalise_country_code

        codes = load_region_lists()["low-ads"]["countries"]
        self.assertEqual(codes, sorted(set(codes)))
        self.assertTrue(all(normalise_country_code(code) == code for code in codes))

    def test_new_low_ads_locations_match_and_monetised_exceptions_do_not(self):
        from nordvpn_filter import compile_filter
        from nordvpn_regions import load_region_lists

        matcher = compile_filter("list:low-ads", load_region_lists())
        for code in ("ao", "bn", "bt", "gl", "im", "je", "mm", "mn", "mz"):
            with self.subTest(country=code):
                endpoint = b.Endpoint(f"{code}1.ovpn", "192.0.2.1", 53, "udp", f"{code}1.nordvpn.com")
                self.assertTrue(matcher(endpoint))
        for code in ("am", "la", "np", "lk"):
            with self.subTest(country=code):
                endpoint = b.Endpoint(f"{code}1.ovpn", "192.0.2.2", 53, "udp", f"{code}1.nordvpn.com")
                self.assertFalse(matcher(endpoint))

    def test_low_ads_filter_matches_nordvpn_country(self):
        from nordvpn_filter import compile_filter
        from nordvpn_regions import load_region_lists

        matcher = compile_filter("list:low-ads", load_region_lists())
        andorra = b.Endpoint("ad1.ovpn", "192.0.2.1", 53, "udp", "ad1.nordvpn.com")
        netherlands = b.Endpoint("nl1.ovpn", "192.0.2.2", 53, "udp", "nl1.nordvpn.com")
        self.assertTrue(matcher(andorra))
        self.assertFalse(matcher(netherlands))


class CountryAliasTests(unittest.TestCase):
    def test_nordvpn_hostname_retains_provider_identity(self):
        from nordvpn_regions import country_code, country_name, normalise_country_code

        self.assertEqual(country_code("uk2108.nordvpn.com"), "gb")
        self.assertEqual(country_name("uk2108.nordvpn.com"), "United Kingdom")
        self.assertEqual(normalise_country_code("UK"), "gb")
        self.assertEqual(normalise_country_code("nl"), "nl")
        self.assertEqual(b.server_identity("uk2108.nordvpn.com.udp_2.6.ovpn"), "uk2108.nordvpn.com")

    def test_aliases_work_in_boolean_filters(self):
        from nordvpn_filter import compile_filter

        endpoint = b.Endpoint("uk2108.ovpn", "192.0.2.1", 53, "udp", "uk2108.nordvpn.com")
        for expression in ("uk", "gb", "country:uk", "country:gb", "uk|nl", "gb&!us"):
            with self.subTest(expression=expression):
                self.assertTrue(compile_filter(expression)(endpoint))
        self.assertFalse(compile_filter("!(gb|us)")(endpoint))

    def test_region_list_normalises_aliases_and_rejects_duplicates(self):
        import json
        from nordvpn_filter import compile_filter
        from nordvpn_regions import load_region_lists

        endpoint = b.Endpoint("uk2108.ovpn", "192.0.2.1", 53, "udp", "uk2108.nordvpn.com")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "regions.json"
            path.write_text(json.dumps({"british": {"description": "UK servers", "countries": ["uk"]}}))
            lists = load_region_lists(path)
            self.assertEqual(lists["british"]["countries"], ["gb"])
            self.assertTrue(compile_filter("list:british", lists)(endpoint))
            path.write_text(json.dumps({"british": {"description": "Duplicate", "countries": ["uk", "gb"]}}))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_region_lists(path)


class EarlyFilterTests(unittest.TestCase):
    def test_country_boolean_semantics_and_unknown_fallback(self):
        from nordvpn_regions import load_region_lists

        regions = load_region_lists()
        cases = {
            "!(uk|us)": {"uk": False, "us": False, "nl": True},
            "!uk|!us": {"uk": True, "us": True, "nl": True},
            "list:low-ads|country:nl": {"ad": True, "nl": True, "us": False},
            "country:gb": {"uk": True, "nl": False},
        }
        for expression, expected in cases.items():
            eligible = b.country_prefilter([expression], regions)
            for code, included in expected.items():
                with self.subTest(expression=expression, code=code):
                    self.assertEqual(eligible(f"{code}1.nordvpn.com.udp_2.6.ovpn"), included)
            self.assertTrue(eligible("unusual-name.ovpn"))

    def test_mixed_expression_never_excludes_on_filename_alone(self):
        from nordvpn_regions import load_region_lists

        eligible = b.country_prefilter(["country:uk|port:443"], load_region_lists())
        self.assertTrue(eligible("us1.nordvpn.com.udp_2.6.ovpn"))

    def test_archive_skips_excluded_profiles_before_extraction(self):
        import io
        import zipfile
        from nordvpn_regions import load_region_lists

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "source.zip", "w") as archive:
                for code in ("uk", "us", "ad"):
                    archive.writestr(f"ovpn_udp/{code}1.nordvpn.com.udp_2.6.ovpn", "proto udp\nremote 127.0.0.1 53\n")
            content = (root / "source.zip").read_bytes()
            eligible = b.country_prefilter(["list:low-ads"], load_region_lists())
            with patch.object(b, "urlopen", return_value=io.BytesIO(content)):
                b.extract_archive(root, lambda message: None, "udp", eligible)
            profiles = list((root / "profiles").glob("*.ovpn"))
            self.assertEqual(len(profiles), 1)
            self.assertIn("ad1.nordvpn.com", profiles[0].name)


class CountryFlagTests(unittest.TestCase):
    def test_flags_and_aliases(self):
        from nordvpn_regions import country_flag

        self.assertEqual(country_flag("uk2108.nordvpn.com"), "🇬🇧")
        self.assertEqual(country_flag("gb1.nordvpn.com"), "🇬🇧")
        self.assertEqual(country_flag("al1.nordvpn.com"), "🇦🇱")
        self.assertEqual(country_flag("custom.example"), "")
        self.assertEqual(country_flag("zz1.nordvpn.com"), "")

    def test_table_flags_and_ascii_fallback(self):
        record = {
            "server": "uk2108.nordvpn.com",
            "country": "United Kingdom",
            "protocol": "udp",
            "address": "192.0.2.1",
            "port": 1194,
            "mean_ms": 10.0,
            "median_ms": 10.0,
            "jitter_mad_ms": 0.0,
            "loss_pct": 0.0,
            "received": 3,
            "sent": 3,
            "stage": "initial",
        }
        unicode_table = b.format_results([record], 1, False)
        ascii_table = b.format_results([record], 1, True)
        self.assertIn("🇬🇧  United Kingdom", unicode_table)
        self.assertNotIn("🇬🇧", ascii_table)
        self.assertIn("United Kingdom", ascii_table)
        self.assertEqual(b.display_width("🇬🇧  United Kingdom"), len("    United Kingdom"))
        # All rows retain the same number of separators.
        self.assertEqual(len({line.count("│") for line in unicode_table.splitlines() if "│" in line}), 1)
