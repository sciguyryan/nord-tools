"""Offline report contract and atomicity tests."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordvpn_report as report
import nordvpn_benchmark as benchmark


class ReportTests(unittest.TestCase):
    def test_report_schema_and_measurement_preservation(self):
        rows = [{"server": "ad9.nordvpn.com", "samples_ms": [8.2, 8.3]}]
        value = report.build_report(
            started_at="start",
            finished_at="end",
            settings={"probe": "tcp"},
            source={"kind": "download"},
            methodology={"latency_unit": "milliseconds"},
            records=rows,
            ranked=rows,
        )
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["measurements"][0]["samples_ms"], [8.2, 8.3])
        self.assertNotIn("stability", value)

    def test_atomic_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "report.json"
            report.write_report(path, {"schema_version": 1, "ranking": []})
            self.assertEqual(json.loads(path.read_text())["ranking"], [])
            previous = path.read_bytes()
            with self.assertRaises(ValueError):
                report.write_report(path, {"invalid": float("nan")})
            self.assertEqual(path.read_bytes(), previous)

    def test_main_report_from_local_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "ad9.nordvpn.com.udp.ovpn").write_text("proto udp\nremote 127.0.0.1 53\n")
            measurement = benchmark.Measurement("127.0.0.1", 3, [8.1, 8.2, 8.3])
            with (
                patch.object(benchmark.shutil, "which", return_value="ping"),
                patch.object(benchmark, "execute_stage", return_value={"127.0.0.1": measurement}),
                patch("nordvpn_connection.benchmark_preflight", return_value=True),
            ):
                self.assertEqual(
                    benchmark.main(
                        ["--config-dir", str(folder), "--report", str(folder / "report.json"), "--quiet", "--ascii"]
                    ),
                    0,
                )
            result = json.loads((folder / "report.json").read_text())
            self.assertEqual(result["settings"]["probe"], "icmp")
            self.assertEqual(result["source"]["kind"], "config-directory")
            self.assertEqual(result["ranking"][0]["server"], "ad9.nordvpn.com")


if __name__ == "__main__":
    unittest.main()
