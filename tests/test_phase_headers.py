import io
import unittest
from unittest.mock import patch
import os

from nordvpn_benchmark import phase_header


class PhaseHeaderTests(unittest.TestCase):
    def test_redirected_output_is_plain_ascii(self):
        stream = io.StringIO()
        phase_header("Server discovery", stream=stream)
        self.assertEqual(stream.getvalue(), "-- Server discovery --\n")

    def test_quiet_suppresses_headings(self):
        stream = io.StringIO()
        phase_header("Results", stream=stream, quiet=True)
        self.assertEqual(stream.getvalue(), "")

    def test_interactive_unicode_heading(self):
        stream = io.StringIO()
        stream.isatty = lambda: True
        with patch("nordvpn_benchmark.shutil.get_terminal_size", return_value=os.terminal_size((50, 24))):
            phase_header("Refinement", stream=stream)
        self.assertTrue(stream.getvalue().startswith("── Refinement ──"))
        self.assertTrue(stream.getvalue().endswith("\n"))

    def test_phase_separation_adds_exactly_one_blank_line(self):
        stream = io.StringIO()
        phase_header("Configuration", stream=stream)
        print("Probe method: TCP", file=stream)
        phase_header("Server discovery", stream=stream, separate=True)
        self.assertEqual(stream.getvalue(), "-- Configuration --\nProbe method: TCP\n\n-- Server discovery --\n")

    def test_quiet_suppresses_separation(self):
        stream = io.StringIO()
        phase_header("Results", stream=stream, separate=True, quiet=True)
        self.assertEqual(stream.getvalue(), "")

    def test_ascii_overrides_tty(self):
        stream = io.StringIO()
        stream.isatty = lambda: True
        phase_header("Results", ascii_only=True, stream=stream)
        self.assertEqual(stream.getvalue(), "-- Results --\n")
