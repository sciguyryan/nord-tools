"""Regression checks for the isolated terminal puzzle."""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch

import nord_tools
from nordvpn_kongroo import decrypt, main, render


class KongrooTests(unittest.TestCase):
    def test_answer_and_authentication(self):
        self.assertIn("El Psy Kongroo.", decrypt("EL PSY KONGROO"))
        self.assertIsNone(decrypt("wrong answer"))

    def test_clue_and_failure(self):
        stream = io.StringIO()
        self.assertEqual(main([], output=stream), 0)
        self.assertIn("CLUE:", stream.getvalue())
        stream = io.StringIO()
        self.assertEqual(main(["--decode", "incorrect"], output=stream), 1)
        self.assertNotIn("El Psy Kongroo.", stream.getvalue())

    def test_ascii_noninteractive_has_no_escapes(self):
        stream = io.StringIO()
        self.assertEqual(main(["--decode", "el psy kongroo"], output=stream), 0)
        self.assertIn("+==", stream.getvalue())
        self.assertNotIn("\x1b", stream.getvalue())

    def test_unicode_and_colour_rendering(self):
        self.assertIn("╔", render("hello", unicode=True, colour=False))
        self.assertIn("\x1b[0m", render("hello", unicode=True, colour=True))
        self.assertNotIn("\x1b", render("hello", unicode=False, colour=False))

    def test_reduced_motion_and_no_colour(self):
        stream = io.StringIO()
        stream.isatty = lambda: True
        with patch.dict("os.environ", {"NORD_TOOLS_REDUCED_MOTION": "1", "NO_COLOR": "1"}):
            self.assertEqual(main(["--decode", "el psy kongroo"], output=stream), 0)
        self.assertNotIn("Synchronising", stream.getvalue())
        self.assertNotIn("\x1b", stream.getvalue())

    def test_unified_dispatch_and_hidden_help(self):
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            self.assertEqual(nord_tools.main(["--help"]), 0)
        self.assertNotIn("divergence", stream.getvalue())
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            self.assertEqual(nord_tools.main(["divergence"]), 0)
        self.assertIn("INTERCEPTED", stream.getvalue())


if __name__ == "__main__":
    unittest.main()


class CinematicRevealTests(unittest.TestCase):
    def test_ciphered_scene_contains_no_plaintext_reveal(self):
        from nordvpn_kongroo import CIPHERTEXT, _payload

        self.assertNotIn("El Psy Kongroo", CIPHERTEXT)
        self.assertEqual(_payload("el psy kongroo")["signature"], "1.048596")

    def test_animation_restores_terminal(self):
        from nordvpn_kongroo import _animate, _payload

        stream = io.StringIO()
        with (
            patch("nordvpn_kongroo.shutil.get_terminal_size", return_value=(80, 24)),
            patch("nordvpn_kongroo.time.sleep"),
        ):
            _animate(_payload("el psy kongroo"), stream, colour=False)
        output = stream.getvalue()
        self.assertIn("\x1b[?1049h\x1b[?25l", output)
        self.assertIn("\x1b[?25h\x1b[?1049l", output)
        self.assertIn("WORLDLINE RECONSTRUCTION", output)
        self.assertIn("El Psy Kongroo.", output)

    def test_interruption_restores_cursor_and_screen(self):
        from nordvpn_kongroo import _animate, _payload

        stream = io.StringIO()
        with (
            patch("nordvpn_kongroo.shutil.get_terminal_size", return_value=(80, 24)),
            patch("nordvpn_kongroo.time.sleep", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            _animate(_payload("el psy kongroo"), stream, colour=True)
        self.assertTrue(stream.getvalue().endswith("\x1b[0m\x1b[?25h\x1b[?1049l"))

    def test_narrow_terminal_falls_back(self):
        from nordvpn_kongroo import _animate, _payload

        stream = io.StringIO()
        with patch("nordvpn_kongroo.shutil.get_terminal_size", return_value=(30, 10)):
            _animate(_payload("el psy kongroo"), stream, colour=False)
        self.assertNotIn("\x1b[?1049h", stream.getvalue())
        self.assertIn("El Psy Kongroo.", stream.getvalue())


class VariableProgressTests(unittest.TestCase):
    def test_progress_is_monotonic_and_reaches_completion(self):
        from nordvpn_kongroo import ANIMATION_FRAMES, _progress

        values = [_progress(i) for i in range(ANIMATION_FRAMES)]
        self.assertEqual(values[0], 0)
        self.assertEqual(values[-1], 100)
        self.assertEqual(values, sorted(values))

    def test_progress_has_bursts_and_slow_intervals(self):
        from nordvpn_kongroo import _progress

        self.assertGreater(_progress(12) - _progress(0), 15)
        self.assertLess(_progress(29) - _progress(12), 10)
        self.assertGreater(_progress(44) - _progress(29), 20)
        self.assertLess(_progress(67) - _progress(44), 10)

    def test_animation_is_longer_than_original_and_bounded(self):
        from nordvpn_kongroo import ANIMATION_FRAMES, FRAME_INTERVAL_SECONDS, _progress

        self.assertGreaterEqual(ANIMATION_FRAMES * FRAME_INTERVAL_SECONDS, 7)
        self.assertLessEqual(ANIMATION_FRAMES * FRAME_INTERVAL_SECONDS, 12)
        self.assertEqual(_progress(-10), 0)
        self.assertEqual(_progress(ANIMATION_FRAMES + 10), 100)


class NumericalSearchTests(unittest.TestCase):
    def test_authenticated_scene_contains_search_inputs(self):
        from nordvpn_kongroo import _payload

        scene = _payload("El Psy Kongroo")
        self.assertEqual(scene["glyphs"], "0123456789ABCDEF")
        self.assertEqual(scene["signature"], "1.048596")

    def test_search_window_narrows_to_target(self):
        from nordvpn_kongroo import ANIMATION_FRAMES, _search_window

        target = 1048596
        windows = [_search_window(i, target) for i in range(ANIMATION_FRAMES)]
        self.assertTrue(all(low <= target <= high for low, high in windows))
        self.assertTrue(all(a[0] <= b[0] and a[1] >= b[1] for a, b in zip(windows, windows[1:])))
        self.assertLessEqual(windows[-1][1] - windows[-1][0], 2)

    def test_search_rows_are_bounded_deterministic_and_converge(self):
        from nordvpn_kongroo import _search_rows

        args = ("0123456789ABCDEF", "1.048596")
        for width in (0, 12, 36, 80):
            for step in (0, 11, 39, 87, 119):
                rows = _search_rows(*args, step, 8, width)
                self.assertEqual(len(rows), 8)
                self.assertTrue(all(len(row) == width for row in rows))
                self.assertEqual(rows, _search_rows(*args, step, 8, width))
        self.assertNotEqual(_search_rows(*args, 0, 8, 80), _search_rows(*args, 40, 8, 80))
        self.assertTrue(all("1.048596" in row and "LOCK" in row for row in _search_rows(*args, 119, 8, 80)))

    def test_invalid_search_inputs_rejected(self):
        from nordvpn_kongroo import _search_rows

        with self.assertRaises(ValueError):
            _search_rows("01ABCDEF", "1.048596", 0, 1, 80)
        with self.assertRaises(ValueError):
            _search_rows("0123456789ABCDEF", "invalid", 0, 1, 80)

    def test_frame_has_numeric_search_not_random_hex_wall(self):
        from nordvpn_kongroo import _frame, _payload

        scene = _payload("El Psy Kongroo")
        for width, height in ((44, 19), (80, 24), (120, 42)):
            frame = _frame(scene, 60, width=width, height=height, colour=False)
            self.assertIn("RANGE", frame)
            self.assertIn("CANDIDATE", frame)
            self.assertIn("SCAN", frame)
            self.assertTrue(all(len(line) == width for line in frame.splitlines()))
            self.assertLessEqual(len(frame.splitlines()), height)


class ChaoticTransmissionTests(unittest.TestCase):
    def test_eccentric_layout_is_bounded_and_deterministic(self):
        from nordvpn_kongroo import decrypt, render

        message = decrypt("El Psy Kongroo")
        for unicode in (False, True):
            result = render(message, unicode=unicode, colour=False)
            self.assertEqual(result, render(message, unicode=unicode, colour=False))
            self.assertIn("RECHECK THAT NUMBER", result)
            self.assertIn("1.048596", result)
            self.assertIn("El Psy Kongroo.", result)
            self.assertTrue(all(len(line) <= 90 for line in result.splitlines()))
            self.assertNotIn("\x1b", result)

    def test_message_is_encrypted_not_embedded_in_source(self):
        from pathlib import Path
        from nordvpn_kongroo import CIPHERTEXT

        source = Path(__file__).resolve().parents[1].joinpath("nordvpn_kongroo.py").read_text()
        self.assertNotIn("THE ORGANISATION HAS LOST OUR COORDINATES!!", source)
        self.assertNotIn("El Psy Kongroo.", CIPHERTEXT)
