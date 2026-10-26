"""Checks for the offline Kongroo payload regeneration utility."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from nordvpn_kongroo import _payload
from tools.generate_kongroo_blob import encode_scene, main, replace_constants


class KongrooGeneratorTests(unittest.TestCase):
    def test_current_scene_reproduces_runtime_blob(self):
        ciphertext, tag = encode_scene(_payload("El Psy Kongroo"), "El Psy Kongroo")
        with patch("nordvpn_kongroo.CIPHERTEXT", ciphertext), patch("nordvpn_kongroo.TAG", tag):
            self.assertEqual(_payload("El Psy Kongroo")["signature"], "1.048596")

    def test_changed_phrase_changes_ciphertext_and_tag(self):
        scene = _payload("El Psy Kongroo")
        original = encode_scene(scene, "El Psy Kongroo")
        changed = encode_scene(scene, "a different worldline")
        self.assertNotEqual(original[0], changed[0])
        self.assertNotEqual(original[1], changed[1])

    def test_changed_message_changes_ciphertext(self):
        scene = _payload("El Psy Kongroo").copy()
        scene["message"] = ["A different transmission"]
        self.assertNotEqual(
            encode_scene(scene, "El Psy Kongroo")[0], encode_scene(_payload("El Psy Kongroo"), "El Psy Kongroo")[0]
        )

    def test_source_replacement_only_changes_blob_constants(self):
        original = 'CIPHERTEXT = "aa"\nTAG = "bb"\nOTHER = "safe"\n'
        self.assertEqual(replace_constants(original, "cc", "dd"), 'CIPHERTEXT = "cc"\nTAG = "dd"\nOTHER = "safe"\n')
        with self.assertRaises(ValueError):
            replace_constants('CIPHERTEXT = "aa"\n', "cc", "dd")

    def test_file_input_outputs_constants_without_modifying_module(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scene.json"
            path.write_text(json.dumps(_payload("El Psy Kongroo")), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--scene", str(path), "--phrase", "replacement"]), 0)
            self.assertIn("CIPHERTEXT =", output.getvalue())
            self.assertIn("TAG =", output.getvalue())

    def test_bad_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scene.json"
            path.write_text('{"message": []}', encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--scene", str(path), "--phrase", "replacement"]), 1)
        with (
            patch("tools.generate_kongroo_blob.getpass.getpass", return_value="incorrect"),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["--current"]), 1)
