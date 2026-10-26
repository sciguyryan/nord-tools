"""Offline coverage for the derived endpoint catalogue."""

import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from nordvpn_cache import load, refresh

URL = "https://example.invalid/ovpn.zip"


def archive_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("ovpn_tcp/ad9.nordvpn.com.tcp.ovpn", "client\nproto tcp\nremote 192.0.2.1 443\n")
    return buffer.getvalue()


class Response(io.BytesIO):
    headers = {}


class CacheTests(unittest.TestCase):
    def test_refresh_reuses_fresh_and_offline_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "endpoints.json"
            with patch("nordvpn_cache.urlopen", return_value=Response(archive_bytes())) as fetch:
                first = refresh(path, URL, 3600, lambda message: None)
                self.assertEqual(first[0]["name"], "ad9.nordvpn.com")
                self.assertEqual(first[0]["port"], 443)
                self.assertEqual(refresh(path, URL, 3600, lambda message: None), first)
                self.assertEqual(refresh(path, URL, 0, lambda message: None, offline=True), first)
                fetch.assert_called_once()
            self.assertEqual(load(path, URL)["schema_version"], 1)

    def test_same_digest_keeps_parsed_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "endpoints.json"
            with patch("nordvpn_cache.urlopen", side_effect=lambda request, timeout: Response(archive_bytes())):
                refresh(path, URL, 0, lambda message: None)
                first = load(path, URL)
                refresh(path, URL, 0, lambda message: None)
                self.assertEqual(load(path, URL)["endpoints"], first["endpoints"])

    def test_invalid_cache_is_not_used_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "endpoints.json"
            path.write_text("{invalid", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "offline mode requires"):
                refresh(path, URL, 0, lambda message: None, offline=True)

    def test_failed_update_preserves_existing_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "endpoints.json"
            with patch("nordvpn_cache.urlopen", return_value=Response(archive_bytes())):
                refresh(path, URL, 0, lambda message: None)
            original = path.read_bytes()
            with (
                patch("nordvpn_cache.urlopen", return_value=Response(b"not a zip")),
                self.assertRaises(zipfile.BadZipFile),
            ):
                refresh(path, URL, 0, lambda message: None)
            self.assertEqual(path.read_bytes(), original)
