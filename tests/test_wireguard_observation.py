"""Deterministic read-only WireGuard observation tests."""

import unittest

from nord_tools_internal.nordvpn_wireguard_observation import (
    ObservationError,
    parse_peer_dump,
    require_fresh_exchange,
)


HEADER = "private\tpublic\t51820\toff\n"
KEY = "expected-peer"


def peer(handshake=100, received=128, sent=256, key=KEY):
    return f"{key}\t(none)\t192.0.2.1:51820\t10.0.0.1/32\t{handshake}\t{received}\t{sent}\toff\n"


class WireguardObservationTests(unittest.TestCase):
    def test_fresh_bidirectional_exchange(self):
        result = require_fresh_exchange(HEADER + peer(), KEY, 90, now=110)
        self.assertEqual((result.received_bytes, result.sent_bytes), (128, 256))

    def test_old_handshake_rejected(self):
        with self.assertRaises(ObservationError):
            require_fresh_exchange(HEADER + peer(), KEY, 101, now=110)

    def test_future_handshake_rejected(self):
        with self.assertRaises(ObservationError):
            require_fresh_exchange(HEADER + peer(handshake=120), KEY, 90, now=110)

    def test_no_bidirectional_traffic_rejected(self):
        for received, sent in ((0, 1), (1, 0), (0, 0)):
            with self.subTest(received=received, sent=sent), self.assertRaises(ObservationError):
                require_fresh_exchange(HEADER + peer(received=received, sent=sent), KEY, 90, now=110)

    def test_ambiguous_matching_peers_rejected(self):
        with self.assertRaises(ObservationError):
            parse_peer_dump(HEADER + peer() + peer(), KEY)

    def test_missing_peer_rejected(self):
        with self.assertRaises(ObservationError):
            parse_peer_dump(HEADER + peer(key="different"), KEY)

    def test_malformed_rows_rejected(self):
        for content in ("", HEADER, HEADER + "broken\n", HEADER + peer(handshake="bad"), HEADER + peer(received=-1)):
            with self.subTest(content=content), self.assertRaises(ObservationError):
                parse_peer_dump(content, KEY)

    def test_invalid_time_window_rejected(self):
        for start, now in ((0, 100), (100, 99), (100.0, 110)):
            with self.subTest(start=start, now=now), self.assertRaises(ObservationError):
                require_fresh_exchange(HEADER + peer(), KEY, start, now=now)


if __name__ == "__main__":
    unittest.main()
