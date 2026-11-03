"""Rtnetlink deletion protocol and fail-closed ACK handling."""

import errno
import struct
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_link_netlink import LinkMutationError, delete_link_by_index


class Channel:
    def __init__(self, *, error=0, malformed=False, sender=(0, 0)):
        self.error = error
        self.malformed = malformed
        self.sender = sender
        self.sent = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, value):
        assert value == 10

    def bind(self, address):
        assert address == (0, 0)

    def send(self, payload):
        self.sent = payload

    def recvfrom(self, size):
        assert size >= 36
        length, kind, flags, sequence, pid = struct.unpack_from("=IHHII", self.sent)
        assert (length, kind, flags, pid) == (32, 17, 5, 0)
        assert struct.unpack_from("=BBHiII", self.sent, 16)[3] == 42
        response = struct.pack("=IHHIIi", 20 if not self.malformed else 18, 2, 0, sequence, 0, self.error)
        return response, self.sender


@pytest.mark.parametrize("value", [0, -1, True, 2**31, "42"])
def test_reject_invalid_indices(value):
    with pytest.raises(LinkMutationError, match="invalid interface index"):
        delete_link_by_index(value)


@pytest.mark.parametrize(
    "error,malformed,sender,passes",
    [
        (0, False, (0, 0), True),
        (-errno.EPERM, False, (0, 0), False),
        (0, True, (0, 0), False),
        (0, False, (123, 0), False),
    ],
)
def test_kernel_ack_is_required(error, malformed, sender, passes):
    channel = Channel(error=error, malformed=malformed, sender=sender)
    with patch("socket.socket", return_value=channel):
        if passes:
            delete_link_by_index(42)
        else:
            with pytest.raises(LinkMutationError):
                delete_link_by_index(42)


def test_matching_ack_cannot_hide_trailing_malformed_message():
    """An ACK does not excuse malformed trailing data in the same datagram."""

    class TrailingChannel(Channel):
        def recvfrom(self, size):
            response, sender = super().recvfrom(size)
            return response + b"\x00", sender

    with (
        patch("socket.socket", return_value=TrailingChannel()),
        pytest.raises(LinkMutationError, match="alignment"),
    ):
        delete_link_by_index(42)


def test_matching_ack_cannot_hide_trailing_invalid_header():
    """Reject an invalid second message rather than returning on the first ACK."""

    class InvalidHeaderChannel(Channel):
        def recvfrom(self, size):
            response, sender = super().recvfrom(size)
            return response + struct.pack("=IHHII", 8, 2, 0, 0, 0), sender

    with (
        patch("socket.socket", return_value=InvalidHeaderChannel()),
        pytest.raises(LinkMutationError, match="malformed"),
    ):
        delete_link_by_index(42)
