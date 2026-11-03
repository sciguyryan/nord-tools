"""Linux rtnetlink deletion by interface index, without name re-resolution.

The kernel resolves the index in the RTM_DELLINK operation. This avoids a
second userspace name lookup, but cannot prevent privileged ifindex reuse
between the independent ownership observation and the kernel operation.
"""

from __future__ import annotations

import os
import socket
import struct


class LinkMutationError(RuntimeError):
    """The kernel did not confirm an indexed link deletion."""


# nlmsghdr and ifinfomsg from Linux rtnetlink UAPI.
_HEADER = struct.Struct("=IHHII")
_LINK = struct.Struct("=BBHiII")
_ERROR = struct.Struct("=i")
_RTM_DELLINK = 17
_NLMSG_ERROR = 2
_NLM_F_REQUEST = 1
_NLM_F_ACK = 4


def delete_link_by_index(ifindex: int) -> None:
    """Request deletion by numeric index and require a matching kernel ACK."""
    if not isinstance(ifindex, int) or isinstance(ifindex, bool) or not 0 < ifindex < 2**31:
        raise LinkMutationError("invalid interface index")
    if not hasattr(socket, "AF_NETLINK"):
        raise LinkMutationError("Linux rtnetlink is unavailable")
    sequence = int.from_bytes(os.urandom(4), "little") or 1
    payload = _LINK.pack(socket.AF_UNSPEC, 0, 0, ifindex, 0, 0)
    request = (
        _HEADER.pack(_HEADER.size + len(payload), _RTM_DELLINK, _NLM_F_REQUEST | _NLM_F_ACK, sequence, 0) + payload
    )
    try:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
            channel.settimeout(10)
            channel.bind((0, 0))
            channel.send(request)
            while True:
                response, sender = channel.recvfrom(65536)
                if sender[0] != 0:
                    raise LinkMutationError("link deletion response was not sent by the kernel")
                offset = 0
                acknowledged = False
                while offset + _HEADER.size <= len(response):
                    length, kind, _, received_sequence, pid = _HEADER.unpack_from(response, offset)
                    if length < _HEADER.size or offset + length > len(response):
                        raise LinkMutationError("malformed rtnetlink response")
                    if received_sequence == sequence:
                        if pid != 0 or kind != _NLMSG_ERROR or length < _HEADER.size + _ERROR.size:
                            raise LinkMutationError("unexpected rtnetlink deletion response")
                        error = _ERROR.unpack_from(response, offset + _HEADER.size)[0]
                        if error:
                            raise LinkMutationError(f"kernel rejected link deletion: errno {-error}")
                        acknowledged = True
                    offset += (length + 3) & ~3
                if offset != len(response):
                    raise LinkMutationError("malformed rtnetlink response alignment")
                if acknowledged:
                    return
    except (OSError, TimeoutError) as exc:
        raise LinkMutationError("rtnetlink deletion failed") from exc
