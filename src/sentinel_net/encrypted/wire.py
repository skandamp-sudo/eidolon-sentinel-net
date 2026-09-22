"""Bounded Ethernet/IP transport slice; no transport/application dissection."""

import struct


class Invalid(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


def require(data, pos, size):
    if pos < 0 or size < 0 or pos + size > len(data):
        raise Invalid("TRUNCATED", "Captured structure shorter than declared length")


def transport_payload(packet, budget=65536):
    if packet.raw_packet is None:
        raise Invalid("UNAVAILABLE", "Raw capture bytes unavailable")
    data = memoryview(packet.raw_packet.raw_bytes)
    require(data, 0, 14)
    kind, pos = struct.unpack_from("!H", data, 12)[0], 14
    for _ in range(2):
        if kind not in (0x8100, 0x88A8):
            break
        require(data, pos, 4)
        kind, pos = struct.unpack_from("!H", data, pos + 2)[0], pos + 4
    if kind == 0x0800:
        require(data, pos, 20)
        header = (data[pos] & 15) * 4
        size = struct.unpack_from("!H", data, pos + 2)[0]
        fragment = struct.unpack_from("!H", data, pos + 6)[0]
        if data[pos] >> 4 != 4 or header < 20 or size < header:
            raise Invalid("MALFORMED", "Invalid IPv4 envelope")
        if fragment & 0x3FFF:
            raise Invalid("UNAVAILABLE", "IP fragments are not reassembled")
        require(data, pos, size)
        proto, end, pos = data[pos + 9], pos + size, pos + header
    elif kind == 0x86DD:
        require(data, pos, 40)
        if data[pos] >> 4 != 6:
            raise Invalid("MALFORMED", "Invalid IPv6 envelope")
        size, proto = struct.unpack_from("!H", data, pos + 4)[0], data[pos + 6]
        if proto not in (6, 17):
            raise Invalid("UNAVAILABLE", "IPv6 extension/fragment chain unavailable")
        require(data, pos + 40, size)
        end, pos = pos + 40 + size, pos + 40
    else:
        raise Invalid("UNSUPPORTED", "Unsupported link/network header")
    if proto != packet.protocol:
        raise Invalid("UNAVAILABLE", "Transport protocol unavailable")
    data = data[:end]
    if proto == 6:
        require(data, pos, 20)
        header = (data[pos + 12] >> 4) * 4
        if header < 20:
            raise Invalid("MALFORMED", "Invalid TCP header length")
        require(data, pos, header)
        pos += header
    elif proto == 17:
        require(data, pos, 8)
        size = struct.unpack_from("!H", data, pos + 4)[0]
        if size < 8:
            raise Invalid("MALFORMED", "Invalid UDP length")
        require(data, pos, size)
        end, pos = pos + size, pos + 8
    else:
        raise Invalid("UNSUPPORTED", "Transport unsupported")
    if end - pos > budget:
        raise Invalid("TRUNCATED", "Transport payload exceeds metadata byte budget")
    return bytes(data[pos:end])
