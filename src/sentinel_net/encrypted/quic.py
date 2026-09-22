"""RFC 9000 invariant/QUIC v1 header metadata only. No crypto or payload decoding."""

import hashlib

from sentinel_net.encrypted.wire import Invalid, require


def varint(data, pos):
    require(data, pos, 1)
    width = 1 << (data[pos] >> 6)
    require(data, pos, width)
    return int.from_bytes(data[pos : pos + width], "big") & (
        (1 << (width * 8 - 2)) - 1
    ), pos + width


def parse_quic(data):
    try:
        require(data, 0, 1)
        if not data[0] & 128:
            return {
                "status": "UNSUPPORTED",
                "reason": "Short-header interpretation requires unobserved connection context",
                "long_header": False,
                "payload_inspected": False,
            }
        require(data, 0, 6)
        version = int.from_bytes(data[1:5], "big")
        pos = 5
        ids = {}
        for role in ("destination", "source"):
            require(data, pos, 1)
            size = data[pos]
            pos += 1
            if size > 20:
                raise Invalid(
                    "MALFORMED" if version == 1 else "UNSUPPORTED",
                    "CID length exceeds 20-byte supported bound",
                )
            require(data, pos, size)
            cid = data[pos : pos + size]
            pos += size
            ids[role + "_cid_length"] = size
            ids[role + "_cid_sha256"] = hashlib.sha256(cid).hexdigest() if size else None
        result = {
            "status": "COMPLETE",
            "long_header": True,
            "version": version,
            "version_hex": f"0x{version:08x}",
            "payload_inspected": False,
            "packet_size": len(data),
            **ids,
        }
        if version == 0:
            remaining = len(data) - pos
            if remaining == 0 or remaining % 4:
                raise Invalid("MALFORMED", "Invalid version-negotiation list length")
            if remaining // 4 > 16:
                raise Invalid("UNSUPPORTED", "Version list count limit exceeded")
            versions = [int.from_bytes(data[i : i + 4], "big") for i in range(pos, len(data), 4)]
            if 0 in versions:
                raise Invalid("MALFORMED", "Zero in version-negotiation list")
            result.update(
                packet_type="VERSION_NEGOTIATION",
                supported_versions=versions,
                integrity_verified=False,
            )
            return result
        if version != 1:
            result.update(
                status="UNSUPPORTED",
                packet_type="UNKNOWN_VERSION",
                reason="Only invariant CID/version fields parsed for unknown version",
            )
            return result
        if not data[0] & 64:
            raise Invalid("MALFORMED", "QUIC v1 fixed bit not set")
        kind = (data[0] >> 4) & 3
        result["packet_type"] = ["INITIAL", "ZERO_RTT", "HANDSHAKE", "RETRY"][kind]
        if kind == 3:
            require(data, pos, 16)
            result.update(token_length=len(data) - pos - 16, integrity_verified=False)
            return result
        if kind == 0:
            size, pos = varint(data, pos)
            if size > 4096:
                raise Invalid("UNSUPPORTED", "Initial token metadata budget exceeded")
            require(data, pos, size)
            pos += size
            result["token_length"] = size
        size, pos = varint(data, pos)
        if size < 1:
            raise Invalid("MALFORMED", "QUIC declared packet length must include protected data")
        require(data, pos, size)
        result.update(
            declared_packet_length=size,
            uninspected_trailing_bytes=len(data) - pos - size,
            packet_number="UNAVAILABLE_HEADER_PROTECTED",
        )
        return result
    except Invalid as exc:
        return {"status": exc.status, "reason": exc.reason, "payload_inspected": False}
