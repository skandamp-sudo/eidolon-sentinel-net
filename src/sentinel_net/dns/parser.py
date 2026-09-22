"""Strict iterative DNS wire reader. No Scapy DNS dissection, I/O or reassembly.

Only complete port-53 UDP datagrams / TCP frames are eligible. IP fragments
and IPv6 extension chains are explicitly unavailable. TCP framing is all-or-
nothing per captured segment, so partial frames never yield behavioral input.
"""

import struct

MAX_MESSAGE = 4096
MAX_POINTERS = 16
MAX_LABELS = 32
MAX_QUESTIONS = 4
MAX_RECORDS = 64
MAX_TCP_MESSAGES = 4
TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    65: "HTTPS",
}


class ParseIssue(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


def problem(status, reason):
    return {"status": status, "reason": reason}


def need(data, pos, size):
    if pos < 0 or pos + size > len(data):
        raise ParseIssue("TRUNCATED", "Record extends beyond captured DNS message")


def name(data, offset):
    labels, seen, jumps, wire_size, end = [], set(), 0, 1, None
    while True:
        need(data, offset, 1)
        if offset in seen:
            raise ParseIssue("MALFORMED", "Compression pointer loop")
        seen.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            need(data, offset, 2)
            target = ((length & 63) << 8) | data[offset + 1]
            if target >= len(data):
                raise ParseIssue("MALFORMED", "Compression pointer out of range")
            jumps += 1
            if jumps > MAX_POINTERS:
                raise ParseIssue("UNSUPPORTED", "Compression pointer limit exceeded")
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0:
            raise ParseIssue("UNSUPPORTED", "Unsupported DNS label encoding")
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        need(data, offset, length)
        if len(labels) >= MAX_LABELS:
            raise ParseIssue("UNSUPPORTED", "Label count limit exceeded")
        wire_size += length + 1
        if wire_size > 255:
            raise ParseIssue("MALFORMED", "Decoded name exceeds DNS wire length limit")
        label = data[offset : offset + length]
        if any(
            not (48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 or b in b"-_*") for b in label
        ):
            raise ParseIssue("UNSUPPORTED", "Non-hostname/binary label encoding is not analyzed")
        labels.append(label.decode("ascii").lower())
        offset += length


def parse_message(data):
    try:
        if len(data) > MAX_MESSAGE:
            raise ParseIssue("UNSUPPORTED", "DNS message exceeds 4096-byte policy limit")
        need(data, 0, 12)
        txid, flags, qd, an, ns, ar = struct.unpack_from("!6H", data)
        if qd > MAX_QUESTIONS or an + ns + ar > MAX_RECORDS:
            raise ParseIssue("UNSUPPORTED", "Question/record count limit exceeded")
        if (flags >> 11) & 15:
            raise ParseIssue("UNSUPPORTED", "Only standard DNS opcode is analyzed")
        pos, questions, types = 12, [], []
        for _ in range(qd):
            qname, pos = name(data, pos)
            need(data, pos, 4)
            qt, qc = struct.unpack_from("!HH", data, pos)
            pos += 4
            questions.append(
                {
                    "name": qname,
                    "qtype": qt,
                    "qtype_name": TYPE_NAMES.get(qt, f"TYPE{qt}"),
                    "qclass": qc,
                }
            )
        extended_rcode = 0
        opt_seen = False
        for index in range(an + ns + ar):
            owner, pos = name(data, pos)
            need(data, pos, 10)
            rt, _, ttl, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            need(data, pos, size)
            if rt == 41:
                if opt_seen or index < an + ns or owner:
                    raise ParseIssue("MALFORMED", "Invalid OPT placement")
                opt_seen = True
                extended_rcode = ttl >> 24
            types.append(rt)
            pos += size  # Never interpret or retain response RDATA.
        if pos != len(data):
            raise ParseIssue("MALFORMED", "Unexpected trailing DNS bytes")
        return {
            "status": "TRUNCATED" if flags & 512 else "PARSED",
            "reason": "DNS TC flag" if flags & 512 else None,
            "transaction_id": txid,
            "qr": bool(flags & 32768),
            "opcode": (flags >> 11) & 15,
            "rcode": (extended_rcode << 4) | (flags & 15),
            "question_count": qd,
            "answer_count": an,
            "record_count": an + ns + ar,
            "questions": questions,
            "response_record_types": types,
            "message_length": len(data),
            "truncated": bool(flags & 512),
        }
    except ParseIssue as exc:
        return problem(exc.status, exc.reason)


def observe_packet(packet):
    """Return capped observations; [] means no observable port-53/853 candidate."""
    ports = (packet.src_port, packet.dst_port)
    if 853 in ports:
        return [
            problem("ENCRYPTED_OR_UNAVAILABLE", "Port 853 candidate; encrypted DNS is not decoded")
        ]
    if 53 not in ports:
        return []
    if packet.protocol not in (6, 17):
        return [problem("ENCRYPTED_OR_UNAVAILABLE", "Extended/fragmented transport is not decoded")]
    if packet.raw_packet is None:
        return [problem("ENCRYPTED_OR_UNAVAILABLE", "Raw bytes unavailable")]
    data = memoryview(packet.raw_packet.raw_bytes)
    try:
        need(data, 0, 14)
        kind, pos = struct.unpack_from("!H", data, 12)[0], 14
        for _ in range(2):
            if kind not in (0x8100, 0x88A8):
                break
            need(data, pos, 4)
            kind, pos = struct.unpack_from("!H", data, pos + 2)[0], pos + 4
        if kind == 0x0800:
            need(data, pos, 20)
            header = (data[pos] & 15) * 4
            total, fragment = (
                struct.unpack_from("!HH", data, pos + 2)[0],
                struct.unpack_from("!H", data, pos + 6)[0],
            )
            if data[pos] >> 4 != 4 or header < 20 or total < header:
                raise ParseIssue("MALFORMED", "Invalid IPv4 envelope")
            if fragment & 0x3FFF:
                raise ParseIssue("ENCRYPTED_OR_UNAVAILABLE", "Fragmented DNS is not reassembled")
            need(data, pos, total)
            proto, end, pos = data[pos + 9], pos + total, pos + header
        elif kind == 0x86DD:
            need(data, pos, 40)
            size, proto = struct.unpack_from("!H", data, pos + 4)[0], data[pos + 6]
            if proto not in (6, 17):
                raise ParseIssue(
                    "ENCRYPTED_OR_UNAVAILABLE", "IPv6 extension/fragment chain is not decoded"
                )
            need(data, pos + 40, size)
            end, pos = pos + 40 + size, pos + 40
        else:
            raise ParseIssue("UNSUPPORTED", "Unsupported link/network envelope")
        if proto != packet.protocol:
            raise ParseIssue("MALFORMED", "Transport metadata mismatch")
        data = data[:end]
        if proto == 17:
            need(data, pos, 8)
            size = struct.unpack_from("!H", data, pos + 4)[0]
            if size < 8:
                raise ParseIssue("MALFORMED", "Invalid UDP length")
            need(data, pos, size)
            if size - 8 > MAX_MESSAGE:
                raise ParseIssue("UNSUPPORTED", "DNS message exceeds policy limit")
            return [parse_message(bytes(data[pos + 8 : pos + size]))]
        need(data, pos, 20)
        header = (data[pos + 12] >> 4) * 4
        if header < 20:
            raise ParseIssue("MALFORMED", "Invalid TCP header")
        need(data, pos, header)
        pos += header
        if pos == end:
            return []  # ACK/SYN without DNS data is not a malformed DNS message.
        if end - pos > MAX_TCP_MESSAGES * (MAX_MESSAGE + 2):
            raise ParseIssue("UNSUPPORTED", "TCP segment DNS budget exceeded")
        frames = []
        while pos < end:
            if len(frames) == MAX_TCP_MESSAGES:
                raise ParseIssue("UNSUPPORTED", "TCP message count limit exceeded")
            need(data, pos, 2)
            size = struct.unpack_from("!H", data, pos)[0]
            pos += 2
            if size < 12:
                raise ParseIssue("MALFORMED", "Invalid TCP DNS length prefix")
            if size > MAX_MESSAGE:
                raise ParseIssue("UNSUPPORTED", "TCP DNS message exceeds policy limit")
            need(data, pos, size)
            frames.append(bytes(data[pos : pos + size]))
            pos += size
        return [parse_message(frame) for frame in frames]
    except ParseIssue as exc:
        return [problem(exc.status, exc.reason)]
