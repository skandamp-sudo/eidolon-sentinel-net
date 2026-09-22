"""Deterministic safe protocol bytes for offline tests/benchmarks; never transmit."""

import struct


def vector(data, width=2):
    return len(data).to_bytes(width, "big") + data


def extension(kind, value):
    return struct.pack("!H", kind) + vector(value)


def record(handshake, content=22, version=771):
    return bytes([content]) + struct.pack("!HH", version, len(handshake)) + handshake


def client_hello(
    *,
    version=771,
    ciphers=(4865, 4866, 49199),
    extensions=None,
    sni="example.test",
    alpn=("h2", "http/1.1"),
    tls13=True,
):
    if extensions is None:
        extensions = []
        if sni is not None:
            extensions.append((0, vector(b"\0" + vector(sni.encode("ascii")))))
        extensions += [
            (10, vector(struct.pack("!HH", 29, 23))),
            (11, b"\x01\x00"),
            (13, vector(struct.pack("!HH", 1027, 2052))),
        ]
        if alpn:
            extensions.append((16, vector(b"".join(vector(p.encode("ascii"), 1) for p in alpn))))
        if tls13:
            extensions.append((43, vector(struct.pack("!HH", 772, 771), 1)))
    body = (
        struct.pack("!H", version)
        + bytes(32)
        + b"\x00"
        + vector(b"".join(struct.pack("!H", v) for v in ciphers))
        + b"\x01\x00"
        + vector(b"".join(extension(*e) for e in extensions))
    )
    return record(b"\x01" + len(body).to_bytes(3, "big") + body)


def server_hello(
    *, version=771, cipher=4865, extensions=((43, b"\x03\x04"), (51, b"\x00\x1d\x00\x00"))
):
    body = (
        struct.pack("!H", version)
        + bytes(32)
        + b"\x00"
        + struct.pack("!H", cipher)
        + b"\x00"
        + vector(b"".join(extension(*e) for e in extensions))
    )
    return record(b"\x02" + len(body).to_bytes(3, "big") + body)


def quic_initial(*, version=1, dcid=b"client01", scid=b"server01", packet_type=0):
    common = (
        bytes([0xC0 | (packet_type << 4)])
        + version.to_bytes(4, "big")
        + vector(dcid, 1)
        + vector(scid, 1)
    )
    if version == 0:
        return common + struct.pack("!II", 1, 0x6B3343CF)
    if version != 1:
        return common + b"opaque"
    if packet_type == 3:
        return common + b"token" + bytes(16)
    return common + (b"\x00" if packet_type == 0 else b"") + b"\x14" + bytes(20)
