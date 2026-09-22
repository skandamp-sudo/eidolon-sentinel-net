"""Strict bounded hello reader and standard JA3/JA3S identifiers.

References: RFC 5246/8446; salesforce/ja3 README. MD5 is used only as the
specified non-security identifier. No key, certificate or ciphertext decoder.
"""

import hashlib

from sentinel_net.encrypted.wire import Invalid

MAX_RECORD = 16384
MAX_HANDSHAKE = 16384
MAX_RECORDS = 8
MAX_CIPHERS = 256
MAX_EXTENSIONS = 64
MAX_EXTENSION = 4096
MAX_GROUPS = 128
MAX_ALPN = 16
MAX_ALPN_LENGTH = 255
GREASE = frozenset(range(0x0A0A, 0xFAFB, 0x1010))
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        # The body/extension is already complete; nested overrun is malformed.
        if n < 0 or self.pos + n > len(self.data):
            raise Invalid("MALFORMED", "Nested TLS vector exceeds its enclosing length")
        result = self.data[self.pos : self.pos + n]
        self.pos += n
        return result

    def number(self, n):
        return int.from_bytes(self.take(n), "big")

    def vector(self, n, cap, minimum=0):
        size = self.number(n)
        if size > cap:
            raise Invalid("UNSUPPORTED", "TLS vector exceeds policy cap")
        if size < minimum:
            raise Invalid("MALFORMED", "Empty/short TLS vector")
        return self.take(size)

    def done(self):
        if self.pos != len(self.data):
            raise Invalid("MALFORMED", "Unexpected trailing TLS structure bytes")


def numbers(data, width=2, cap=128):
    if len(data) % width or not data:
        raise Invalid("MALFORMED", "Invalid TLS numeric vector")
    if len(data) // width > cap:
        raise Invalid("UNSUPPORTED", "TLS numeric count cap exceeded")
    return [int.from_bytes(data[i : i + width], "big") for i in range(0, len(data), width)]


def fingerprint(hello):
    clean = lambda values: "-".join(str(v) for v in values if v not in GREASE)
    fields = [
        str(hello["legacy_version"]),
        clean(hello["cipher_suites"]),
        clean(hello["extension_ids"]),
    ]
    family = "JA3S" if hello["handshake_type"] == 2 else "JA3"
    if family == "JA3":
        fields += [
            clean(hello.get("supported_groups", [])),
            "-".join(map(str, hello.get("ec_point_formats", []))),
        ]
    canonical = ",".join(fields)
    return {
        "family": family,
        "canonical": canonical,
        "digest": hashlib.md5(canonical.encode("ascii"), usedforsecurity=False).hexdigest(),
        "semantics": "Metadata identifier only; no reputation or malware conclusion",
    }


def hello_body(data, kind):
    r = Reader(data)
    legacy = r.number(2)
    random_bytes = r.take(32)  # Only compare HRR sentinel; never persist random/session values.
    session = r.vector(1, 32)
    result = {
        "handshake_type": kind,
        "legacy_version": legacy,
        "session_id_length": len(session),
        "extension_ids": [],
        "supported_versions": [],
        "supported_groups": [],
        "signature_algorithms": [],
        "ec_point_formats": [],
        "alpn": [],
        "sni": None,
        "sni_status": "not_observed",
        "ja4_status": "NOT_IMPLEMENTED",
    }
    if legacy not in (0x0300, 0x0301, 0x0302, 0x0303):
        raise Invalid("UNSUPPORTED", "Unsupported hello legacy version")
    if kind == 1:
        result["cipher_suites"] = numbers(r.vector(2, MAX_CIPHERS * 2, 2), cap=MAX_CIPHERS)
        result["compression_methods"] = numbers(r.vector(1, 16, 1), width=1, cap=16)
    else:
        result["cipher_suites"] = [r.number(2)]
        result["selected_cipher_suite"] = result["cipher_suites"][0]
        result["compression_methods"] = [r.number(1)]
        result["hello_retry_request"] = random_bytes == HRR_RANDOM
    extension_bytes = r.vector(2, MAX_HANDSHAKE) if r.pos < len(data) else b""
    r.done()
    ext = Reader(extension_bytes)
    while ext.pos < len(extension_bytes):
        if len(result["extension_ids"]) == MAX_EXTENSIONS:
            raise Invalid("UNSUPPORTED", "Extension count limit exceeded")
        identifier = ext.number(2)
        if identifier in result["extension_ids"]:
            raise Invalid("MALFORMED", "Duplicate TLS extension")
        value = ext.vector(2, MAX_EXTENSION)
        result["extension_ids"].append(identifier)
        item = Reader(value)
        if identifier == 0:
            if kind == 2:
                if value:
                    raise Invalid("MALFORMED", "Server SNI acknowledgement must be empty")
            else:
                names = Reader(item.vector(2, 256, 1))
                seen = set()
                while names.pos < len(names.data):
                    if len(seen) >= 1:
                        raise Invalid("UNSUPPORTED", "Only one SNI hostname supported")
                    name_type = names.number(1)
                    hostname = names.vector(2, 253, 1)
                    if name_type != 0 or name_type in seen:
                        raise Invalid("UNSUPPORTED", "Unsupported SNI name type/count")
                    seen.add(name_type)
                    try:
                        text = hostname.decode("ascii").lower()
                    except UnicodeDecodeError as exc:
                        raise Invalid("MALFORMED", "Non-ASCII SNI") from exc
                    labels = text.split(".")
                    if any(
                        not label
                        or len(label) > 63
                        or label[0] == "-"
                        or label[-1] == "-"
                        or any(not (c.isalnum() or c == "-") for c in label)
                        for label in labels
                    ):
                        raise Invalid("MALFORMED", "Invalid SNI hostname")
                    result["sni"], result["sni_status"] = text, "plaintext_observed"
                item.done()
        elif identifier in (10, 13, 50):
            vector = numbers(item.vector(2, MAX_GROUPS * 2, 2), cap=MAX_GROUPS)
            result[
                {
                    10: "supported_groups",
                    13: "signature_algorithms",
                    50: "certificate_signature_algorithms",
                }[identifier]
            ] = vector
            item.done()
        elif identifier == 11:
            result["ec_point_formats"] = numbers(item.vector(1, 32, 1), width=1, cap=32)
            item.done()
        elif identifier == 43:
            result["supported_versions"] = (
                numbers(item.vector(1, 64, 2), cap=32) if kind == 1 else [item.number(2)]
            )
            item.done()
        elif identifier == 16:
            protocols = Reader(item.vector(2, MAX_EXTENSION, 2))
            values = []
            while protocols.pos < len(protocols.data):
                if len(values) == MAX_ALPN:
                    raise Invalid("UNSUPPORTED", "ALPN count limit exceeded")
                value = protocols.vector(1, MAX_ALPN_LENGTH, 1)
                # ALPN is opaque; safe hex for nonprintable values, no guessed decoding.
                values.append(
                    {
                        "value": value.decode("ascii")
                        if all(32 <= b < 127 for b in value)
                        else value.hex(),
                        "encoding": "ascii" if all(32 <= b < 127 for b in value) else "hex",
                    }
                )
            if kind == 2 and len(values) != 1:
                raise Invalid("MALFORMED", "Server ALPN must select exactly one protocol")
            result["alpn"] = values
            item.done()
    if 0xFE0D in result["extension_ids"]:
        result["sni_status"] = (
            "outer_name_only_ech_extension_observed"
            if result["sni"]
            else "unavailable_ech_extension_observed"
        )
    result["selected_version"] = (
        (result["supported_versions"][0] if result["supported_versions"] else legacy)
        if kind == 2
        else None
    )
    result["fingerprint"] = fingerprint(result)
    return result


def parse_records(data):
    """Contiguous prefix only. Incomplete bytes stay in the capped reassembler."""
    pos, records, handshake = 0, [], bytearray()
    try:
        while pos < len(data):
            if len(records) >= MAX_RECORDS:
                raise Invalid("UNSUPPORTED", "TLS record count budget exceeded")
            if len(data) - pos < 5:
                return {"status": "INCOMPLETE", "record_count": len(records)}
            content, version, size = (
                data[pos],
                int.from_bytes(data[pos + 1 : pos + 3], "big"),
                int.from_bytes(data[pos + 3 : pos + 5], "big"),
            )
            if content not in (20, 21, 22, 23) or not 0x0300 <= version <= 0x0303:
                return {
                    "status": "INCOMPLETE",
                    "reason": "No supported record boundary at earliest observed sequence",
                    "record_count": len(records),
                }
            if size == 0 or size > (18432 if content == 23 else MAX_RECORD):
                raise Invalid("MALFORMED", "TLS record length outside supported plaintext bound")
            if content == 23:
                # Header only; ciphertext bytes are never inspected.
                return {
                    "status": "ENCRYPTED_APPLICATION_DATA",
                    "record_count": len(records) + 1,
                    "record_version": version,
                    "record_content_type": content,
                    "declared_record_length": size,
                    "record_complete": len(data) - pos - 5 >= size,
                }
            if len(data) - pos - 5 < size:
                return {"status": "INCOMPLETE", "record_count": len(records)}
            records.append({"content_type": content, "version": version, "length": size})
            if content == 21:
                raise Invalid("UNAVAILABLE", "Alert content not interpreted")
            if content == 20:
                if data[pos + 5 : pos + 5 + size] != b"\x01":
                    raise Invalid("MALFORMED", "Malformed compatibility CCS")
                # Without an earlier visible hello, TLS 1.2 encrypted handshake
                # records cannot be distinguished safely from TLS 1.3 compatibility CCS.
                raise Invalid("UNAVAILABLE", "ChangeCipherSpec boundary; subsequent bytes not interpreted")
            else:
                if len(handshake) + size > MAX_HANDSHAKE + 4:
                    raise Invalid("UNSUPPORTED", "Accumulated handshake limit exceeded")
                handshake.extend(data[pos + 5 : pos + 5 + size])
                if len(handshake) >= 4:
                    kind, length = handshake[0], int.from_bytes(handshake[1:4], "big")
                    if kind not in (1, 2):
                        raise Invalid("UNSUPPORTED", "Only ClientHello and ServerHello are parsed")
                    if length > MAX_HANDSHAKE or length < 35:
                        raise Invalid("MALFORMED", "Invalid/excessive hello length")
                    if len(handshake) >= length + 4:
                        hello = hello_body(bytes(handshake[4 : 4 + length]), kind)
                        return {
                            "status": "COMPLETE",
                            "hello": hello,
                            "record_count": len(records),
                            "records": records,
                            "trailing_handshake_bytes_uninspected": len(handshake) - 4 - length,
                        }
            pos += 5 + size
        return {"status": "INCOMPLETE", "record_count": len(records)}
    except Invalid as exc:
        return {"status": exc.status, "reason": exc.reason, "record_count": len(records)}
