"""Bounded first-hello TCP prefix collector, not a general TCP stack."""

from dataclasses import dataclass, field

from sentinel_net.encrypted.tls import parse_records


@dataclass
class Direction:
    started: float
    base: int | None = None
    extent: int = 0
    data: bytearray = field(default_factory=bytearray)
    present: bytearray = field(default_factory=bytearray)
    result: dict = field(default_factory=lambda: {"status": "INCOMPLETE"})
    records_counted: int = 0
    retransmitted_bytes: int = 0
    out_of_order_segments: int = 0

    def release(self):
        self.data.clear()
        self.present.clear()
        self.extent = 0

    def expire(self):
        if self.result["status"] == "INCOMPLETE":
            self.result = {
                "status": "TRUNCATED",
                "reason": "Capture-time handshake deadline expired",
            }
            self.release()
            return True
        return False

    def feed(self, seq, payload, cap):
        if self.result["status"] != "INCOMPLETE" or not payload:
            return self.result
        if self.base is None:
            self.base = seq
            self.data = bytearray(cap)
            self.present = bytearray(cap)
        offset = ((seq - self.base + (1 << 31)) % (1 << 32)) - (1 << 31)
        if (
            len(payload) > cap
            or abs(offset) > cap
            or max(self.extent, offset + len(payload)) - min(0, offset) > cap
        ):
            self.result = {
                "status": "TRUNCATED",
                "reason": "TCP sequence span exceeds metadata byte cap",
            }
            self.release()
            return self.result
        if offset < 0:
            shift = -offset
            self.data[shift : shift + self.extent] = self.data[: self.extent]
            self.present[shift : shift + self.extent] = self.present[: self.extent]
            self.present[:shift] = bytes(shift)
            self.base = seq
            self.extent += shift
            offset = 0
            self.out_of_order_segments += 1
        elif offset > self.extent:
            self.out_of_order_segments += 1
        for i, byte in enumerate(payload, offset):
            if self.present[i]:
                if self.data[i] != byte:
                    self.result = {
                        "status": "MALFORMED",
                        "reason": "Conflicting TCP overlap; direction discarded",
                    }
                    self.release()
                    return self.result
                self.retransmitted_bytes += 1
            self.data[i] = byte
            self.present[i] = 1
        self.extent = max(self.extent, offset + len(payload))
        contiguous = self.present.find(0, 0, self.extent)
        if contiguous < 0:
            contiguous = self.extent
        self.result = parse_records(bytes(self.data[:contiguous]))
        if self.result["status"] != "INCOMPLETE":
            self.release()
        return self.result
