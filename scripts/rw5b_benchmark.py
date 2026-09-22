"""Reproducible receive-free, complete-path operational benchmark.

PYTHONPATH=src .venv/bin/python scripts/rw5b_benchmark.py --registry PATH \
  --model runtime/1.0.0 --seconds 30 --output /tmp/rw5b-measured

Run each workload in a fresh process. Packet templates are deterministic PCAPs,
never transmitted. E uses authenticated loopback WebSocket output only. Models
are loaded from an already approved frozen bundle; no runtime training.
"""

import argparse
import asyncio
import hashlib
import json
import os
import queue
import resource
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, Raw, DNS, DNSQR
from sentinel_net.dns.config import DNSConfig
from sentinel_net.encrypted.config import EncryptedConfig
from scapy.utils import PcapWriter

from sentinel_net.config import SentinelConfig
from sentinel_net.intelligence.config import IntelligenceConfig
from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from sentinel_net.sensor.retention import RetentionWorker
from sentinel_net.sensor.runtime_model import load_runtime_model
from sentinel_net.sensor.sources import LiveCaptureSource, PcapReplaySource, ReadKind, SourceRead
from sentinel_net.storage.database import Database

WORKLOADS = [
    "A_mixed",
    "B_cardinality",
    "C_long_tuple",
    "D_burst",
    "E_slow_websocket",
    "F_slow_storage",
    "G_dns_heavy",
    "H_tls_heavy",
    "I_quic_headers",
]


def rss():
    # macOS ps reports resident KiB; separate from getrusage peak (bytes on macOS).
    return (
        int(
            subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())], text=True).strip()
        )
        * 1024
    )


def templates(path, workload):
    packets = []
    with PcapWriter(str(path), sync=True) as writer:
        for i in range(1024):
            port = 10000 + (i if workload.startswith("B") else i // 4 % 32)
            if workload.startswith("C"):
                port = 10000
            ether = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            layer = TCP(
                sport=port,
                dport=443,
                flags="A" if workload[0] in "BC" else ("R" if i % 4 == 3 else "A"),
            )
            if workload.startswith("A") and i % 8 < 4:
                layer = UDP(sport=port, dport=53000)
            pkt = (
                ether
                / IP(src="192.0.2.1", dst="192.0.2.2")
                / layer
                / Raw(bytes([i % 251]) * (32 + i % 128))
            )
            if workload.startswith("G"):
                pair = i // 2
                label = hashlib.sha256(f"safe-dns-fixture-{pair}".encode()).hexdigest()[:48]
                parent = "service.test" if pair % 2 else f"parent{pair % 64}.test"
                client = f"192.0.2.{pair % 8 + 1}"
                reverse = bool(i % 2)
                dns = DNS(id=pair, qr=int(reverse), rcode=3 if reverse and pair % 3 == 0 else 0,
                          qd=DNSQR(qname=f"{label}.{parent}", qtype=16 if pair % 4 == 0 else 1))
                pkt = ether / IP(src="198.51.100.53" if reverse else client, dst=client if reverse else "198.51.100.53") / UDP(sport=53 if reverse else 10000 + pair % 64, dport=10000 + pair % 64 if reverse else 53) / dns
            if workload.startswith("H"):
                from f5_fixtures import client_hello, server_hello
                client = client_hello()
                port = 10000 + i // 4
                phase = i % 4
                reverse = phase == 2
                body = client[:40] if phase == 0 else client[40:] if phase == 1 else server_hello() if phase == 2 else b""
                seq = 1000 if phase == 0 else 1041 if phase == 1 else 2000 if phase == 2 else 1001 + len(client)
                pkt = ether / IP(src="198.51.100.1" if reverse else "192.0.2.1", dst="192.0.2.1" if reverse else "198.51.100.1") / TCP(sport=443 if reverse else port, dport=port if reverse else 443, seq=seq, flags="S" if phase == 0 else "R" if phase == 3 else "PA") / Raw(body)
            if workload.startswith("I"):
                from f5_fixtures import quic_initial
                body = quic_initial(dcid=i.to_bytes(8,"big"), packet_type=0 if i % 2 == 0 else 2)
                pkt = ether / IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=10000 + i % 256, dport=443) / Raw(body)
            pkt.time = 1700000000 + i * 0.001
            writer.write(pkt)
            packets.append(extract_raw_packet(pkt))
    return packets


class CyclicReplay:
    """Replay the same historic file until a monotonic duration ends."""

    from sentinel_net.sensor.sources import SourceMode

    mode = SourceMode.REPLAY

    def __init__(self, path, metrics, seconds):
        self.path, self.metrics, self.seconds = path, metrics, seconds
        self.source = None
        self.stopped = threading.Event()
        self.input_bytes = 0

    @property
    def provenance(self):
        return {"source_mode": "REPLAY", "replay_file_identifier": "synthetic-benchmark"}

    def start(self):
        self.deadline = time.monotonic() + self.seconds
        self.source = PcapReplaySource(self.path, self.metrics)
        self.source.start()

    def read(self, timeout=0.1):
        if self.stopped.is_set() or time.monotonic() >= self.deadline:
            return SourceRead(ReadKind.EOF)
        item = self.source.read(timeout)
        if item.kind == ReadKind.EOF:
            self.source.stop()
            self.source = PcapReplaySource(self.path, self.metrics)
            self.source.start()
            item = self.source.read(timeout)
        if item.packet:
            self.input_bytes += item.packet.capture_length
        return item

    def acknowledge(self):
        pass

    def stop(self):
        self.stopped.set()
        if self.source:
            self.source.stop()


class BurstCapture:
    def __init__(self, packets, metrics, seconds, templates):
        self.packets, self.metrics, self.seconds, self.templates = (
            packets,
            metrics,
            seconds,
            templates,
        )
        self.halt = threading.Event()
        self.input_bytes = 0

    def start(self):
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        deadline = time.monotonic() + self.seconds
        i = 0
        while time.monotonic() < deadline and not self.halt.is_set():
            for _ in range(256):
                packet = self.templates[i % len(self.templates)]
                i += 1
                self.input_bytes += packet.capture_length
                self.metrics.increment("packets_observed")
                try:
                    self.packets.put_nowait(packet)
                    self.metrics.observe_peak("capture_queue_peak", self.packets.qsize())
                except queue.Full:
                    self.metrics.increment("packets_dropped")
            self.halt.wait(0.02)

    def stop(self):
        self.halt.set()
        self.thread.join()


async def slow_websocket(bus, metrics, db):
    """Actual loopback transport, small send buffer and a slow authenticated reader."""
    import uvicorn
    import websockets
    from fastapi import FastAPI

    from sentinel_net.api.routes.websocket import router
    from sentinel_net.config import get_config

    app = FastAPI()
    app.include_router(router)
    app.state.event_bus, app.state.sensor_metrics = bus, metrics
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, log_level="error", ws_max_queue=1, timeout_graceful_shutdown=1)
    )
    server.install_signal_handlers = lambda: None
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    client = await websockets.connect(
        f"ws://127.0.0.1:{port}/api/v1/ws/events", max_queue=1, close_timeout=0.2
    )
    await client.send(json.dumps({"type": "auth", "api_key": get_config().api_key}))
    assert json.loads(await client.recv())["type"] == "auth_ok"
    reads = [0]

    async def consume():
        try:
            while True:
                await asyncio.sleep(0.25)
                if json.loads(await client.recv())["type"] == "event":
                    reads[0] += 1
        except websockets.ConnectionClosed:
            pass

    consumer = asyncio.create_task(consume())

    async def stop():
        consumer.cancel()
        await asyncio.gather(consumer, return_exceptions=True)
        await client.close()
        server.should_exit = True
        await task
        return reads[0]

    return stop


async def run(args):
    out = args.output / args.workload
    out.mkdir(parents=True, exist_ok=False)
    pcap = out / "workload.pcap"
    packet_templates = templates(pcap, args.workload)
    model = load_runtime_model(args.model, registry=args.registry)
    metrics = SensorMetrics()
    initial = rss()
    db = Database(out / "events.db")
    await db.initialize()
    pipeline = None
    retention = None
    try:
        config = SentinelConfig(
            intelligence=IntelligenceConfig(enabled=not args.intelligence_disabled),
            dns=DNSConfig(enabled=not args.dns_disabled),
            encrypted=EncryptedConfig(enabled=not args.encrypted_disabled, max_connections=64),
            database_path=out / "events.db",
            max_active_flows=64,
            capture_queue_size=128,
            event_queue_size=16,
            max_subscribers=4,
            max_events=500,
            retention_hours=168,
            cleanup_interval_sec=1,
            cleanup_batch_rows=50,
            cleanup_cycle_rows=200,
        )
        bus = EventBus(config.event_queue_size, config.max_subscribers)
        retention = RetentionWorker(db, config, metrics)
        if args.workload.startswith("F"):
            store = db.store_event

            async def delayed(event):
                await asyncio.sleep(0.02)  # explicit, bounded injected persistence latency
                return await store(event)

            db.store_event = delayed
        capture = None
        if args.workload.startswith("D"):
            packets = queue.Queue(maxsize=config.capture_queue_size)
            capture = BurstCapture(packets, metrics, args.seconds, packet_templates)
            source = LiveCaptureSource(
                packets, metrics, capture=capture, clock=lambda: 1700000001.024
            )
        else:
            source = CyclicReplay(pcap, metrics, args.seconds)
        ws_stop = await slow_websocket(bus, metrics, db) if args.workload.startswith("E") else None
        subscriber = None if ws_stop else bus.subscribe("benchmark-output")
        initial = rss()
        db_initial = db.storage_sizes()
        peak_rss, peak_db, peak_wal = initial, db_initial["database_bytes"], db_initial["wal_bytes"]
        windows = []
        stop_sampling = asyncio.Event()
        pipeline = PacketProcessingPipeline(
            config, source, bus, metrics, model, db=db, event_loop=asyncio.get_running_loop()
        )

        async def drain():
            while not stop_sampling.is_set():
                if subscriber:
                    try:
                        while True:
                            subscriber.get_nowait()
                            metrics.increment("events_delivered")
                    except queue.Empty:
                        pass
                await asyncio.sleep(0.01)

        async def sample():
            nonlocal peak_rss, peak_db, peak_wal
            while not stop_sampling.is_set():
                current = rss()
                sizes = db.storage_sizes()
                peak_rss = max(peak_rss, current)
                peak_db, peak_wal = (
                    max(peak_db, sizes["database_bytes"]),
                    max(peak_wal, sizes["wal_bytes"]),
                )
                if len(windows) < 1000:
                    windows.append(
                        {
                            "elapsed_sec": time.monotonic() - started,
                            "rss_bytes": current,
                            "metrics": metrics.snapshot(),
                            "storage": sizes,
                            "latency_ms": metrics.latency_snapshot(),
                        }
                    )
                await asyncio.sleep(0.5)

        started_utc = datetime.now(UTC).isoformat()
        started = time.monotonic()
        retention.start()
        drain_task, sampler = asyncio.create_task(drain()), asyncio.create_task(sample())
        pipeline.start()
        if capture:
            await asyncio.to_thread(capture.thread.join)
            await pipeline.astop()
        else:
            await pipeline.wait()
        elapsed = time.monotonic() - started
        await asyncio.sleep(0.02)
        stop_sampling.set()
        await asyncio.gather(drain_task, sampler)
        await retention.stop()
        ws_reads = await ws_stop() if ws_stop else None
        metrics.increment("events_dropped", bus.shutdown())
        final = rss()
        input_bytes = capture.input_bytes if capture else source.input_bytes
        # Processed bytes are summed at parser/aggregation boundary (includes Ethernet).
        result = {
            "source_sha256": {
                str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted([*Path('src/sentinel_net').rglob('*.py'), Path('scripts/f5_fixtures.py'), Path(__file__).relative_to(Path.cwd())])
            },
            "workload": args.workload,
            "started_at": started_utc,
            "ended_at": datetime.now(UTC).isoformat(),
            "target_duration_sec": args.seconds,
            "elapsed_sec_including_drain": elapsed,
            "input_packets": metrics.packets_observed,
            "processed_packets": metrics.packets_processed,
            "input_bytes": input_bytes,
            "processed_bytes": metrics.bytes_processed,
            "completed_flows": metrics.flows_completed,
            "events": metrics.events_persisted,
            "packets_per_sec": metrics.packets_processed / elapsed,
            "flows_per_sec": metrics.flows_completed / elapsed,
            "processing_mbps": metrics.bytes_processed * 8 / elapsed / 1e6,
            "latency_ms": metrics.latency_snapshot(),
            "metrics": metrics.snapshot(),
            "rss_bytes": {
                "initial": initial,
                "sampled_peak": max(peak_rss, final),
                "final": final,
                "process_lifetime_peak": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                * (1 if sys.platform == "darwin" else 1024),
            },
            "storage_bytes": {
                "initial": db_initial,
                "peak_database": peak_db,
                "peak_wal": peak_wal,
                "final_before_close": db.storage_sizes(),
            },
            "subscriber_queue_peak": bus.queue_peak,
            "subscriber_peak": bus.subscriber_peak,
            "websocket_client_events_read": ws_reads,
            "model_identity": model.deployment_identity,
            "workload_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
            "configuration": config.model_dump(mode="json", exclude={"api_key"}),
            "windows": windows,
            "retained_events": await db.get_event_count(),
            "retained_flows": await db.get_flow_count(),
            "notes": [
                "Synthetic operational QA only; no accuracy claim.",
                "Latency percentiles retain the most recent 4096 observations per stage; windows sampled every 0.5 s.",
                "Inference excludes measured evidence hook; inclusive inference also reported.",
                "Packet processing includes synchronous downstream backpressure for flows finalized by that packet.",
                "Historical PCAP timestamps are not latency clocks.",
                "Each PCAP repeats without timestamp rewriting; exact v2.0.0 segmentation remains unchanged.",
            ],
        }
        await db.close()
        (out / "result.json").write_text(json.dumps(result, indent=2))
        print(
            json.dumps(
                {
                    k: result[k]
                    for k in [
                        "workload",
                        "processed_packets",
                        "completed_flows",
                        "packets_per_sec",
                        "flows_per_sec",
                        "processing_mbps",
                    ]
                }
            ),
            flush=True,
        )
    finally:
        if pipeline and pipeline.alive:
            await pipeline.astop()
        if retention:
            await retention.stop()
        await db.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--registry", type=Path, required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--seconds", type=float, default=30)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--workload", choices=WORKLOADS)
    p.add_argument("--intelligence-disabled", action="store_true", help="Same-runtime operational comparison with streaming intelligence disabled")
    p.add_argument("--dns-disabled", action="store_true", help="F3 enabled with DNS intelligence disabled comparison")
    p.add_argument("--encrypted-disabled", action="store_true", help="F3/F4 enabled, F5 metadata disabled control")
    args = p.parse_args()
    if args.seconds <= 0 or args.seconds > 3600:
        p.error("duration must be in (0,3600] seconds")
    if args.workload:
        asyncio.run(run(args))
    else:
        args.output.mkdir(parents=True, exist_ok=True)
        for workload in WORKLOADS:
            subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--registry",
                    str(args.registry),
                    "--model",
                    args.model,
                    "--seconds",
                    str(args.seconds),
                    "--output",
                    str(args.output),
                    "--workload",
                    workload,
                    *(["--intelligence-disabled"] if args.intelligence_disabled else []),
                    *(["--dns-disabled"] if args.dns_disabled else []),
                    *(["--encrypted-disabled"] if args.encrypted_disabled else []),
                ],
                check=True,
            )
        results = [json.loads((args.output / w / "result.json").read_text()) for w in WORKLOADS]
        (args.output / "benchmark.json").write_text(
            json.dumps({"phase": "SIH-F5", "encrypted_enabled": not args.encrypted_disabled, "dns_enabled": not args.dns_disabled, "intelligence_enabled": not args.intelligence_disabled, "results": results}, indent=2)
        )


if __name__ == "__main__":
    main()
