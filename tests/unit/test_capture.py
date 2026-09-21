"""Tests for sensor capture, lifecycle, metrics, and pipeline.

Uses mock capture source — no root/pcap permissions required.
"""

from __future__ import annotations

import queue
import threading
import time

import pytest

from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.lifecycle import SensorState, SensorLifecycle


class TestSensorMetrics:
    def test_initial_values(self):
        m = SensorMetrics()
        snap = m.snapshot()
        assert snap["packets_observed"] == 0
        assert snap["packets_parsed"] == 0

    def test_increment(self):
        m = SensorMetrics()
        m.increment("packets_observed")
        m.increment("packets_observed", 5)
        assert m.snapshot()["packets_observed"] == 6

    def test_set_gauge(self):
        m = SensorMetrics()
        m.set_gauge("flows_active", 42)
        assert m.snapshot()["flows_active"] == 42

    def test_uptime(self):
        m = SensorMetrics()
        time.sleep(0.05)
        assert m.uptime_sec >= 0.04

    def test_thread_safety(self):
        m = SensorMetrics()

        def inc():
            for _ in range(100):
                m.increment("packets_observed")

        threads = [threading.Thread(target=inc) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert m.snapshot()["packets_observed"] == 400

    def test_invalid_field_raises(self):
        m = SensorMetrics()
        with pytest.raises((ValueError, KeyError)):
            m.increment("nonexistent_field")


class TestSensorLifecycle:
    def test_initial_state(self):
        lc = SensorLifecycle()
        assert lc.state == SensorState.STOPPED

    def test_valid_transition(self):
        lc = SensorLifecycle()
        lc.transition(SensorState.STARTING)
        assert lc.state == SensorState.STARTING
        lc.transition(SensorState.RUNNING)
        assert lc.state == SensorState.RUNNING

    def test_invalid_transition_raises(self):
        lc = SensorLifecycle()
        with pytest.raises(ValueError):
            lc.transition(SensorState.RUNNING)  # STOPPED → RUNNING invalid

    def test_full_lifecycle(self):
        lc = SensorLifecycle()
        lc.transition(SensorState.STARTING)
        lc.transition(SensorState.RUNNING)
        lc.transition(SensorState.STOPPING)
        lc.transition(SensorState.STOPPED)
        assert lc.state == SensorState.STOPPED

    def test_error_from_running(self):
        lc = SensorLifecycle()
        lc.transition(SensorState.STARTING)
        lc.transition(SensorState.RUNNING)
        lc.transition(SensorState.ERROR)
        assert lc.state == SensorState.ERROR

    def test_recovery_from_error(self):
        lc = SensorLifecycle()
        lc.transition(SensorState.STARTING)
        lc.transition(SensorState.ERROR)
        lc.transition(SensorState.STARTING)  # Retry
        assert lc.state == SensorState.STARTING

    def test_shutdown_request(self):
        lc = SensorLifecycle()
        assert not lc.shutdown_requested
        lc.request_shutdown()
        assert lc.shutdown_requested

    def test_thread_safe_transitions(self):
        lc = SensorLifecycle()
        lc.transition(SensorState.STARTING)
        lc.transition(SensorState.RUNNING)

        errors = []

        def try_transition():
            try:
                lc.transition(SensorState.STOPPING)
            except ValueError:
                errors.append("already transitioned")

        t1 = threading.Thread(target=try_transition)
        t2 = threading.Thread(target=try_transition)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        # One should succeed, one should fail
        assert lc.state in (SensorState.STOPPING,)
        assert len(errors) == 1


class TestCaptureConfig:
    def test_filter_validation_rejects_shell_injection(self):
        from sentinel_net.sensor.capture import PassiveCaptureSource
        dangerous = ["tcp; rm -rf /", "tcp | cat", "tcp `id`", "tcp $(whoami)", "tcp > /tmp/x"]
        for filt in dangerous:
            with pytest.raises(ValueError, match="filter"):
                PassiveCaptureSource._validate_filter(filt)

    def test_filter_validation_accepts_valid_bpf(self):
        from sentinel_net.sensor.capture import PassiveCaptureSource
        valid = ["tcp", "tcp port 80", "host 10.0.0.1", "tcp and port 443", "udp and not port 53", ""]
        for filt in valid:
            PassiveCaptureSource._validate_filter(filt)  # Should not raise


class TestMockCapture:
    def test_mock_delivers_packets(self):
        from sentinel_net.sensor.capture import MockCaptureSource
        from sentinel_net.models.types import ParsedPacket

        packets = [
            ParsedPacket(
                timestamp=time.time(), src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=1234, dst_port=80, protocol=6, protocol_name="TCP",
                ip_version=4, ttl=64, ip_total_length=100,
                tcp_flags=0x02, tcp_window=65535, tcp_seq=1, tcp_ack_num=0,
                payload_size=50, payload_entropy=3.5,
            )
        ]

        pkt_queue = queue.Queue(maxsize=100)
        m = SensorMetrics()
        mock = MockCaptureSource(packets=packets, packet_queue=pkt_queue, metrics=m)
        mock.start()
        mock.stop()
        assert pkt_queue.qsize() == 1

    def test_mock_bounded_queue(self):
        from sentinel_net.sensor.capture import MockCaptureSource
        from sentinel_net.models.types import ParsedPacket

        pkt = ParsedPacket(
            timestamp=time.time(), src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol=6, protocol_name="TCP",
            ip_version=4, ttl=64, ip_total_length=40,
            tcp_flags=None, tcp_window=None, tcp_seq=None, tcp_ack_num=None,
            payload_size=0, payload_entropy=0.0,
        )
        packets = [pkt] * 10
        pkt_queue = queue.Queue(maxsize=3)
        m = SensorMetrics()
        mock = MockCaptureSource(packets=packets, packet_queue=pkt_queue, metrics=m)
        mock.start()
        mock.stop()
        assert pkt_queue.qsize() == 3
        assert m.snapshot()["packets_dropped"] >= 7
