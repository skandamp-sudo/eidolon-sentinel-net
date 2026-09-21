"""Repository-wide passive security assertions.

These tests verify the fundamental passive/read-only architecture
across ALL source modules. If any of these tests fail, the security
model has been violated.

IMPORTANT: These tests scan actual source code files — no mocking.
"""

import ast
import os
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[2] / "src" / "sentinel_net"


def _python_files() -> list[Path]:
    """Find all .py files under src/sentinel_net/."""
    return sorted(SRC_DIR.rglob("*.py"))


def _read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestPassiveSecurity:
    """Verify no offensive, transmission, or decryption capabilities."""

    @pytest.fixture(scope="class")
    def all_sources(self) -> dict[str, str]:
        return {str(p.relative_to(SRC_DIR)): _read_source(p) for p in _python_files()}

    def test_no_scapy_send_functions(self, all_sources):
        """No module imports scapy send/sendp/sr/sr1.
        
        sniff/AsyncSniffer are allowed ONLY in sensor/capture.py (receive-only capture).
        """
        # Active transmission functions — forbidden everywhere
        active_forbidden = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sendpfast"}
        # sniff is forbidden everywhere EXCEPT sensor/capture.py
        for relpath, source in all_sources.items():
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and "scapy" in node.module:
                    imported = {alias.name for alias in node.names}
                    # Active functions forbidden everywhere
                    violations = imported & active_forbidden
                    assert not violations, (
                        f"{relpath} imports forbidden scapy function(s): {violations}"
                    )
                    # sniff forbidden outside sensor/capture.py
                    if imported & {"sniff", "AsyncSniffer"} and relpath != "sensor/capture.py":
                        pytest.fail(
                            f"{relpath} imports a sniffer — only sensor/capture.py may capture"
                        )

    def test_no_socket_operations(self, all_sources):
        """No module imports socket for network operations."""
        for relpath, source in all_sources.items():
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name != "socket", (
                            f"{relpath} imports socket module"
                        )
                if isinstance(node, ast.ImportFrom) and node.module == "socket":
                    pytest.fail(f"{relpath} imports from socket module")

    def test_no_unsafe_deserialization(self, all_sources):
        """No pickle.load/pickle.loads/eval() in source code."""
        for relpath, source in all_sources.items():
            # Check for pickle.load patterns
            assert "pickle.load(" not in source and "pickle.loads(" not in source, (
                f"{relpath} contains unsafe pickle deserialization"
            )
            # Check for eval() — but not in comments or strings
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "eval":
                        pytest.fail(f"{relpath} contains eval() call")

    def test_no_network_clients(self, all_sources):
        """No HTTP/network client imports in detection or explainability modules."""
        net_modules = {"requests", "urllib", "aiohttp", "httpcore"}
        for relpath, source in all_sources.items():
            if "detection" in relpath or "explainability" in relpath:
                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            assert alias.name not in net_modules, (
                                f"{relpath} imports network module {alias.name}"
                            )
                    if isinstance(node, ast.ImportFrom) and node.module:
                        base = node.module.split(".")[0]
                        assert base not in net_modules, (
                            f"{relpath} imports from network module {node.module}"
                        )

    def test_no_decryption_code(self, all_sources):
        """No TLS/QUIC decryption in detection or explainability."""
        forbidden_patterns = [
            "ssl.unwrap", "tls_key", "ssl_context", ".decrypt(", "QUIC_decrypt"
        ]
        for relpath, source in all_sources.items():
            if "detection" in relpath or "explainability" in relpath:
                for pattern in forbidden_patterns:
                    assert pattern not in source, (
                        f"{relpath} contains decryption pattern: {pattern}"
                    )

    def test_no_docker_files(self):
        """No Docker-related files in the repository."""
        repo_root = SRC_DIR.parents[1]
        for name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"):
            assert not (repo_root / name).exists(), f"Found forbidden Docker file: {name}"

    def test_no_exec_calls(self, all_sources):
        """No exec() calls in source code."""
        for relpath, source in all_sources.items():
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "exec":
                        pytest.fail(f"{relpath} contains exec() call")


class TestFeatureSchemaConsistency:
    """Verify 52-feature schema is the single source of truth."""

    def test_canonical_count(self):
        from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT
        assert len(FEATURE_SCHEMA) == FEATURE_COUNT == 52

    def test_unique_names(self):
        from sentinel_net.features.schema import FEATURE_SCHEMA
        assert len(set(FEATURE_SCHEMA)) == len(FEATURE_SCHEMA)

    def test_deterministic_ordering(self):
        from sentinel_net.features.schema import FEATURE_SCHEMA
        assert isinstance(FEATURE_SCHEMA, tuple)  # Immutable
        # Import twice to verify consistency
        from sentinel_net.features.schema import FEATURE_SCHEMA as SCHEMA2
        assert FEATURE_SCHEMA == SCHEMA2

    def test_feature_vector_dimensionality(self):
        from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT
        from sentinel_net.models.types import FeatureVector, FlowKey
        fk = FlowKey("1.1.1.1", "2.2.2.2", 1, 80, 6)
        values = [float(i) for i in range(FEATURE_COUNT)]
        features = {name: float(i) for i, name in enumerate(FEATURE_SCHEMA)}
        fv = FeatureVector(
            flow_key=fk, timestamp=0.0, features=features,
            feature_names=list(FEATURE_SCHEMA), values=values,
        )
        assert len(fv.values) == FEATURE_COUNT
        assert len(fv.feature_names) == FEATURE_COUNT

    def test_audit_covers_all_features(self):
        from sentinel_net.features.schema import FEATURE_SCHEMA
        from sentinel_net.detection.audit import FEATURE_AUDIT
        assert set(FEATURE_AUDIT.keys()) == set(FEATURE_SCHEMA)


class TestSensorSecurity:
    """Phase 5: Verify sensor captures only — no transmission, no shell execution."""

    def test_capture_no_subprocess(self):
        """capture.py must not use subprocess for filter/interface config."""
        path = SRC_DIR / "sensor" / "capture.py"
        if not path.exists():
            pytest.skip("capture.py not yet created")
        source = _read_source(path)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "subprocess", "capture.py imports subprocess"
                    assert alias.name != "os", "capture.py imports os"
            if isinstance(node, ast.ImportFrom):
                assert node.module not in ("subprocess", "os.system"), (
                    f"capture.py imports from {node.module}"
                )

    def test_capture_has_no_transmit_calls_or_socket_factories(self):
        tree = ast.parse(_read_source(SRC_DIR / "sensor" / "capture.py"))
        forbidden = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sendpfast",
                     "L2socket", "L3socket", "l2socket", "l3socket"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', '')
                assert name not in forbidden, f"Capture calls transmit-capable function {name}"

    def test_capture_validates_bpf_filter(self):
        """BPF filter validation rejects shell metacharacters."""
        from sentinel_net.sensor.capture import PassiveCaptureSource

        dangerous = ["tcp; rm -rf /", "x | cat", "x `id`", "$(whoami)", "x > /tmp/x"]
        for filt in dangerous:
            with pytest.raises(ValueError):
                PassiveCaptureSource._validate_filter(filt)

    def test_capture_only_imports_sniff(self):
        """capture.py only imports sniff from scapy, not send functions."""
        path = SRC_DIR / "sensor" / "capture.py"
        if not path.exists():
            pytest.skip("capture.py not yet created")
        source = _read_source(path)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "scapy" in node.module:
                imported = {alias.name for alias in node.names}
                forbidden = {"send", "sendp", "sr", "sr1"}
                violations = imported & forbidden
                assert not violations, f"capture.py imports {violations}"


class TestAPISecurity:
    """Phase 5: Verify API authentication uses constant-time comparison."""

    def test_auth_uses_hmac(self):
        """auth.py must use hmac.compare_digest for key comparison."""
        path = SRC_DIR / "api" / "auth.py"
        source = _read_source(path)
        tree = ast.parse(source)

        found_hmac = False
        found_compare = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "hmac":
                        found_hmac = True
            if isinstance(node, ast.Attribute) and node.attr == "compare_digest":
                found_compare = True

        assert found_hmac, "auth.py must import hmac"
        assert found_compare, "auth.py must use hmac.compare_digest()"

    def test_auth_no_credential_logging(self):
        """auth.py must not log credential values."""
        path = SRC_DIR / "api" / "auth.py"
        source = _read_source(path)
        # Ensure the actual key values are never in format strings
        assert "provided_key}" not in source, "auth.py may log provided key"
        assert "expected_key}" not in source, "auth.py may log expected key"
        assert "api_key}" not in source, "auth.py may log api_key"

    def test_websocket_uses_hmac(self):
        """websocket.py must use hmac.compare_digest."""
        path = SRC_DIR / "api" / "routes" / "websocket.py"
        if not path.exists():
            pytest.skip("websocket.py not yet created")
        source = _read_source(path)
        assert "hmac.compare_digest" in source, "websocket.py must use hmac.compare_digest"

    def test_websocket_no_credential_logging(self):
        """websocket.py must not log API key values."""
        path = SRC_DIR / "api" / "routes" / "websocket.py"
        if not path.exists():
            pytest.skip("websocket.py not yet created")
        source = _read_source(path)
        assert "api_key}" not in source
        assert "provided}" not in source

    def test_no_sql_fstrings_in_database(self):
        """database.py must not use f-strings for SQL queries."""
        path = SRC_DIR / "storage" / "database.py"
        source = _read_source(path)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                    for arg in node.args:
                        assert not isinstance(arg, ast.JoinedStr), (
                            "database.py uses f-string in SQL execute() — use parameterized queries"
                        )
