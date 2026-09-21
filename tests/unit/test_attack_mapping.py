"""Tests for MITRE ATT&CK mapping."""

import pytest
from sentinel_net.explainability.attack_mapping import ATTACKMapping, ATTACKMapper


class TestATTACKMapping:
    def test_create_mapping(self):
        m = ATTACKMapping(
            technique_id="T1498", technique_name="Network Denial of Service",
            tactic="Impact", rationale="High packet rate",
            applicability="high", qualification="possible",
        )
        assert m.technique_id == "T1498"
        assert m.qualification == "possible"

    def test_invalid_qualification_raises(self):
        with pytest.raises(ValueError, match="qualification"):
            ATTACKMapping(
                technique_id="T1498", technique_name="Test",
                tactic="Impact", rationale="Test",
                applicability="high", qualification="confirmed",
            )

    def test_valid_qualifications(self):
        for qual in ("possible", "likely", "observed indicators consistent with"):
            m = ATTACKMapping(
                technique_id="T1498", technique_name="Test",
                tactic="Impact", rationale="Test",
                applicability="high", qualification=qual,
            )
            assert m.qualification == qual

    def test_to_dict_roundtrip(self):
        m = ATTACKMapping(
            technique_id="T1071", technique_name="Application Layer Protocol",
            tactic="Command and Control", rationale="Beaconing patterns",
            applicability="high", qualification="likely",
        )
        d = m.to_dict()
        m2 = ATTACKMapping.from_dict(d)
        assert m2 == m


class TestATTACKMapper:
    @pytest.fixture
    def mapper(self):
        return ATTACKMapper()

    def test_ddos_mapping(self, mapper):
        mappings = mapper.map("ddos", confidence=0.9)
        assert len(mappings) > 0
        ids = [m.technique_id for m in mappings]
        assert "T1498" in ids

    def test_c2_mapping(self, mapper):
        mappings = mapper.map("c2", confidence=0.7)
        assert len(mappings) > 0
        ids = [m.technique_id for m in mappings]
        assert "T1071" in ids

    def test_reconnaissance_mapping(self, mapper):
        mappings = mapper.map("reconnaissance")
        assert len(mappings) > 0

    def test_brute_force_mapping(self, mapper):
        mappings = mapper.map("brute_force")
        assert len(mappings) > 0
        assert mappings[0].technique_id == "T1110"

    def test_benign_returns_empty(self, mapper):
        assert mapper.map("benign") == []

    def test_unknown_returns_empty(self, mapper):
        assert mapper.map("unknown") == []

    def test_unsupported_returns_empty(self, mapper):
        assert mapper.map("unsupported") == []

    def test_nonexistent_type_returns_empty(self, mapper):
        assert mapper.map("alien_invasion") == []

    def test_high_confidence_likely(self, mapper):
        mappings = mapper.map("ddos", confidence=0.9)
        assert all(m.qualification == "likely" for m in mappings)

    def test_medium_confidence_consistent(self, mapper):
        mappings = mapper.map("ddos", confidence=0.6)
        assert all(m.qualification == "observed indicators consistent with" for m in mappings)

    def test_low_confidence_possible(self, mapper):
        mappings = mapper.map("ddos", confidence=0.3)
        assert all(m.qualification == "possible" for m in mappings)

    def test_supported_threat_types(self, mapper):
        types = mapper.supported_threat_types
        assert "ddos" in types
        assert "c2" in types
        assert "reconnaissance" in types

    def test_custom_mapping_table(self):
        custom = {"custom_threat": [{
            "technique_id": "T9999", "technique_name": "Custom",
            "tactic": "Custom", "rationale": "Test",
            "applicability": "high",
        }]}
        mapper = ATTACKMapper(mapping_table=custom)
        mappings = mapper.map("custom_threat")
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T9999"
