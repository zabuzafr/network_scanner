"""Tests for classifier rules and engine."""

import pytest
from pathlib import Path

from classifier.rules import Match, Rule, RuleSet, load_rules_from_yaml, load_rules_from_dict
from classifier.engine import ClassificationEngine, create_engine_from_yaml
from classifier.cves import detect_cves


class TestMatch:
    """Test Match condition."""

    def test_match_mac_prefix(self):
        """Test oui matching."""
        m = Match(oui="AA:BB:CC")
        host = {"mac": "aa:bb:cc:11:22:33"}
        assert m.matches_host(host)

    def test_match_mac_regex(self):
        """Test mac_regex matching."""
        m = Match(mac_regex=r"^AA:BB:CC:\d{2}:\d{2}:\d{2}$", hostname_regex=".*test.*")
        host = {"hostname": "myhost-test.local"}
        assert m.matches_host(host)

    def test_match_port(self):
        """Test port matching."""
        m = Match(port=80)
        host = {"port": 80}
        assert m.matches_host(host)

    def test_match_os_guess(self):
        """Test os_guess matching."""
        m = Match(os_guess="Linux")
        host = {"os_guess": "Linux/macOS/Unix (TTL≈64)"}
        assert m.matches_host(host)

    def test_no_match(self):
        """Test no match condition."""
        m = Match(vendor="Cisco")
        host = {"vendor": "Apple"}
        assert not m.matches_host(host)


class TestRule:
    """Test Rule."""

    def test_rule_matches_all_conditions(self):
        """Rule matches only if all Match conditions match."""
        rule = Rule(
            name="test_rule",
            category="network",
            matches=[
                Match(oui="AA:BB:CC"),
                Match(port=443)
            ]
        )
        host = {"mac": "aa:bb:cc:11:22:33", "port": 443}
        assert rule.matches_host(host)

    def test_rule_misses_one_condition(self):
        """Rule does not match if one condition fails."""
        rule = Rule(
            name="test_rule",
            category="network",
            matches=[
                Match(oui="AA:BB:CC"),
                Match(port=80)
            ]
        )
        host = {"mac": "aa:bb:cc:11:22:33", "port": 443}
        assert not rule.matches_host(host)


class TestRuleSet:
    """Test RuleSet."""

    def test_classify_host_priority(self):
        """Rules sorted by priority, higher first."""
        ruleset = RuleSet(rules=[
            Rule(name="low", category="low", matches=[Match(os_guess="test")], priority=1),
            Rule(name="high", category="high", matches=[Match(os_guess="test")], priority=10)
        ])
        host = {"os_guess": "test"}
        results = ruleset.classify_host(host)
        assert results[0]["rule_name"] == "high"
        assert results[1]["rule_name"] == "low"


class TestLoadRules:
    """Test YAML rule loading."""

    def test_load_from_yaml(self):
        """Load rules from YAML file."""
        yaml_path = str(Path(__file__).parent.parent / "config" / "rules.yaml")
        ruleset = load_rules_from_yaml(yaml_path)
        assert len(ruleset.rules) > 0

    def test_load_from_dict(self):
        """Load rules from dictionary."""
        data = {
            "version": "1.0",
            "rules": [
                {
                    "name": "test",
                    "category": "test",
                    "matches": []
                }
            ]
        }
        ruleset = load_rules_from_dict(data)
        assert len(ruleset.rules) == 1


class TestClassificationEngine:
    """Test ClassificationEngine."""

    def test_classify_host(self):
        """Classify single host."""
        ruleset = RuleSet(rules=[
            Rule(name="web", category="server", matches=[Match(port=80)], priority=1)
        ])
        engine = ClassificationEngine(ruleset)
        host = {"ip": "10.0.0.1", "port": 80}
        results = engine.classify_host(host)
        assert len(results) == 1
        assert results[0]["category"] == "server"

    def test_classify_hosts_batch(self):
        """Classify multiple hosts."""
        ruleset = RuleSet(rules=[
            Rule(name="device", category="iot", matches=[Match(os_guess="Linux")], priority=1)
        ])
        engine = ClassificationEngine(ruleset)
        hosts = [
            {"ip": "10.0.0.1", "os_guess": "Linux"},
            {"ip": "10.0.0.2", "os_guess": "Windows"}
        ]
        results = engine.classify_hosts(hosts)
        assert len(results["10.0.0.1"]) == 1
        assert len(results["10.0.0.2"]) == 0

    def test_get_summary(self):
        """Get classification summary."""
        ruleset = RuleSet(rules=[
            Rule(name="a", category="server", matches=[Match(os_guess="test")], priority=1),
            Rule(name="b", category="iot", matches=[Match(os_guess="test")], priority=1)
        ])
        engine = ClassificationEngine(ruleset)
        host = {"os_guess": "test"}
        engine.classify_host(host)
        summary = engine.get_classification_summary()
        assert summary["server"] == 1
        assert summary["iot"] == 1

    def test_create_engine_from_yaml(self):
        """Create engine from YAML file."""
        yaml_path = str(Path(__file__).parent.parent / "config" / "rules.yaml")
        engine = create_engine_from_yaml(yaml_path)
        assert isinstance(engine, ClassificationEngine)
        assert len(engine.ruleset.rules) > 0


class TestDetectCves:
    """Test CVE signature detection (classifier/cves.py)."""

    def test_mqtt_ports(self):
        """MQTT broker ports yield the 3 Mosquitto CVEs."""
        result = detect_cves({"open_ports": [1883, 8883]})
        cve_ids = {r["cve"] for r in result}
        assert cve_ids == {"CVE-2021-30605", "CVE-2021-30606", "CVE-2021-3193"}
        assert all(r["source"] == "signature" for r in result)
        by_id = {r["cve"]: r for r in result}
        assert by_id["CVE-2021-30605"]["severity"] == "critical"
        assert by_id["CVE-2021-30606"]["severity"] == "critical"
        assert by_id["CVE-2021-3193"]["severity"] == "medium"

    def test_camera_vendor(self):
        """Camera vendor + RTSP ports match exactly one CVE (high)."""
        result = detect_cves({"open_ports": [80, 554], "vendor": "hikvision"})
        assert {r["cve"] for r in result} == {"CVE-2021-36260"}
        assert result[0]["severity"] == "high"
        assert result[0]["source"] == "signature"

    def test_printer_hostname(self):
        """CUPS port + printer-like hostname yields 3 high-severity CVEs."""
        result = detect_cves({"open_ports": [631], "hostname": "office-printer.local"})
        assert {r["cve"] for r in result} == {
            "CVE-2022-26905", "CVE-2023-29003", "CVE-2023-29004"
        }
        assert all(r["severity"] == "high" for r in result)

    def test_no_match(self):
        """No open ports (or unknown port) -> empty result."""
        assert detect_cves({}) == []
        assert (
            detect_cves(
                {"open_ports": [99999], "vendor": "unknown", "hostname": "unknown"}
            )
            == []
        )

    def test_string_open_ports(self):
        """String open_ports are normalized the same as a list."""
        result = detect_cves({"open_ports": "1883,8883"})
        assert {r["cve"] for r in result} == {
            "CVE-2021-30605", "CVE-2021-30606", "CVE-2021-3193"
        }

    def test_record_shape(self):
        """Each detected record has exactly the expected keys."""
        result = detect_cves({"open_ports": [1883]})
        assert len(result) >= 1
        for r in result:
            assert set(r.keys()) == {"cve", "note", "severity", "source"}


class TestMatchOpenPorts:
    """Test Match/Rule open_ports matching (classifier/rules.py)."""

    def test_single_port_in_open_ports(self):
        """Match(port) is satisfied when present in the open_ports list."""
        m = Match(port=1883)
        assert m.matches_host({"open_ports": [1883, 8883]})

    def test_single_port_absent(self):
        """Match(port) fails when not in the open_ports list."""
        m = Match(port=9999)
        assert not m.matches_host({"open_ports": [1883, 8883]})

    def test_single_port_string_open_ports(self):
        """Match(port) works with a comma-separated open_ports string."""
        m = Match(port=1883)
        assert m.matches_host({"open_ports": "1883,8883"})

    def test_port_regex(self):
        """Match(port_regex) matches any open_port entry."""
        m = Match(port_regex=r"^18\d\d$")
        assert m.matches_host({"open_ports": [1883, 8883, 22]})

    def test_classify_host_with_open_ports(self):
        """RuleSet classifies a host using its open_ports."""
        ruleset = RuleSet(rules=[
            Rule(name="mqtt", category="iot", matches=[Match(port=1883)], priority=1)
        ])
        host = {"ip": "10.0.0.5", "open_ports": [1883, 9001]}
        results = ruleset.classify_host(host)
        assert len(results) == 1
        assert results[0]["rule_name"] == "mqtt"
        assert results[0]["category"] == "iot"
