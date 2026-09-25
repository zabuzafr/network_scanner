"""Classifier engine: apply rules to hosts and generate classification results."""

from typing import List, Dict, Any
from .rules import RuleSet
from .credentials import credentials_for_host


class ClassificationEngine:
    """Engine to classify hosts using a ruleset."""

    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset
        self._log = []

    def classify_host(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify a single host and return all matching rule results."""
        classifications = self.ruleset.classify_host(host)
        creds = credentials_for_host(host)
        if creds:
            for c in classifications:
                c["default_credentials"] = creds
        if not classifications and creds:
            classifications = [{
                "category": "unknown",
                "matched_rule": None,
                "default_credentials": creds,
            }]
        for c in classifications:
            self._log.append({
                "ip": host.get("ip"),
                "mac": host.get("mac"),
                "classification": c
            })
        return classifications

    def classify_hosts(self, hosts: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Classify multiple hosts and return {ip: [classifications]}."""
        results = {}
        for host in hosts:
            ip = host.get("ip", "unknown")
            results[ip] = self.classify_host(host)
        return results

    def get_classification_summary(self) -> Dict[str, int]:
        """Return category counts from all classified hosts."""
        summary = {}
        for entry in self._log:
            cat = entry["classification"].get("category", "unknown")
            summary[cat] = summary.get(cat, 0) + 1
        return summary

    def get_log(self) -> List[Dict[str, Any]]:
        """Return full classification log."""
        return self._log.copy()


def create_engine_from_yaml(yaml_path: str) -> ClassificationEngine:
    """Load ruleset from YAML and return initialized engine."""
    from .rules import load_rules_from_yaml
    ruleset = load_rules_from_yaml(yaml_path)
    return ClassificationEngine(ruleset)
