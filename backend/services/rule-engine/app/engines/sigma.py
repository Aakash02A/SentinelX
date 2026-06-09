"""
Sigma rule evaluator.
Parses Sigma YAML rules and evaluates them against normalized ECS events.
"""
import fnmatch
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class SigmaRule:
    """Parsed and compiled Sigma detection rule."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.id: str = raw.get("id", "")
        self.title: str = raw.get("title", "Untitled Rule")
        self.description: str = raw.get("description", "")
        self.severity: str = raw.get("level", "medium").lower()
        self.tags: list[str] = raw.get("tags", [])
        self.mitre_technique: str | None = self._extract_mitre(self.tags)
        self._condition_raw: dict[str, Any] = raw.get("detection", {})

    @staticmethod
    def _extract_mitre(tags: list[str]) -> str | None:
        for tag in tags:
            if tag.startswith("attack.t") or tag.startswith("attack.T"):
                return tag.split(".")[-1].upper()
        return None

    def evaluate(self, event: dict[str, Any]) -> bool:
        """Return True if this rule matches the event."""
        try:
            detection = self._condition_raw
            if not detection:
                return False

            # Simple keyword + condition evaluation
            # For production: use a full Sigma parser (e.g. pySigma)
            for key, checks in detection.items():
                if key == "condition":
                    continue
                if isinstance(checks, dict):
                    if not self._check_field_conditions(event, checks):
                        return False
            return True
        except Exception as exc:
            logger.debug("Rule evaluation error [%s]: %s", self.title, exc)
            return False

    def _check_field_conditions(
        self, event: dict[str, Any], checks: dict[str, Any]
    ) -> bool:
        """Check field conditions against the event (flattened dot-notation lookup)."""
        for field, value in checks.items():
            event_value = self._get_nested(event, field)
            if event_value is None:
                return False
            if isinstance(value, list):
                if not any(self._match(event_value, v) for v in value):
                    return False
            else:
                if not self._match(event_value, value):
                    return False
        return True

    @staticmethod
    def _get_nested(obj: dict, dotted_key: str) -> Any:
        """Extract a value from a nested dict using dot notation."""
        keys = dotted_key.split(".")
        for k in keys:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(k)  # type: ignore[assignment]
        return obj

    @staticmethod
    def _match(value: Any, pattern: Any) -> bool:
        if value is None:
            return False
        v_str = str(value).lower()
        p_str = str(pattern).lower()
        # Wildcard support (* and ?)
        if "*" in p_str or "?" in p_str:
            return fnmatch.fnmatch(v_str, p_str)
        return p_str in v_str


class SigmaRuleEngine:
    """Loads and manages a collection of Sigma rules."""

    def __init__(self) -> None:
        self._rules: list[SigmaRule] = []

    def load_directory(self, rules_dir: Path) -> None:
        """Load all .yml Sigma rule files from a directory recursively."""
        count = 0
        for path in rules_dir.rglob("*.yml"):
            try:
                with path.open() as f:
                    raw = yaml.safe_load(f)
                    if isinstance(raw, dict) and "detection" in raw:
                        self._rules.append(SigmaRule(raw))
                        count += 1
            except Exception as exc:
                logger.warning("Failed to load Sigma rule %s: %s", path, exc)
        logger.info("Loaded %d Sigma rules from %s", count, rules_dir)

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Evaluate all rules against an event.
        Returns a list of matches with rule metadata.
        """
        matches = []
        for rule in self._rules:
            if rule.evaluate(event):
                matches.append({
                    "rule_id": rule.id,
                    "rule_title": rule.title,
                    "severity": rule.severity,
                    "mitre_technique": rule.mitre_technique,
                    "tags": rule.tags,
                })
        return matches

    @property
    def rule_count(self) -> int:
        return len(self._rules)
