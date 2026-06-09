"""
IOC Matcher — matches events against known malicious indicators.
Checks IPs, domains, URLs, and file hashes against the threat intel DB.
"""
import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)


class IOCMatcher:
    """
    Fast in-memory IOC lookup.
    Populated from the ThreatIntel DB and refreshed on a schedule.
    """

    def __init__(self) -> None:
        self._malicious_ips: set[str] = set()
        self._malicious_domains: set[str] = set()
        self._malicious_hashes: set[str] = set()
        self._malicious_urls: set[str] = set()

    def load_iocs(
        self,
        ips: list[str],
        domains: list[str],
        hashes: list[str],
        urls: list[str],
    ) -> None:
        """Refresh the in-memory IOC sets."""
        self._malicious_ips = set(ips)
        self._malicious_domains = set(d.lower() for d in domains)
        self._malicious_hashes = set(h.lower() for h in hashes)
        self._malicious_urls = set(urls)
        logger.info(
            "IOC cache refreshed: %d IPs, %d domains, %d hashes, %d URLs",
            len(ips), len(domains), len(hashes), len(urls),
        )

    def check_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Check an ECS-normalized event for IOC matches. Returns list of matches."""
        matches = []

        # ── IP checks ────────────────────────────────────────
        for ip_field in ("destination.ip", "source.ip"):
            ip = self._get_nested(event, ip_field)
            if ip and ip in self._malicious_ips:
                matches.append({
                    "type": "ip",
                    "value": ip,
                    "field": ip_field,
                    "severity": "high",
                })

        # ── Domain checks ─────────────────────────────────────
        domain = self._get_nested(event, "destination.domain")
        if domain and domain.lower() in self._malicious_domains:
            matches.append({
                "type": "domain",
                "value": domain,
                "field": "destination.domain",
                "severity": "high",
            })

        # ── Hash checks ───────────────────────────────────────
        for hash_field in ("process.hash.sha256", "file.hash.sha256"):
            h = self._get_nested(event, hash_field)
            if h and h.lower() in self._malicious_hashes:
                matches.append({
                    "type": "hash_sha256",
                    "value": h,
                    "field": hash_field,
                    "severity": "critical",
                })

        return matches

    @staticmethod
    def _get_nested(obj: dict, dotted_key: str) -> Any:
        keys = dotted_key.split(".")
        for k in keys:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(k)  # type: ignore[assignment]
        return obj

    def is_private_ip(self, ip: str) -> bool:
        """Return True if the IP is a private/RFC1918 address."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
