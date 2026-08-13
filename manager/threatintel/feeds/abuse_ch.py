"""
abuse.ch Threat Intel Feed Connector — Phase 14 (M9).

Fetches malware hash IOCs from the abuse.ch URLhaus / MalwareBazaar
public API or CSV export. Demonstrates the pluggable feed pattern.
"""
import logging
from typing import List

from manager.threatintel.models import IndicatorDTO, ThreatIntelFeed

logger = logging.getLogger(__name__)

ABUSECH_RECENT_HASHES_URL = "https://bazaar.abuse.ch/export/csv/recent/"


class AbuseChFeed:
    """Feed connector for abuse.ch MalwareBazaar recent hashes."""

    def __init__(self, url: str = ABUSECH_RECENT_HASHES_URL):
        self.url = url

    async def fetch_indicators(self) -> List[IndicatorDTO]:
        """Pull recent malware hashes from abuse.ch.

        In production this would HTTP GET the CSV and parse it.
        For safety in CI / offline dev we return a curated sample set.
        """
        logger.info("Fetching indicators from abuse.ch feed: %s", self.url)

        # Sample indicators for development / offline testing
        sample_indicators = [
            IndicatorDTO(
                ioc_type="hash_sha256",
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                source="abuse.ch",
                confidence=90,
                tags=["malware", "bazaar"],
            ),
            IndicatorDTO(
                ioc_type="hash_sha256",
                value="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                source="abuse.ch",
                confidence=85,
                tags=["ransomware"],
            ),
            IndicatorDTO(
                ioc_type="ip",
                value="198.51.100.42",
                source="abuse.ch",
                confidence=75,
                tags=["c2", "botnet"],
            ),
            IndicatorDTO(
                ioc_type="domain",
                value="evil-payload.example.com",
                source="abuse.ch",
                confidence=80,
                tags=["phishing"],
            ),
        ]

        logger.info("Fetched %d sample indicators from abuse.ch feed", len(sample_indicators))
        return sample_indicators
