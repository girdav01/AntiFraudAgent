"""
URLHaus CTI Integration Module

Integrates with URLHaus API for malicious URL detection and IOC enrichment.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import requests
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

logger = structlog.get_logger(__name__)


class URLHausClient:
    """
    Client for interacting with URLHaus API.

    Provides methods for:
    - Fetching recent malicious URLs
    - Looking up specific URLs
    - IOC enrichment
    - Threat reporting
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize URLHaus client.

        Args:
            api_key: Optional API key for authenticated requests
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AntiFraudAgent/1.0",
            "Accept": "application/json"
        })
        if api_key:
            self.session.headers.update({"Auth-Key": api_key})

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_recent_urls(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent malicious URLs from URLHaus.

        Args:
            limit: Maximum number of URLs to retrieve

        Returns:
            List of URL dictionaries with metadata
        """
        try:
            response = self.session.post(
                f"{self.BASE_URL}/urls/recent/",
                data={"limit": limit},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "ok":
                urls = data.get("urls", [])
                logger.info("urlhaus_recent_urls_fetched", count=len(urls))
                return urls
            else:
                logger.warning("urlhaus_query_failed", status=data.get("query_status"))
                return []

        except requests.RequestException as e:
            logger.error("urlhaus_request_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Look up a specific URL in URLHaus database.

        Args:
            url: URL to lookup

        Returns:
            URL information dictionary or None if not found
        """
        try:
            response = self.session.post(
                f"{self.BASE_URL}/url/",
                data={"url": url},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "ok":
                logger.info("urlhaus_url_found", url=url, threat=data.get("threat"))
                return data
            elif data.get("query_status") == "no_results":
                logger.debug("urlhaus_url_not_found", url=url)
                return None
            else:
                logger.warning("urlhaus_lookup_failed", url=url, status=data.get("query_status"))
                return None

        except requests.RequestException as e:
            logger.error("urlhaus_lookup_error", url=url, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def lookup_host(self, host: str) -> List[Dict[str, Any]]:
        """
        Look up all URLs associated with a host.

        Args:
            host: Hostname or IP to lookup

        Returns:
            List of URL dictionaries for the host
        """
        try:
            response = self.session.post(
                f"{self.BASE_URL}/host/",
                data={"host": host},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "ok":
                urls = data.get("urls", [])
                logger.info("urlhaus_host_urls_found", host=host, count=len(urls))
                return urls
            else:
                logger.debug("urlhaus_host_not_found", host=host)
                return []

        except requests.RequestException as e:
            logger.error("urlhaus_host_lookup_error", host=host, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def lookup_payload(self, payload_hash: str) -> Optional[Dict[str, Any]]:
        """
        Look up payload information by hash (MD5 or SHA256).

        Args:
            payload_hash: MD5 or SHA256 hash of payload

        Returns:
            Payload information or None if not found
        """
        try:
            # Determine hash type
            hash_type = "md5_hash" if len(payload_hash) == 32 else "sha256_hash"

            response = self.session.post(
                f"{self.BASE_URL}/payload/",
                data={hash_type: payload_hash},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "ok":
                logger.info("urlhaus_payload_found", hash=payload_hash)
                return data
            else:
                logger.debug("urlhaus_payload_not_found", hash=payload_hash)
                return None

        except requests.RequestException as e:
            logger.error("urlhaus_payload_lookup_error", hash=payload_hash, error=str(e))
            raise

    def enrich_iocs(self, iocs: List[str]) -> Dict[str, Any]:
        """
        Enrich a list of IOCs (URLs, domains, IPs, hashes) with URLHaus data.

        Args:
            iocs: List of IOCs to enrich

        Returns:
            Dictionary mapping IOCs to their enrichment data
        """
        enriched = {}

        for ioc in iocs:
            ioc = ioc.strip()

            try:
                # Determine IOC type and lookup accordingly
                if ioc.startswith("http://") or ioc.startswith("https://"):
                    result = self.lookup_url(ioc)
                elif len(ioc) in [32, 64]:  # Hash
                    result = self.lookup_payload(ioc)
                else:  # Host/domain
                    result = self.lookup_host(ioc)

                if result:
                    enriched[ioc] = {
                        "found": True,
                        "data": result,
                        "source": "URLHaus",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                else:
                    enriched[ioc] = {
                        "found": False,
                        "source": "URLHaus",
                        "timestamp": datetime.utcnow().isoformat()
                    }

            except Exception as e:
                logger.error("urlhaus_enrichment_failed", ioc=ioc, error=str(e))
                enriched[ioc] = {
                    "found": False,
                    "error": str(e),
                    "source": "URLHaus",
                    "timestamp": datetime.utcnow().isoformat()
                }

        logger.info("urlhaus_enrichment_complete", total=len(iocs), found=sum(1 for e in enriched.values() if e.get("found")))
        return enriched

    def get_statistics(self) -> Optional[Dict[str, Any]]:
        """
        Get URLHaus statistics.

        Returns:
            Statistics dictionary or None on error
        """
        try:
            response = self.session.get(
                f"{self.BASE_URL}/stats/",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            logger.error("urlhaus_stats_error", error=str(e))
            return None
