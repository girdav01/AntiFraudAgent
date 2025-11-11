"""
VirusTotal CTI Integration Module

Integrates with VirusTotal API v3 for file/URL scanning and entity enrichment.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import time
import vt
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

logger = structlog.get_logger(__name__)


class VirusTotalClient:
    """
    Client for interacting with VirusTotal API v3.

    Provides methods for:
    - URL scanning and analysis
    - File scanning
    - Entity enrichment (domains, IPs, hashes)
    - Related submissions lookup
    """

    def __init__(self, api_key: str, rate_limit_delay: float = 0.5):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key
            rate_limit_delay: Delay between requests to avoid rate limiting
        """
        if not api_key:
            raise ValueError("VirusTotal API key is required")

        self.api_key = api_key
        self.rate_limit_delay = rate_limit_delay
        self.client = vt.Client(api_key)
        self.last_request_time = 0

    def _rate_limit(self):
        """Apply rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning.

        Args:
            url: URL to scan

        Returns:
            Scan result dictionary with analysis ID
        """
        try:
            self._rate_limit()
            analysis = self.client.scan_url(url)

            result = {
                "analysis_id": analysis.id,
                "url": url,
                "status": "submitted",
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("virustotal_url_submitted", url=url, analysis_id=analysis.id)
            return result

        except vt.APIError as e:
            logger.error("virustotal_scan_failed", url=url, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_url_analysis(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get analysis results for a URL.

        Args:
            url: URL to analyze

        Returns:
            Analysis results dictionary or None if not found
        """
        try:
            self._rate_limit()
            url_id = vt.url_id(url)
            url_obj = self.client.get_object(f"/urls/{url_id}")

            stats = url_obj.last_analysis_stats
            result = {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "categories": url_obj.categories if hasattr(url_obj, "categories") else {},
                "last_analysis_date": datetime.fromtimestamp(url_obj.last_analysis_date).isoformat() if url_obj.last_analysis_date else None,
                "threat_names": url_obj.last_analysis_results if hasattr(url_obj, "last_analysis_results") else {},
                "reputation": url_obj.reputation if hasattr(url_obj, "reputation") else None,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info(
                "virustotal_url_analyzed",
                url=url,
                malicious=result["malicious"],
                total=result["total_engines"]
            )
            return result

        except vt.APIError as e:
            if "NotFoundError" in str(e):
                logger.debug("virustotal_url_not_found", url=url)
                return None
            logger.error("virustotal_url_analysis_failed", url=url, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_file_analysis(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get file analysis by hash (MD5, SHA1, or SHA256).

        Args:
            file_hash: File hash

        Returns:
            File analysis dictionary or None if not found
        """
        try:
            self._rate_limit()
            file_obj = self.client.get_object(f"/files/{file_hash}")

            stats = file_obj.last_analysis_stats
            result = {
                "hash": {
                    "md5": file_obj.md5,
                    "sha1": file_obj.sha1,
                    "sha256": file_obj.sha256
                },
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "file_type": file_obj.type_description if hasattr(file_obj, "type_description") else None,
                "size": file_obj.size if hasattr(file_obj, "size") else None,
                "names": file_obj.names if hasattr(file_obj, "names") else [],
                "signature_info": file_obj.signature_info if hasattr(file_obj, "signature_info") else None,
                "threat_names": list(set([
                    result["category"] for result in file_obj.last_analysis_results.values()
                    if result.get("category") in ["malicious", "suspicious"]
                ])) if hasattr(file_obj, "last_analysis_results") else [],
                "reputation": file_obj.reputation if hasattr(file_obj, "reputation") else None,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info(
                "virustotal_file_analyzed",
                hash=file_hash,
                malicious=result["malicious"],
                total=result["total_engines"]
            )
            return result

        except vt.APIError as e:
            if "NotFoundError" in str(e):
                logger.debug("virustotal_file_not_found", hash=file_hash)
                return None
            logger.error("virustotal_file_analysis_failed", hash=file_hash, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain information and reputation.

        Args:
            domain: Domain name

        Returns:
            Domain information dictionary or None if not found
        """
        try:
            self._rate_limit()
            domain_obj = self.client.get_object(f"/domains/{domain}")

            stats = domain_obj.last_analysis_stats if hasattr(domain_obj, "last_analysis_stats") else {}
            result = {
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "categories": domain_obj.categories if hasattr(domain_obj, "categories") else {},
                "reputation": domain_obj.reputation if hasattr(domain_obj, "reputation") else None,
                "registrar": domain_obj.registrar if hasattr(domain_obj, "registrar") else None,
                "creation_date": datetime.fromtimestamp(domain_obj.creation_date).isoformat() if hasattr(domain_obj, "creation_date") and domain_obj.creation_date else None,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("virustotal_domain_analyzed", domain=domain, reputation=result["reputation"])
            return result

        except vt.APIError as e:
            if "NotFoundError" in str(e):
                logger.debug("virustotal_domain_not_found", domain=domain)
                return None
            logger.error("virustotal_domain_analysis_failed", domain=domain, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_ip_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get IP address information and reputation.

        Args:
            ip_address: IP address

        Returns:
            IP information dictionary or None if not found
        """
        try:
            self._rate_limit()
            ip_obj = self.client.get_object(f"/ip_addresses/{ip_address}")

            stats = ip_obj.last_analysis_stats if hasattr(ip_obj, "last_analysis_stats") else {}
            result = {
                "ip": ip_address,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": ip_obj.reputation if hasattr(ip_obj, "reputation") else None,
                "country": ip_obj.country if hasattr(ip_obj, "country") else None,
                "asn": ip_obj.asn if hasattr(ip_obj, "asn") else None,
                "as_owner": ip_obj.as_owner if hasattr(ip_obj, "as_owner") else None,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("virustotal_ip_analyzed", ip=ip_address, reputation=result["reputation"])
            return result

        except vt.APIError as e:
            if "NotFoundError" in str(e):
                logger.debug("virustotal_ip_not_found", ip=ip_address)
                return None
            logger.error("virustotal_ip_analysis_failed", ip=ip_address, error=str(e))
            raise

    def enrich_iocs(self, iocs: List[str]) -> Dict[str, Any]:
        """
        Enrich multiple IOCs with VirusTotal data.

        Args:
            iocs: List of IOCs (URLs, domains, IPs, hashes)

        Returns:
            Dictionary mapping IOCs to enrichment data
        """
        enriched = {}

        for ioc in iocs:
            ioc = ioc.strip()

            try:
                # Determine IOC type and lookup
                if ioc.startswith("http://") or ioc.startswith("https://"):
                    result = self.get_url_analysis(ioc)
                elif len(ioc) in [32, 40, 64]:  # Hash (MD5, SHA1, SHA256)
                    result = self.get_file_analysis(ioc)
                elif "." in ioc and not ioc.replace(".", "").replace(":", "").isdigit():  # Domain
                    result = self.get_domain_info(ioc)
                else:  # IP address
                    result = self.get_ip_info(ioc)

                if result:
                    enriched[ioc] = {
                        "found": True,
                        "data": result,
                        "source": "VirusTotal",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                else:
                    enriched[ioc] = {
                        "found": False,
                        "source": "VirusTotal",
                        "timestamp": datetime.utcnow().isoformat()
                    }

            except Exception as e:
                logger.error("virustotal_enrichment_failed", ioc=ioc, error=str(e))
                enriched[ioc] = {
                    "found": False,
                    "error": str(e),
                    "source": "VirusTotal",
                    "timestamp": datetime.utcnow().isoformat()
                }

        logger.info("virustotal_enrichment_complete", total=len(iocs), found=sum(1 for e in enriched.values() if e.get("found")))
        return enriched

    def close(self):
        """Close the VirusTotal client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
