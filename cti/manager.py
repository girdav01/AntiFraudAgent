"""
CTI Manager Module

Orchestrates multiple CTI sources for comprehensive threat intelligence enrichment.
"""

import logging
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import structlog

from .urlhaus import URLHausClient
from .virustotal import VirusTotalClient
from .trend_vision_one import TrendVisionOneClient

logger = structlog.get_logger(__name__)


class CTIManager:
    """
    Unified manager for all CTI integrations.

    Orchestrates URLHaus, VirusTotal, and Trend Vision One for:
    - Multi-source IOC enrichment
    - Comprehensive threat analysis
    - Correlation across sources
    """

    def __init__(
        self,
        urlhaus_enabled: bool = True,
        virustotal_api_key: Optional[str] = None,
        trend_api_key: Optional[str] = None,
        trend_base_url: str = "https://api.xdr.trendmicro.com"
    ):
        """
        Initialize CTI Manager.

        Args:
            urlhaus_enabled: Enable URLHaus integration
            virustotal_api_key: VirusTotal API key
            trend_api_key: Trend Vision One API key
            trend_base_url: Trend Vision One base URL
        """
        self.clients = {}

        # Initialize URLHaus
        if urlhaus_enabled:
            try:
                self.clients["urlhaus"] = URLHausClient()
                logger.info("cti_urlhaus_initialized")
            except Exception as e:
                logger.error("cti_urlhaus_init_failed", error=str(e))

        # Initialize VirusTotal
        if virustotal_api_key:
            try:
                self.clients["virustotal"] = VirusTotalClient(virustotal_api_key)
                logger.info("cti_virustotal_initialized")
            except Exception as e:
                logger.error("cti_virustotal_init_failed", error=str(e))

        # Initialize Trend Vision One
        if trend_api_key:
            try:
                self.clients["trend"] = TrendVisionOneClient(trend_api_key, trend_base_url)
                logger.info("cti_trend_initialized")
            except Exception as e:
                logger.error("cti_trend_init_failed", error=str(e))

        if not self.clients:
            logger.warning("cti_no_sources_available")

    def enrich_iocs_multi_source(
        self,
        iocs: List[str],
        sources: Optional[List[str]] = None,
        parallel: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        """
        Enrich IOCs using multiple CTI sources in parallel.

        Args:
            iocs: List of IOCs to enrich
            sources: List of sources to use (None = all available)
            parallel: Whether to query sources in parallel

        Returns:
            Dictionary mapping IOCs to enrichment data from all sources
        """
        if not sources:
            sources = list(self.clients.keys())

        enriched = {ioc: {} for ioc in iocs}

        if parallel:
            with ThreadPoolExecutor(max_workers=len(sources)) as executor:
                future_to_source = {}

                for source in sources:
                    if source in self.clients:
                        client = self.clients[source]
                        future = executor.submit(client.enrich_iocs, iocs)
                        future_to_source[future] = source

                for future in as_completed(future_to_source):
                    source = future_to_source[future]
                    try:
                        results = future.result()
                        for ioc, data in results.items():
                            enriched[ioc][source] = data
                    except Exception as e:
                        logger.error("cti_enrichment_source_failed", source=source, error=str(e))
        else:
            for source in sources:
                if source in self.clients:
                    try:
                        client = self.clients[source]
                        results = client.enrich_iocs(iocs)
                        for ioc, data in results.items():
                            enriched[ioc][source] = data
                    except Exception as e:
                        logger.error("cti_enrichment_source_failed", source=source, error=str(e))

        logger.info("cti_multi_source_enrichment_complete", iocs=len(iocs), sources=len(sources))
        return enriched

    def get_threat_score(self, ioc: str) -> Dict[str, Any]:
        """
        Calculate aggregate threat score for an IOC across all sources.

        Args:
            ioc: IOC to score

        Returns:
            Threat score and verdict
        """
        enrichment = self.enrich_iocs_multi_source([ioc])
        ioc_data = enrichment.get(ioc, {})

        total_malicious = 0
        total_suspicious = 0
        total_engines = 0
        sources_checked = 0

        for source, data in ioc_data.items():
            if data.get("found"):
                sources_checked += 1
                result_data = data.get("data", {})

                if "malicious" in result_data:
                    total_malicious += result_data["malicious"]
                    total_suspicious += result_data.get("suspicious", 0)
                    total_engines += result_data.get("total_engines", 0)

        # Calculate normalized threat score (0-100)
        if total_engines > 0:
            threat_score = ((total_malicious * 2 + total_suspicious) / total_engines) * 100
        else:
            threat_score = 0

        # Determine verdict
        if threat_score >= 50:
            verdict = "malicious"
        elif threat_score >= 20:
            verdict = "suspicious"
        elif threat_score > 0:
            verdict = "potentially_unwanted"
        else:
            verdict = "clean"

        result = {
            "ioc": ioc,
            "threat_score": round(threat_score, 2),
            "verdict": verdict,
            "sources_checked": sources_checked,
            "total_malicious": total_malicious,
            "total_suspicious": total_suspicious,
            "total_engines": total_engines,
            "source_data": ioc_data
        }

        logger.info(
            "cti_threat_score_calculated",
            ioc=ioc,
            score=result["threat_score"],
            verdict=verdict
        )
        return result

    def get_recent_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent threats from all available sources.

        Args:
            limit: Maximum number of threats per source

        Returns:
            List of recent threat indicators
        """
        threats = []

        # URLHaus recent URLs
        if "urlhaus" in self.clients:
            try:
                urlhaus_threats = self.clients["urlhaus"].get_recent_urls(limit)
                for threat in urlhaus_threats:
                    threats.append({
                        "source": "URLHaus",
                        "type": "url",
                        "indicator": threat.get("url"),
                        "threat": threat.get("threat"),
                        "dateadded": threat.get("dateadded"),
                        "data": threat
                    })
            except Exception as e:
                logger.error("cti_urlhaus_recent_failed", error=str(e))

        logger.info("cti_recent_threats_fetched", count=len(threats))
        return threats

    def correlate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlate findings across multiple CTI sources.

        Args:
            findings: List of enriched findings

        Returns:
            Correlation analysis
        """
        correlations = {
            "high_confidence": [],
            "medium_confidence": [],
            "low_confidence": [],
            "indicators_by_source": {}
        }

        for finding in findings:
            ioc = finding.get("ioc")
            source_data = finding.get("source_data", {})

            # Count how many sources flagged as malicious
            malicious_count = sum(
                1 for data in source_data.values()
                if data.get("found") and data.get("data", {}).get("malicious", 0) > 0
            )

            if malicious_count >= 2:
                correlations["high_confidence"].append(finding)
            elif malicious_count == 1:
                correlations["medium_confidence"].append(finding)
            else:
                correlations["low_confidence"].append(finding)

            # Track by source
            for source in source_data.keys():
                if source not in correlations["indicators_by_source"]:
                    correlations["indicators_by_source"][source] = []
                correlations["indicators_by_source"][source].append(ioc)

        logger.info(
            "cti_correlation_complete",
            high=len(correlations["high_confidence"]),
            medium=len(correlations["medium_confidence"]),
            low=len(correlations["low_confidence"])
        )
        return correlations

    def close_all(self):
        """Close all CTI client connections."""
        if "virustotal" in self.clients:
            self.clients["virustotal"].close()
        logger.info("cti_clients_closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()
