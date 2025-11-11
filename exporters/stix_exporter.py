"""
STIX 2.1 Exporter Module

Handles creation and export of STIX 2.1 bundles to Trend Vision One and OpenCTI.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import structlog
from stix2 import (
    Bundle, Indicator, Malware, ThreatActor, AttackPattern,
    Vulnerability, Identity, Relationship, ObservedData,
    URL, IPv4Address, IPv6Address, DomainName, EmailAddress, File
)
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

logger = structlog.get_logger(__name__)


class STIXExporter:
    """
    STIX 2.1 exporter for fraud and CTI findings.

    Features:
    - Create STIX 2.1 bundles from IOCs and findings
    - Export to Trend Micro Vision One
    - Export to OpenCTI
    - Relationship mapping
    - Custom fraud extensions
    """

    def __init__(
        self,
        identity_name: str = "AntiFraudAgent",
        identity_class: str = "system",
        trend_api_key: Optional[str] = None,
        trend_base_url: str = "https://api.xdr.trendmicro.com",
        opencti_url: Optional[str] = None,
        opencti_token: Optional[str] = None
    ):
        """
        Initialize STIX exporter.

        Args:
            identity_name: Identity name for STIX objects
            identity_class: Identity class
            trend_api_key: Trend Vision One API key
            trend_base_url: Trend Vision One base URL
            opencti_url: OpenCTI URL
            opencti_token: OpenCTI API token
        """
        self.identity = Identity(
            name=identity_name,
            identity_class=identity_class
        )

        self.trend_api_key = trend_api_key
        self.trend_base_url = trend_base_url.rstrip("/")

        self.opencti_url = opencti_url.rstrip("/") if opencti_url else None
        self.opencti_token = opencti_token

        logger.info("stix_exporter_initialized", identity=identity_name)

    def create_indicator_from_ioc(
        self,
        ioc: str,
        ioc_type: str,
        labels: Optional[List[str]] = None,
        description: Optional[str] = None,
        confidence: int = 50
    ) -> Indicator:
        """
        Create STIX Indicator from IOC.

        Args:
            ioc: IOC value
            ioc_type: Type (url, ip, domain, hash, email)
            labels: Optional labels
            description: Optional description
            confidence: Confidence score (0-100)

        Returns:
            STIX Indicator object
        """
        # Determine pattern based on IOC type
        if ioc_type == "url":
            pattern = f"[url:value = '{ioc}']"
            pattern_type = "stix"
        elif ioc_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{ioc}']"
            pattern_type = "stix"
        elif ioc_type == "ipv6":
            pattern = f"[ipv6-addr:value = '{ioc}']"
            pattern_type = "stix"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc}']"
            pattern_type = "stix"
        elif ioc_type == "email":
            pattern = f"[email-addr:value = '{ioc}']"
            pattern_type = "stix"
        elif ioc_type in ["md5", "sha1", "sha256"]:
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{ioc}']"
            pattern_type = "stix"
        else:
            pattern = ioc
            pattern_type = "stix"

        if not labels:
            labels = ["malicious-activity", "fraud"]

        indicator = Indicator(
            pattern=pattern,
            pattern_type=pattern_type,
            created_by_ref=self.identity,
            labels=labels,
            description=description or f"{ioc_type}: {ioc}",
            confidence=confidence,
            valid_from=datetime.utcnow()
        )

        return indicator

    def create_bundle_from_iocs(
        self,
        enriched_iocs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create STIX bundle from enriched IOCs.

        Args:
            enriched_iocs: Dictionary of IOCs with enrichment data

        Returns:
            STIX Bundle dictionary
        """
        objects = [self.identity]
        relationships = []

        for ioc, enrichment_data in enriched_iocs.items():
            # Determine IOC type
            ioc_type = self._determine_ioc_type(ioc)

            # Aggregate confidence from sources
            confidence = self._calculate_confidence(enrichment_data)

            # Create indicator
            labels = ["malicious-activity"]

            # Add specific labels based on enrichment
            for source, data in enrichment_data.items():
                if data.get("found") and data.get("data"):
                    source_data = data["data"]

                    # Add labels based on findings
                    if source_data.get("malicious", 0) > 0:
                        labels.append("malicious")
                    if source_data.get("threat"):
                        labels.append(f"threat-{source_data['threat']}")

            indicator = self.create_indicator_from_ioc(
                ioc,
                ioc_type,
                labels=list(set(labels)),
                description=f"IOC enriched from {len(enrichment_data)} sources",
                confidence=confidence
            )

            objects.append(indicator)

        # Create bundle
        bundle = Bundle(objects=objects)

        logger.info("stix_bundle_created_from_iocs", indicators=len(objects) - 1)

        return bundle.serialize(pretty=True)

    def create_fraud_bundle(
        self,
        fraud_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Create STIX bundle from fraud findings.

        Args:
            fraud_findings: List of fraud detection findings

        Returns:
            STIX Bundle dictionary
        """
        objects = [self.identity]

        for finding in fraud_findings:
            fraud_type = finding.get("fraud_type", "unknown")
            confidence = finding.get("confidence", 50)
            source_url = finding.get("source_url")

            # Create indicator for the fraudulent URL/content
            if source_url:
                labels = ["fraud", f"fraud-{fraud_type}", "social-engineering"]

                indicator = self.create_indicator_from_ioc(
                    source_url,
                    "url",
                    labels=labels,
                    description=f"Fraudulent content detected: {fraud_type}",
                    confidence=confidence
                )

                objects.append(indicator)

                # Create attack pattern if applicable
                if fraud_type in ["phishing", "social_engineering", "scam"]:
                    attack_pattern = AttackPattern(
                        name=fraud_type.title(),
                        description=finding.get("explanation", f"{fraud_type} attack detected"),
                        created_by_ref=self.identity
                    )

                    objects.append(attack_pattern)

                    # Create relationship
                    relationship = Relationship(
                        source_ref=indicator.id,
                        target_ref=attack_pattern.id,
                        relationship_type="indicates",
                        created_by_ref=self.identity
                    )

                    objects.append(relationship)

        bundle = Bundle(objects=objects)

        logger.info("stix_fraud_bundle_created", indicators=len([o for o in objects if hasattr(o, "pattern")]))

        return bundle.serialize(pretty=True)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def export_to_trend_vision_one(
        self,
        bundles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export STIX bundles to Trend Micro Vision One.

        Args:
            bundles: List of STIX bundle dictionaries

        Returns:
            Export results
        """
        if not self.trend_api_key:
            logger.warning("trend_api_key_not_configured")
            return {"success": False, "error": "API key not configured"}

        results = {
            "success": True,
            "count": 0,
            "submissions": [],
            "errors": []
        }

        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {self.trend_api_key}",
            "Content-Type": "application/json"
        })

        for i, bundle in enumerate(bundles):
            try:
                response = session.post(
                    f"{self.trend_base_url}/v3.0/threatintel/stix",
                    json=bundle,
                    timeout=30
                )

                response.raise_for_status()
                data = response.json()

                results["submissions"].append({
                    "bundle_index": i,
                    "submission_id": data.get("id"),
                    "status": "success"
                })

                results["count"] += 1

                logger.info("trend_stix_export_success", bundle_index=i, submission_id=data.get("id"))

            except requests.RequestException as e:
                logger.error("trend_stix_export_failed", bundle_index=i, error=str(e))
                results["errors"].append({
                    "bundle_index": i,
                    "error": str(e)
                })
                results["success"] = False

        logger.info("trend_stix_export_complete", total=len(bundles), successful=results["count"])

        return results

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def export_to_opencti(
        self,
        bundles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export STIX bundles to OpenCTI.

        Args:
            bundles: List of STIX bundle dictionaries

        Returns:
            Export results
        """
        if not self.opencti_url or not self.opencti_token:
            logger.warning("opencti_not_configured")
            return {"success": False, "error": "OpenCTI not configured"}

        results = {
            "success": True,
            "count": 0,
            "submissions": [],
            "errors": []
        }

        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {self.opencti_token}",
            "Content-Type": "application/json"
        })

        for i, bundle in enumerate(bundles):
            try:
                # OpenCTI STIX import endpoint
                response = session.post(
                    f"{self.opencti_url}/graphql",
                    json={
                        "query": """
                        mutation StixBundleImport($file: Upload!) {
                            stixBundleImport(file: $file) {
                                id
                            }
                        }
                        """,
                        "variables": {
                            "file": bundle
                        }
                    },
                    timeout=30
                )

                response.raise_for_status()
                data = response.json()

                if "errors" in data:
                    raise Exception(f"GraphQL errors: {data['errors']}")

                results["submissions"].append({
                    "bundle_index": i,
                    "import_id": data.get("data", {}).get("stixBundleImport", {}).get("id"),
                    "status": "success"
                })

                results["count"] += 1

                logger.info("opencti_stix_export_success", bundle_index=i)

            except (requests.RequestException, Exception) as e:
                logger.error("opencti_stix_export_failed", bundle_index=i, error=str(e))
                results["errors"].append({
                    "bundle_index": i,
                    "error": str(e)
                })
                results["success"] = False

        logger.info("opencti_stix_export_complete", total=len(bundles), successful=results["count"])

        return results

    def _determine_ioc_type(self, ioc: str) -> str:
        """
        Determine IOC type from value.

        Args:
            ioc: IOC value

        Returns:
            IOC type string
        """
        import re

        if ioc.startswith("http://") or ioc.startswith("https://"):
            return "url"
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return "ipv4"
        elif ':' in ioc and not '@' in ioc:
            return "ipv6"
        elif '@' in ioc:
            return "email"
        elif len(ioc) == 32:
            return "md5"
        elif len(ioc) == 40:
            return "sha1"
        elif len(ioc) == 64:
            return "sha256"
        elif '.' in ioc:
            return "domain"
        else:
            return "unknown"

    def _calculate_confidence(self, enrichment_data: Dict[str, Any]) -> int:
        """
        Calculate aggregate confidence from enrichment data.

        Args:
            enrichment_data: Enrichment data from multiple sources

        Returns:
            Confidence score (0-100)
        """
        total_malicious = 0
        total_engines = 0

        for source, data in enrichment_data.items():
            if data.get("found") and data.get("data"):
                source_data = data["data"]

                if "malicious" in source_data:
                    total_malicious += source_data["malicious"]
                    total_engines += source_data.get("total_engines", 1)

        if total_engines > 0:
            confidence = int((total_malicious / total_engines) * 100)
            return min(confidence, 100)

        return 50  # Default confidence

    def save_bundle(self, bundle: Dict[str, Any], file_path: str):
        """
        Save STIX bundle to file.

        Args:
            bundle: STIX bundle dictionary
            file_path: Output file path
        """
        import json

        with open(file_path, "w") as f:
            json.dump(bundle, f, indent=2)

        logger.info("stix_bundle_saved", file=file_path)
