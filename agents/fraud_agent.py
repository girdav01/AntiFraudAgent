"""
Fraud Detection Autonomous Agent

Multi-step agent for fraud detection, CTI enrichment, and reporting.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import asyncio
import structlog

from parsers.web_crawler import WebCrawler
from parsers.document_parser import DocumentParser
from parsers.vision_parser import VisionParser
from cti.manager import CTIManager
from llm.agent_llm import AgentLLM
from exporters.stix_exporter import STIXExporter

logger = structlog.get_logger(__name__)


class FraudDetectionAgent:
    """
    Autonomous agent for fraud detection and CTI enrichment.

    Workflow:
    1. Discover and fetch threat intelligence
    2. Crawl suspicious URLs
    3. Parse documents and images
    4. Analyze with LLM
    5. Enrich with CTI sources
    6. Export STIX bundles
    7. Generate reports
    """

    def __init__(
        self,
        config: Dict[str, Any],
        llm: AgentLLM,
        cti_manager: CTIManager
    ):
        """
        Initialize fraud detection agent.

        Args:
            config: Agent configuration
            llm: LLM instance for analysis
            cti_manager: CTI manager for threat intelligence
        """
        self.config = config
        self.llm = llm
        self.cti_manager = cti_manager

        # Initialize parsers
        self.web_crawler = WebCrawler(
            timeout=config.get("crawl_timeout", 30),
            max_depth=config.get("max_depth", 2)
        )
        self.doc_parser = DocumentParser()
        self.vision_parser = VisionParser()

        # Initialize STIX exporter
        self.stix_exporter = STIXExporter(
            identity_name=config.get("identity_name", "AntiFraudAgent"),
            identity_class=config.get("identity_class", "system")
        )

        # State tracking
        self.findings = []
        self.iocs = set()
        self.reports = []

        logger.info("fraud_agent_initialized", config_keys=list(config.keys()))

    async def run_daily_workflow(self) -> Dict[str, Any]:
        """
        Execute daily autonomous workflow.

        Returns:
            Workflow results dictionary
        """
        logger.info("daily_workflow_started")
        start_time = datetime.utcnow()

        workflow_results = {
            "start_time": start_time.isoformat(),
            "steps_completed": [],
            "findings": [],
            "iocs": [],
            "reports": [],
            "errors": []
        }

        try:
            # Step 1: Fetch recent threats from CTI sources
            logger.info("workflow_step", step=1, name="fetch_cti_threats")
            cti_threats = await self._fetch_cti_threats()
            workflow_results["steps_completed"].append("fetch_cti_threats")
            workflow_results["cti_threats_count"] = len(cti_threats)

            # Step 2: Crawl suspicious URLs
            logger.info("workflow_step", step=2, name="crawl_urls")
            crawl_results = await self._crawl_threat_urls(cti_threats)
            workflow_results["steps_completed"].append("crawl_urls")
            workflow_results["urls_crawled"] = len(crawl_results)

            # Step 3: Analyze crawled content with LLM
            logger.info("workflow_step", step=3, name="analyze_content")
            analysis_results = await self._analyze_content(crawl_results)
            workflow_results["steps_completed"].append("analyze_content")
            workflow_results["analyses_completed"] = len(analysis_results)

            # Step 4: Extract and enrich IOCs
            logger.info("workflow_step", step=4, name="extract_enrich_iocs")
            enriched_iocs = await self._extract_and_enrich_iocs(crawl_results, analysis_results)
            workflow_results["steps_completed"].append("extract_enrich_iocs")
            workflow_results["iocs_enriched"] = len(enriched_iocs)
            workflow_results["iocs"] = list(enriched_iocs.keys())

            # Step 5: Detect fraud patterns
            logger.info("workflow_step", step=5, name="detect_fraud")
            fraud_findings = await self._detect_fraud_patterns(analysis_results)
            workflow_results["steps_completed"].append("detect_fraud")
            workflow_results["fraud_findings_count"] = len(fraud_findings)
            workflow_results["findings"] = fraud_findings

            # Step 6: Generate STIX bundles
            logger.info("workflow_step", step=6, name="generate_stix")
            stix_bundles = await self._generate_stix_bundles(enriched_iocs, fraud_findings)
            workflow_results["steps_completed"].append("generate_stix")
            workflow_results["stix_bundles_count"] = len(stix_bundles)

            # Step 7: Export STIX to external platforms
            logger.info("workflow_step", step=7, name="export_stix")
            export_results = await self._export_stix_bundles(stix_bundles)
            workflow_results["steps_completed"].append("export_stix")
            workflow_results["stix_exports"] = export_results

            # Step 8: Generate daily report
            logger.info("workflow_step", step=8, name="generate_report")
            daily_report = await self._generate_daily_report(workflow_results)
            workflow_results["steps_completed"].append("generate_report")
            workflow_results["report"] = daily_report
            workflow_results["reports"].append(daily_report)

        except Exception as e:
            logger.error("workflow_error", error=str(e))
            workflow_results["errors"].append(str(e))

        workflow_results["end_time"] = datetime.utcnow().isoformat()
        workflow_results["duration_seconds"] = (datetime.utcnow() - start_time).total_seconds()

        logger.info(
            "daily_workflow_completed",
            duration=workflow_results["duration_seconds"],
            steps=len(workflow_results["steps_completed"])
        )

        return workflow_results

    async def _fetch_cti_threats(self) -> List[Dict[str, Any]]:
        """Fetch recent threats from CTI sources."""
        try:
            limit = self.config.get("cti_fetch_limit", 100)
            threats = self.cti_manager.get_recent_threats(limit)
            logger.info("cti_threats_fetched", count=len(threats))
            return threats
        except Exception as e:
            logger.error("cti_fetch_failed", error=str(e))
            return []

    async def _crawl_threat_urls(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Crawl URLs from threat data."""
        urls = []

        # Extract URLs from threats
        for threat in threats:
            if threat.get("type") == "url" and threat.get("indicator"):
                urls.append(threat["indicator"])

        # Limit number of URLs to crawl
        max_urls = self.config.get("max_urls_to_crawl", 50)
        urls = urls[:max_urls]

        if not urls:
            logger.info("no_urls_to_crawl")
            return []

        # Crawl URLs
        try:
            results = await self.web_crawler.crawl_multiple(
                urls,
                parallel=True,
                max_concurrent=self.config.get("max_concurrent_crawls", 5)
            )
            logger.info("urls_crawled", total=len(urls), successful=sum(1 for r in results if r.get("success")))
            return results
        except Exception as e:
            logger.error("url_crawl_failed", error=str(e))
            return []

    async def _analyze_content(self, crawl_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze crawled content with LLM."""
        analyses = []

        for result in crawl_results:
            if not result.get("success"):
                continue

            try:
                # Analyze text content
                text = result.get("text", "")
                if len(text) > 100:  # Only analyze if substantial content
                    analysis = self.llm.analyze_content(text, content_type="web")
                    analysis["source_url"] = result.get("url")
                    analyses.append(analysis)

            except Exception as e:
                logger.error("content_analysis_failed", url=result.get("url"), error=str(e))

        logger.info("content_analyzed", count=len(analyses))
        return analyses

    async def _extract_and_enrich_iocs(
        self,
        crawl_results: List[Dict[str, Any]],
        analysis_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract IOCs and enrich with CTI data."""
        all_iocs = set()

        # Extract IOCs from crawl results
        for result in crawl_results:
            if result.get("success"):
                iocs = self.web_crawler.extract_iocs(result)
                all_iocs.update(iocs)

        # Convert to list for enrichment
        iocs_list = list(all_iocs)[:self.config.get("max_iocs_to_enrich", 100)]

        if not iocs_list:
            logger.info("no_iocs_to_enrich")
            return {}

        # Enrich with CTI
        try:
            enriched = self.cti_manager.enrich_iocs_multi_source(iocs_list)
            logger.info("iocs_enriched", count=len(enriched))
            return enriched
        except Exception as e:
            logger.error("ioc_enrichment_failed", error=str(e))
            return {}

    async def _detect_fraud_patterns(self, analysis_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect fraud patterns in analysis results."""
        findings = []

        for analysis in analysis_results:
            try:
                # Check for high-confidence fraud indicators
                if self.backend == "local" and "fraud_type" in analysis:
                    confidence = analysis.get("confidence", 0)
                    if isinstance(confidence, str):
                        try:
                            confidence = int(confidence)
                        except (ValueError, TypeError):
                            confidence = 0

                    if confidence > 50:
                        findings.append({
                            "type": "fraud_detection",
                            "fraud_type": analysis.get("fraud_type"),
                            "confidence": confidence,
                            "source_url": analysis.get("source_url"),
                            "indicators": analysis.get("indicators", []),
                            "timestamp": datetime.utcnow().isoformat()
                        })

                # Additional social engineering detection
                source_url = analysis.get("source_url")
                if source_url:
                    # Get original content
                    se_analysis = self.llm.detect_social_engineering(
                        analysis.get("explanation", "") or analysis.get("analysis", "")
                    )

                    if "high risk" in str(se_analysis).lower():
                        findings.append({
                            "type": "social_engineering",
                            "source_url": source_url,
                            "analysis": se_analysis,
                            "timestamp": datetime.utcnow().isoformat()
                        })

            except Exception as e:
                logger.error("fraud_detection_failed", error=str(e))

        logger.info("fraud_patterns_detected", count=len(findings))
        return findings

    async def _generate_stix_bundles(
        self,
        enriched_iocs: Dict[str, Any],
        fraud_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate STIX 2.1 bundles from findings."""
        bundles = []

        try:
            # Create bundle from IOCs
            if enriched_iocs:
                bundle = self.stix_exporter.create_bundle_from_iocs(enriched_iocs)
                bundles.append(bundle)

            # Create bundle from fraud findings
            if fraud_findings:
                fraud_bundle = self.stix_exporter.create_fraud_bundle(fraud_findings)
                bundles.append(fraud_bundle)

            logger.info("stix_bundles_generated", count=len(bundles))

        except Exception as e:
            logger.error("stix_generation_failed", error=str(e))

        return bundles

    async def _export_stix_bundles(self, bundles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Export STIX bundles to external platforms."""
        results = {
            "trend_vision_one": {"success": False, "count": 0},
            "opencti": {"success": False, "count": 0}
        }

        # Export to Trend Vision One
        if self.config.get("export_to_trend", False):
            try:
                trend_results = self.stix_exporter.export_to_trend_vision_one(bundles)
                results["trend_vision_one"] = trend_results
            except Exception as e:
                logger.error("trend_export_failed", error=str(e))
                results["trend_vision_one"]["error"] = str(e)

        # Export to OpenCTI
        if self.config.get("export_to_opencti", False):
            try:
                opencti_results = self.stix_exporter.export_to_opencti(bundles)
                results["opencti"] = opencti_results
            except Exception as e:
                logger.error("opencti_export_failed", error=str(e))
                results["opencti"]["error"] = str(e)

        return results

    async def _generate_daily_report(self, workflow_results: Dict[str, Any]) -> str:
        """Generate daily report from workflow results."""
        try:
            report = self.llm.generate_report(workflow_results, report_type="daily")
            logger.info("daily_report_generated", length=len(report))
            return report
        except Exception as e:
            logger.error("report_generation_failed", error=str(e))
            return f"# Daily Report\n\nError generating report: {str(e)}"

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL on-demand.

        Args:
            url: URL to analyze

        Returns:
            Analysis results
        """
        logger.info("analyzing_single_url", url=url)

        try:
            # Crawl URL
            crawl_result = await self.web_crawler.crawl_url(url)

            if not crawl_result.get("success"):
                return {
                    "success": False,
                    "error": crawl_result.get("error"),
                    "url": url
                }

            # Analyze content
            text = crawl_result.get("text", "")
            analysis = self.llm.analyze_content(text, content_type="web")

            # Extract and enrich IOCs
            iocs = self.web_crawler.extract_iocs(crawl_result)
            if iocs:
                enriched_iocs = self.cti_manager.enrich_iocs_multi_source(iocs[:20])
            else:
                enriched_iocs = {}

            result = {
                "success": True,
                "url": url,
                "crawl_result": crawl_result,
                "analysis": analysis,
                "iocs": iocs,
                "enriched_iocs": enriched_iocs,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("url_analysis_complete", url=url)
            return result

        except Exception as e:
            logger.error("url_analysis_failed", url=url, error=str(e))
            return {
                "success": False,
                "url": url,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    async def analyze_document(self, doc_path: str) -> Dict[str, Any]:
        """
        Analyze a document for fraud indicators.

        Args:
            doc_path: Path to document

        Returns:
            Analysis results
        """
        logger.info("analyzing_document", document=doc_path)

        try:
            # Parse document
            parse_result = self.doc_parser.parse_document(doc_path)

            if not parse_result.get("success"):
                return {
                    "success": False,
                    "error": parse_result.get("error"),
                    "document": doc_path
                }

            # Analyze text content
            text = parse_result.get("text", "")
            analysis = self.llm.analyze_content(text, content_type="document")

            # Enrich IOCs
            iocs = parse_result.get("iocs", {})
            all_iocs = []
            for ioc_list in iocs.values():
                if isinstance(ioc_list, list):
                    all_iocs.extend(ioc_list)

            enriched_iocs = {}
            if all_iocs:
                enriched_iocs = self.cti_manager.enrich_iocs_multi_source(all_iocs[:20])

            result = {
                "success": True,
                "document": doc_path,
                "parse_result": parse_result,
                "analysis": analysis,
                "enriched_iocs": enriched_iocs,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("document_analysis_complete", document=doc_path)
            return result

        except Exception as e:
            logger.error("document_analysis_failed", document=doc_path, error=str(e))
            return {
                "success": False,
                "document": doc_path,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
