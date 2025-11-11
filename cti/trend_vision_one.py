"""
Trend Micro Vision One CTI Integration Module

Integrates with Trend Micro Vision One Sandbox API for:
- File/URL submission
- Verdict and report retrieval
- STIX export enrichment
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import requests
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog
import time

logger = structlog.get_logger(__name__)


class TrendVisionOneClient:
    """
    Client for interacting with Trend Micro Vision One Sandbox API.

    Provides methods for:
    - Submitting files and URLs for analysis
    - Retrieving analysis verdicts and reports
    - Enriching STIX exports with sandbox results
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.xdr.trendmicro.com",
        timeout: int = 30
    ):
        """
        Initialize Trend Vision One client.

        Args:
            api_key: Trend Vision One API key
            base_url: API base URL (default: global)
            timeout: Request timeout in seconds
        """
        if not api_key:
            raise ValueError("Trend Vision One API key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "AntiFraudAgent/1.0"
        })

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def submit_url(self, url: str) -> Dict[str, Any]:
        """
        Submit a URL for sandbox analysis.

        Args:
            url: URL to analyze

        Returns:
            Submission result with task ID
        """
        try:
            payload = {
                "url": url,
                "arguments": {
                    "timeout": 180
                }
            }

            response = self.session.post(
                f"{self.base_url}/v3.0/sandbox/urls",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            result = {
                "task_id": data.get("id"),
                "url": url,
                "status": "submitted",
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("trend_url_submitted", url=url, task_id=result["task_id"])
            return result

        except requests.RequestException as e:
            logger.error("trend_url_submission_failed", url=url, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def submit_file(self, file_path: str, file_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Submit a file for sandbox analysis.

        Args:
            file_path: Path to file to analyze
            file_name: Optional custom file name

        Returns:
            Submission result with task ID
        """
        try:
            if not file_name:
                file_name = file_path.split("/")[-1]

            with open(file_path, "rb") as f:
                files = {"file": (file_name, f)}
                # Remove Content-Type header for multipart upload
                headers = self.session.headers.copy()
                headers.pop("Content-Type", None)

                response = self.session.post(
                    f"{self.base_url}/v3.0/sandbox/files",
                    files=files,
                    headers=headers,
                    timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()

            result = {
                "task_id": data.get("id"),
                "file_name": file_name,
                "status": "submitted",
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("trend_file_submitted", file=file_name, task_id=result["task_id"])
            return result

        except (requests.RequestException, IOError) as e:
            logger.error("trend_file_submission_failed", file=file_path, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_submission_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get analysis status for a submission.

        Args:
            task_id: Submission task ID

        Returns:
            Status information
        """
        try:
            response = self.session.get(
                f"{self.base_url}/v3.0/sandbox/tasks/{task_id}",
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            status = data.get("status", "unknown")
            result = {
                "task_id": task_id,
                "status": status,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.debug("trend_status_retrieved", task_id=task_id, status=status)
            return result

        except requests.RequestException as e:
            logger.error("trend_status_retrieval_failed", task_id=task_id, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_analysis_report(self, task_id: str, wait_for_completion: bool = True, max_wait: int = 300) -> Optional[Dict[str, Any]]:
        """
        Get full analysis report for a submission.

        Args:
            task_id: Submission task ID
            wait_for_completion: Whether to wait for analysis to complete
            max_wait: Maximum wait time in seconds

        Returns:
            Analysis report or None if not completed
        """
        start_time = time.time()

        while wait_for_completion:
            try:
                status_info = self.get_submission_status(task_id)
                status = status_info.get("status")

                if status == "succeeded":
                    break
                elif status in ["failed", "error"]:
                    logger.error("trend_analysis_failed", task_id=task_id, status=status)
                    return None
                elif time.time() - start_time > max_wait:
                    logger.warning("trend_analysis_timeout", task_id=task_id)
                    return None

                time.sleep(10)  # Poll every 10 seconds

            except Exception as e:
                logger.error("trend_status_check_failed", task_id=task_id, error=str(e))
                return None

        try:
            response = self.session.get(
                f"{self.base_url}/v3.0/sandbox/tasks/{task_id}/report",
                timeout=self.timeout
            )
            response.raise_for_status()
            report = response.json()

            # Extract key findings
            result = {
                "task_id": task_id,
                "risk_level": report.get("riskLevel"),
                "threat_type": report.get("threatType"),
                "analysis_completion_time": report.get("analysisCompletionTime"),
                "detection_names": report.get("detectionNames", []),
                "true_file_type": report.get("trueFileType"),
                "indicators": {
                    "network": report.get("networkIndicators", []),
                    "file": report.get("fileIndicators", []),
                    "registry": report.get("registryIndicators", []),
                },
                "behavior": report.get("behavior", {}),
                "full_report": report,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info(
                "trend_report_retrieved",
                task_id=task_id,
                risk_level=result["risk_level"],
                threat_type=result["threat_type"]
            )
            return result

        except requests.RequestException as e:
            logger.error("trend_report_retrieval_failed", task_id=task_id, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def submit_stix(self, stix_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit STIX 2.1 bundle to Trend Vision One.

        Args:
            stix_bundle: STIX 2.1 bundle dictionary

        Returns:
            Submission result
        """
        try:
            response = self.session.post(
                f"{self.base_url}/v3.0/threatintel/stix",
                json=stix_bundle,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            result = {
                "submission_id": data.get("id"),
                "status": "submitted",
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("trend_stix_submitted", submission_id=result["submission_id"])
            return result

        except requests.RequestException as e:
            logger.error("trend_stix_submission_failed", error=str(e))
            raise

    def analyze_url_sync(self, url: str, max_wait: int = 300) -> Optional[Dict[str, Any]]:
        """
        Submit URL and wait for analysis to complete (synchronous).

        Args:
            url: URL to analyze
            max_wait: Maximum wait time in seconds

        Returns:
            Analysis report or None on failure
        """
        try:
            submission = self.submit_url(url)
            task_id = submission["task_id"]
            return self.get_analysis_report(task_id, wait_for_completion=True, max_wait=max_wait)

        except Exception as e:
            logger.error("trend_sync_analysis_failed", url=url, error=str(e))
            return None

    def enrich_with_sandbox(self, urls: List[str]) -> Dict[str, Any]:
        """
        Enrich multiple URLs with sandbox analysis.

        Args:
            urls: List of URLs to analyze

        Returns:
            Dictionary mapping URLs to analysis results
        """
        enriched = {}

        for url in urls:
            try:
                result = self.analyze_url_sync(url)

                if result:
                    enriched[url] = {
                        "found": True,
                        "data": result,
                        "source": "Trend Vision One",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                else:
                    enriched[url] = {
                        "found": False,
                        "source": "Trend Vision One",
                        "timestamp": datetime.utcnow().isoformat()
                    }

            except Exception as e:
                logger.error("trend_enrichment_failed", url=url, error=str(e))
                enriched[url] = {
                    "found": False,
                    "error": str(e),
                    "source": "Trend Vision One",
                    "timestamp": datetime.utcnow().isoformat()
                }

        logger.info("trend_enrichment_complete", total=len(urls), found=sum(1 for e in enriched.values() if e.get("found")))
        return enriched
