"""
Web Crawler Module using Crawl4AI

Provides advanced web crawling and content extraction capabilities.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from crawl4ai import AsyncWebCrawler
from crawl4ai.extraction_strategy import LLMExtractionStrategy
import structlog
from bs4 import BeautifulSoup
import re

logger = structlog.get_logger(__name__)


class WebCrawler:
    """
    Advanced web crawler using Crawl4AI for content extraction.

    Features:
    - Asynchronous crawling
    - JavaScript rendering
    - Content cleaning and extraction
    - Link discovery
    - Fraud pattern detection
    """

    def __init__(
        self,
        user_agent: str = "AntiFraudAgent/1.0",
        timeout: int = 30,
        max_depth: int = 2
    ):
        """
        Initialize web crawler.

        Args:
            user_agent: User agent string
            timeout: Request timeout in seconds
            max_depth: Maximum crawl depth
        """
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_depth = max_depth

    async def crawl_url(
        self,
        url: str,
        extract_links: bool = True,
        render_js: bool = False
    ) -> Dict[str, Any]:
        """
        Crawl a single URL and extract content.

        Args:
            url: URL to crawl
            extract_links: Whether to extract links
            render_js: Whether to render JavaScript

        Returns:
            Crawled content dictionary
        """
        try:
            async with AsyncWebCrawler(verbose=False) as crawler:
                result = await crawler.arun(
                    url=url,
                    bypass_cache=True,
                    word_count_threshold=10,
                    user_agent=self.user_agent
                )

                # Extract content
                content = {
                    "url": url,
                    "title": result.metadata.get("title", ""),
                    "description": result.metadata.get("description", ""),
                    "html": result.html,
                    "markdown": result.markdown,
                    "cleaned_html": result.cleaned_html,
                    "links": result.links if extract_links else [],
                    "images": result.media.get("images", []) if hasattr(result, "media") else [],
                    "metadata": result.metadata,
                    "success": result.success,
                    "timestamp": datetime.utcnow().isoformat()
                }

                # Extract text content
                soup = BeautifulSoup(result.cleaned_html, "lxml")
                content["text"] = soup.get_text(separator=" ", strip=True)

                # Extract suspicious patterns
                content["suspicious_patterns"] = self._detect_suspicious_patterns(content["text"])

                logger.info("web_crawl_success", url=url, links=len(content["links"]))
                return content

        except Exception as e:
            logger.error("web_crawl_failed", url=url, error=str(e))
            return {
                "url": url,
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    async def crawl_multiple(
        self,
        urls: List[str],
        parallel: bool = True,
        max_concurrent: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Crawl multiple URLs concurrently.

        Args:
            urls: List of URLs to crawl
            parallel: Whether to crawl in parallel
            max_concurrent: Maximum concurrent requests

        Returns:
            List of crawled content dictionaries
        """
        results = []

        if parallel:
            semaphore = asyncio.Semaphore(max_concurrent)

            async def crawl_with_semaphore(url):
                async with semaphore:
                    return await self.crawl_url(url)

            tasks = [crawl_with_semaphore(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle exceptions
            results = [
                r if not isinstance(r, Exception) else {
                    "url": urls[i],
                    "success": False,
                    "error": str(r),
                    "timestamp": datetime.utcnow().isoformat()
                }
                for i, r in enumerate(results)
            ]
        else:
            for url in urls:
                result = await self.crawl_url(url)
                results.append(result)

        logger.info("web_crawl_multiple_complete", total=len(urls), successful=sum(1 for r in results if r.get("success")))
        return results

    def _detect_suspicious_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect suspicious fraud patterns in text content.

        Args:
            text: Text content to analyze

        Returns:
            List of detected suspicious patterns
        """
        patterns = []

        # Fraud indicators
        fraud_keywords = [
            r'\b(urgent|immediate|act now|limited time|verify account|suspended account)\b',
            r'\b(click here|download now|claim reward|prize winner)\b',
            r'\b(wire transfer|western union|gift card|cryptocurrency|bitcoin)\b',
            r'\b(social security number|ssn|credit card|bank account)\b',
            r'\b(password|login credentials|pin|security code)\b',
        ]

        for i, pattern in enumerate(fraud_keywords):
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                patterns.append({
                    "type": "fraud_keyword",
                    "pattern_id": i,
                    "matched_text": match.group(0),
                    "position": match.start(),
                    "severity": "medium"
                })

        # Suspicious URLs
        suspicious_url_patterns = [
            r'(http[s]?://[^\s]+\.(tk|ml|ga|cf|gq))',  # Free TLDs
            r'(http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IP addresses
        ]

        for pattern in suspicious_url_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                patterns.append({
                    "type": "suspicious_url",
                    "matched_text": match.group(0),
                    "position": match.start(),
                    "severity": "high"
                })

        # Phone number patterns (potential phishing)
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        matches = re.finditer(phone_pattern, text)
        if sum(1 for _ in matches) > 3:  # Multiple phone numbers might indicate spam
            patterns.append({
                "type": "excessive_phone_numbers",
                "severity": "low"
            })

        return patterns

    async def deep_crawl(
        self,
        start_url: str,
        max_pages: int = 50,
        same_domain_only: bool = True
    ) -> Dict[str, Any]:
        """
        Perform deep crawl starting from a URL.

        Args:
            start_url: Starting URL
            max_pages: Maximum pages to crawl
            same_domain_only: Only crawl pages on same domain

        Returns:
            Deep crawl results
        """
        from urllib.parse import urlparse

        visited = set()
        to_visit = [start_url]
        results = []
        start_domain = urlparse(start_url).netloc

        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)

            if current_url in visited:
                continue

            visited.add(current_url)

            # Crawl page
            page_result = await self.crawl_url(current_url)
            results.append(page_result)

            if not page_result.get("success"):
                continue

            # Extract and queue new links
            for link in page_result.get("links", []):
                if link not in visited and link not in to_visit:
                    if same_domain_only:
                        link_domain = urlparse(link).netloc
                        if link_domain == start_domain:
                            to_visit.append(link)
                    else:
                        to_visit.append(link)

        logger.info(
            "deep_crawl_complete",
            start_url=start_url,
            pages_crawled=len(visited),
            pages_queued=len(to_visit)
        )

        return {
            "start_url": start_url,
            "pages_crawled": len(visited),
            "pages": results,
            "unvisited_urls": to_visit,
            "timestamp": datetime.utcnow().isoformat()
        }

    def extract_iocs(self, crawl_results: Dict[str, Any]) -> List[str]:
        """
        Extract IOCs from crawl results.

        Args:
            crawl_results: Results from crawl operation

        Returns:
            List of extracted IOCs
        """
        iocs = []
        text = crawl_results.get("text", "")

        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        iocs.extend(urls)

        # Extract IP addresses
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        iocs.extend(ips)

        # Extract email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        iocs.extend(emails)

        # Extract hashes (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        hashes = re.findall(hash_pattern, text)
        iocs.extend(hashes)

        # Deduplicate
        iocs = list(set(iocs))

        logger.info("iocs_extracted_from_crawl", count=len(iocs))
        return iocs


def crawl_sync(url: str, **kwargs) -> Dict[str, Any]:
    """
    Synchronous wrapper for crawl_url.

    Args:
        url: URL to crawl
        **kwargs: Additional arguments for crawl_url

    Returns:
        Crawled content dictionary
    """
    crawler = WebCrawler()
    return asyncio.run(crawler.crawl_url(url, **kwargs))
