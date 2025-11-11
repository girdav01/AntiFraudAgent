"""
Document Parser Module using Docling

Provides document parsing for PDF, DOCX, and other formats.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import structlog
from docling.document_converter import DocumentConverter
from docling.datamodel.base_models import InputFormat
from docling.datamodel.pipeline_options import PdfPipelineOptions
import pypdf
import re

logger = structlog.get_logger(__name__)


class DocumentParser:
    """
    Document parser using Docling for advanced document extraction.

    Supports:
    - PDF documents
    - DOCX/DOC files
    - Text extraction
    - Structure preservation
    - Metadata extraction
    """

    def __init__(self):
        """Initialize document parser."""
        # Initialize Docling converter
        pipeline_options = PdfPipelineOptions()
        pipeline_options.do_ocr = True  # Enable OCR for scanned PDFs
        pipeline_options.do_table_structure = True

        self.converter = DocumentConverter(
            allowed_formats=[
                InputFormat.PDF,
                InputFormat.DOCX,
                InputFormat.HTML,
                InputFormat.PPTX,
                InputFormat.ASCIIDOC,
                InputFormat.MD
            ],
            pipeline_options=pipeline_options
        )

    def parse_document(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a document and extract content.

        Args:
            file_path: Path to document file

        Returns:
            Parsed document dictionary
        """
        try:
            path = Path(file_path)

            if not path.exists():
                raise FileNotFoundError(f"Document not found: {file_path}")

            # Convert document
            result = self.converter.convert(file_path)

            # Extract content
            content = {
                "file_path": file_path,
                "file_name": path.name,
                "file_type": path.suffix.lower(),
                "text": result.document.export_to_text(),
                "markdown": result.document.export_to_markdown(),
                "success": True,
                "timestamp": datetime.utcnow().isoformat()
            }

            # Extract metadata
            if hasattr(result.document, "metadata"):
                content["metadata"] = {
                    "title": getattr(result.document.metadata, "title", None),
                    "author": getattr(result.document.metadata, "author", None),
                    "creation_date": getattr(result.document.metadata, "creation_date", None),
                    "modification_date": getattr(result.document.metadata, "modification_date", None),
                }
            else:
                content["metadata"] = {}

            # Extract structure
            if hasattr(result.document, "tables"):
                content["tables"] = [
                    {
                        "data": table.export_to_dataframe().to_dict() if hasattr(table, "export_to_dataframe") else {},
                        "caption": getattr(table, "caption", "")
                    }
                    for table in result.document.tables
                ]
            else:
                content["tables"] = []

            # Detect suspicious content
            content["suspicious_patterns"] = self._detect_suspicious_patterns(content["text"])

            # Extract IOCs
            content["iocs"] = self._extract_iocs(content["text"])

            logger.info("document_parsed", file=file_path, pages=len(getattr(result.document, "pages", [])))
            return content

        except Exception as e:
            logger.error("document_parse_failed", file=file_path, error=str(e))
            return {
                "file_path": file_path,
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def parse_pdf_simple(self, file_path: str) -> Dict[str, Any]:
        """
        Simple PDF parsing using pypdf (fallback method).

        Args:
            file_path: Path to PDF file

        Returns:
            Parsed PDF content
        """
        try:
            with open(file_path, "rb") as f:
                pdf_reader = pypdf.PdfReader(f)

                content = {
                    "file_path": file_path,
                    "file_name": Path(file_path).name,
                    "file_type": ".pdf",
                    "num_pages": len(pdf_reader.pages),
                    "text": "",
                    "metadata": {},
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat()
                }

                # Extract metadata
                if pdf_reader.metadata:
                    content["metadata"] = {
                        "title": pdf_reader.metadata.get("/Title"),
                        "author": pdf_reader.metadata.get("/Author"),
                        "subject": pdf_reader.metadata.get("/Subject"),
                        "creator": pdf_reader.metadata.get("/Creator"),
                        "producer": pdf_reader.metadata.get("/Producer"),
                        "creation_date": pdf_reader.metadata.get("/CreationDate"),
                    }

                # Extract text from all pages
                text_parts = []
                for page_num, page in enumerate(pdf_reader.pages):
                    try:
                        page_text = page.extract_text()
                        text_parts.append(f"--- Page {page_num + 1} ---\n{page_text}\n")
                    except Exception as e:
                        logger.warning("pdf_page_extraction_failed", page=page_num, error=str(e))

                content["text"] = "\n".join(text_parts)

                # Detect suspicious patterns
                content["suspicious_patterns"] = self._detect_suspicious_patterns(content["text"])

                # Extract IOCs
                content["iocs"] = self._extract_iocs(content["text"])

                logger.info("pdf_parsed_simple", file=file_path, pages=content["num_pages"])
                return content

        except Exception as e:
            logger.error("pdf_parse_simple_failed", file=file_path, error=str(e))
            return {
                "file_path": file_path,
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def parse_multiple(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Parse multiple documents.

        Args:
            file_paths: List of file paths

        Returns:
            List of parsed document dictionaries
        """
        results = []

        for file_path in file_paths:
            result = self.parse_document(file_path)
            results.append(result)

        logger.info("documents_parsed_multiple", total=len(file_paths), successful=sum(1 for r in results if r.get("success")))
        return results

    def _detect_suspicious_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect suspicious fraud patterns in document text.

        Args:
            text: Text content

        Returns:
            List of suspicious patterns
        """
        patterns = []

        # Fraud keywords
        fraud_keywords = [
            (r'\b(urgent|immediate|act now|limited time|verify account)\b', "urgency"),
            (r'\b(suspended|locked|restricted|blocked)\s+account\b', "account_threat"),
            (r'\b(confirm|verify|update)\s+(password|credentials|information)\b', "credential_request"),
            (r'\b(wire transfer|western union|gift card|cryptocurrency|bitcoin)\b', "payment_method"),
            (r'\b(ssn|social security|credit card number|bank account)\b', "sensitive_info"),
            (r'\b(click here|download now|install|executable)\b', "action_request"),
        ]

        for pattern, category in fraud_keywords:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                patterns.append({
                    "type": "fraud_keyword",
                    "category": category,
                    "matched_text": match.group(0),
                    "position": match.start(),
                    "severity": "medium"
                })

        # Suspicious URLs in documents
        suspicious_tlds = r'\.(tk|ml|ga|cf|gq|xyz)\b'
        matches = re.finditer(suspicious_tlds, text, re.IGNORECASE)
        for match in matches:
            patterns.append({
                "type": "suspicious_tld",
                "matched_text": match.group(0),
                "position": match.start(),
                "severity": "high"
            })

        return patterns

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from document text.

        Args:
            text: Text content

        Returns:
            Dictionary of IOCs by type
        """
        iocs = {
            "urls": [],
            "ips": [],
            "emails": [],
            "domains": [],
            "hashes": []
        }

        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        iocs["urls"] = list(set(re.findall(url_pattern, text)))

        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        # Validate IPs
        iocs["ips"] = [
            ip for ip in potential_ips
            if all(0 <= int(octet) <= 255 for octet in ip.split("."))
        ]

        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["emails"] = list(set(re.findall(email_pattern, text)))

        # Extract domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domains"] = list(set(re.findall(domain_pattern, text)))

        # Extract hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            (r'\b[a-fA-F0-9]{32}\b', "md5"),
            (r'\b[a-fA-F0-9]{40}\b', "sha1"),
            (r'\b[a-fA-F0-9]{64}\b', "sha256")
        ]

        for pattern, hash_type in hash_patterns:
            hashes = re.findall(pattern, text)
            iocs["hashes"].extend([{"hash": h, "type": hash_type} for h in hashes])

        # Deduplicate
        for key in ["urls", "ips", "emails", "domains"]:
            iocs[key] = list(set(iocs[key]))

        return iocs

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """
        Extract security-relevant entities from text.

        Args:
            text: Text content

        Returns:
            Dictionary of extracted entities
        """
        entities = {
            "malware_names": [],
            "cves": [],
            "attack_techniques": [],
            "threat_actors": []
        }

        # Extract CVEs
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        entities["cves"] = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

        # Common malware families
        malware_keywords = [
            r'\b(ransomware|trojan|backdoor|rootkit|spyware|adware)\b',
            r'\b(emotet|trickbot|ryuk|maze|conti|lockbit)\b',
            r'\b(cobalt\s*strike|metasploit|mimikatz)\b'
        ]

        for pattern in malware_keywords:
            matches = re.findall(pattern, text, re.IGNORECASE)
            entities["malware_names"].extend(matches)

        entities["malware_names"] = list(set(entities["malware_names"]))

        return entities
