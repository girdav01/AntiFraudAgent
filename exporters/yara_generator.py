"""
YARA Rule Generation from Fraud Findings

Automatically generates YARA rules from detected fraud patterns and IOCs.
"""

import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import structlog
import re
from pathlib import Path
import hashlib

logger = structlog.get_logger(__name__)


class YARAGenerator:
    """
    Generates YARA rules from fraud findings.

    Features:
    - Automatic rule generation from fraud patterns
    - String extraction from malicious content
    - Metadata inclusion (author, date, severity)
    - Rule validation
    - Multi-rule bundle export
    """

    def __init__(
        self,
        author: str = "AntiFraudAgent",
        organization: str = "AntiFraud CTI"
    ):
        """
        Initialize YARA generator.

        Args:
            author: Rule author name
            organization: Organization name
        """
        self.author = author
        self.organization = organization

        logger.info("yara_generator_initialized", author=author)

    def generate_rule_from_finding(
        self,
        finding: Dict[str, Any],
        rule_name: Optional[str] = None
    ) -> str:
        """
        Generate YARA rule from a fraud finding.

        Args:
            finding: Fraud finding dictionary
            rule_name: Optional custom rule name

        Returns:
            YARA rule string
        """
        fraud_type = finding.get("fraud_type", "unknown")
        confidence = finding.get("confidence", 0)
        source_url = finding.get("source_url", "")

        # Generate rule name
        if not rule_name:
            rule_name = self._generate_rule_name(fraud_type, source_url)

        # Extract strings
        strings = self._extract_strings(finding)

        # Build metadata
        metadata = {
            "author": self.author,
            "organization": self.organization,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "description": f"Detected {fraud_type} with {confidence}% confidence",
            "fraud_type": fraud_type,
            "confidence": str(confidence),
            "source": source_url,
            "severity": self._determine_severity(confidence)
        }

        # Build rule
        rule = self._build_rule(rule_name, metadata, strings)

        logger.info("yara_rule_generated", rule_name=rule_name, strings=len(strings))

        return rule

    def generate_rules_from_findings(
        self,
        findings: List[Dict[str, Any]],
        min_confidence: int = 70
    ) -> List[str]:
        """
        Generate multiple YARA rules from findings.

        Args:
            findings: List of fraud findings
            min_confidence: Minimum confidence threshold

        Returns:
            List of YARA rule strings
        """
        rules = []

        for i, finding in enumerate(findings):
            confidence = finding.get("confidence", 0)

            if confidence >= min_confidence:
                try:
                    rule = self.generate_rule_from_finding(finding)
                    rules.append(rule)
                except Exception as e:
                    logger.error("rule_generation_failed", finding_index=i, error=str(e))

        logger.info("rules_generated_batch", count=len(rules), total_findings=len(findings))

        return rules

    def generate_ioc_rule(
        self,
        iocs: List[str],
        rule_name: str,
        description: str,
        tags: Optional[List[str]] = None
    ) -> str:
        """
        Generate YARA rule from IOCs.

        Args:
            iocs: List of IOCs (URLs, domains, IPs, hashes)
            rule_name: Rule name
            description: Rule description
            tags: Optional tags

        Returns:
            YARA rule string
        """
        # Categorize IOCs
        urls = []
        domains = []
        ips = []
        hashes = []
        emails = []

        for ioc in iocs:
            ioc = ioc.strip()

            if ioc.startswith("http://") or ioc.startswith("https://"):
                urls.append(ioc)
            elif "@" in ioc:
                emails.append(ioc)
            elif len(ioc) in [32, 40, 64]:  # Hash
                hashes.append(ioc)
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
                ips.append(ioc)
            elif "." in ioc:
                domains.append(ioc)

        # Build strings section
        strings_section = []
        string_conditions = []
        counter = 0

        for url in urls:
            strings_section.append(f'$url{counter} = "{self._escape_string(url)}" wide ascii')
            string_conditions.append(f"$url{counter}")
            counter += 1

        for domain in domains:
            strings_section.append(f'$domain{counter} = "{self._escape_string(domain)}" wide ascii')
            string_conditions.append(f"$domain{counter}")
            counter += 1

        for ip in ips:
            strings_section.append(f'$ip{counter} = "{self._escape_string(ip)}" wide ascii')
            string_conditions.append(f"$ip{counter}")
            counter += 1

        for email in emails:
            strings_section.append(f'$email{counter} = "{self._escape_string(email)}" wide ascii')
            string_conditions.append(f"$email{counter}")
            counter += 1

        for hash_val in hashes:
            strings_section.append(f'$hash{counter} = "{self._escape_string(hash_val)}" nocase')
            string_conditions.append(f"$hash{counter}")
            counter += 1

        # Build metadata
        metadata = {
            "author": self.author,
            "organization": self.organization,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "description": description,
            "ioc_count": str(len(iocs))
        }

        # Build rule
        rule_parts = [f"rule {rule_name}"]

        # Add tags
        if tags:
            rule_parts[-1] += f" : {' '.join(tags)}"

        rule_parts.append("{")

        # Metadata
        rule_parts.append("    meta:")
        for key, value in metadata.items():
            rule_parts.append(f'        {key} = "{value}"')

        # Strings
        if strings_section:
            rule_parts.append("")
            rule_parts.append("    strings:")
            for string_def in strings_section:
                rule_parts.append(f"        {string_def}")

        # Condition
        rule_parts.append("")
        rule_parts.append("    condition:")
        if string_conditions:
            condition = " or ".join(string_conditions)
            rule_parts.append(f"        {condition}")
        else:
            rule_parts.append("        false")

        rule_parts.append("}")

        rule = "\n".join(rule_parts)

        logger.info("ioc_rule_generated", rule_name=rule_name, iocs=len(iocs))

        return rule

    def generate_pattern_rule(
        self,
        patterns: List[str],
        rule_name: str,
        description: str,
        fraud_type: str
    ) -> str:
        """
        Generate YARA rule from text patterns.

        Args:
            patterns: List of text patterns
            rule_name: Rule name
            description: Rule description
            fraud_type: Type of fraud

        Returns:
            YARA rule string
        """
        strings_section = []
        string_conditions = []

        for i, pattern in enumerate(patterns):
            # Escape special characters
            escaped = self._escape_string(pattern)
            strings_section.append(f'$pattern{i} = "{escaped}" wide ascii nocase')
            string_conditions.append(f"$pattern{i}")

        metadata = {
            "author": self.author,
            "organization": self.organization,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "description": description,
            "fraud_type": fraud_type,
            "pattern_count": str(len(patterns))
        }

        # Build rule with "any of them" condition
        rule_parts = [
            f"rule {rule_name}",
            "{",
            "    meta:"
        ]

        for key, value in metadata.items():
            rule_parts.append(f'        {key} = "{value}"')

        rule_parts.append("")
        rule_parts.append("    strings:")
        for string_def in strings_section:
            rule_parts.append(f"        {string_def}")

        rule_parts.append("")
        rule_parts.append("    condition:")
        rule_parts.append(f"        {len(patterns) // 2} of them")  # Match at least half
        rule_parts.append("}")

        return "\n".join(rule_parts)

    def save_rules(self, rules: List[str], output_path: str):
        """
        Save YARA rules to file.

        Args:
            rules: List of YARA rule strings
            output_path: Output file path
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            # Add header
            f.write("/*\n")
            f.write(" * AntiFraud Agent - Auto-Generated YARA Rules\n")
            f.write(f" * Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f" * Author: {self.author}\n")
            f.write(f" * Organization: {self.organization}\n")
            f.write(f" * Rule Count: {len(rules)}\n")
            f.write(" */\n\n")

            # Write rules
            for rule in rules:
                f.write(rule)
                f.write("\n\n")

        logger.info("rules_saved", path=output_path, count=len(rules))

    def _extract_strings(self, finding: Dict[str, Any]) -> List[str]:
        """Extract relevant strings from finding."""
        strings = set()

        # Extract from indicators
        indicators = finding.get("indicators", [])
        if isinstance(indicators, list):
            for indicator in indicators:
                if isinstance(indicator, str):
                    strings.add(indicator)

        # Extract from suspicious patterns
        patterns = finding.get("suspicious_patterns", [])
        if isinstance(patterns, list):
            for pattern in patterns:
                if isinstance(pattern, dict):
                    matched_text = pattern.get("matched_text")
                    if matched_text:
                        strings.add(matched_text)

        # Extract from source URL
        source_url = finding.get("source_url", "")
        if source_url:
            # Extract domain
            domain = re.findall(r'https?://([^/]+)', source_url)
            if domain:
                strings.add(domain[0])

        # Limit and filter
        filtered = [s for s in strings if len(s) >= 4 and len(s) <= 100]

        return list(filtered)[:20]  # Limit to 20 strings

    def _build_rule(
        self,
        rule_name: str,
        metadata: Dict[str, str],
        strings: List[str]
    ) -> str:
        """Build complete YARA rule."""
        rule_parts = [
            f"rule {rule_name}",
            "{",
            "    meta:"
        ]

        # Add metadata
        for key, value in metadata.items():
            rule_parts.append(f'        {key} = "{value}"')

        # Add strings
        if strings:
            rule_parts.append("")
            rule_parts.append("    strings:")

            for i, string in enumerate(strings):
                escaped = self._escape_string(string)
                rule_parts.append(f'        $str{i} = "{escaped}" wide ascii nocase')

        # Add condition
        rule_parts.append("")
        rule_parts.append("    condition:")
        if strings:
            # Require at least 2 string matches or 1 if only 1 string
            threshold = min(2, len(strings))
            rule_parts.append(f"        {threshold} of them")
        else:
            rule_parts.append("        false")

        rule_parts.append("}")

        return "\n".join(rule_parts)

    def _generate_rule_name(self, fraud_type: str, source_url: str) -> str:
        """Generate sanitized rule name."""
        # Create base name from fraud type
        base = fraud_type.replace(" ", "_").replace("-", "_")

        # Add URL hash for uniqueness
        url_hash = hashlib.md5(source_url.encode()).hexdigest()[:8]

        rule_name = f"fraud_{base}_{url_hash}"

        # Sanitize (YARA rules must be alphanumeric + underscore)
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '', rule_name)

        return rule_name

    def _escape_string(self, s: str) -> str:
        """Escape special characters for YARA."""
        # Escape backslashes first
        s = s.replace("\\", "\\\\")
        # Escape quotes
        s = s.replace('"', '\\"')
        # Escape newlines
        s = s.replace("\n", "\\n")
        s = s.replace("\r", "\\r")
        s = s.replace("\t", "\\t")

        return s

    def _determine_severity(self, confidence: int) -> str:
        """Determine severity from confidence."""
        if confidence >= 90:
            return "critical"
        elif confidence >= 70:
            return "high"
        elif confidence >= 50:
            return "medium"
        else:
            return "low"

    def validate_rule(self, rule: str) -> Dict[str, Any]:
        """
        Validate YARA rule syntax.

        Args:
            rule: YARA rule string

        Returns:
            Validation result
        """
        try:
            # Basic syntax checks
            if not rule.strip().startswith("rule "):
                return {
                    "valid": False,
                    "error": "Rule must start with 'rule ' keyword"
                }

            if "{" not in rule or "}" not in rule:
                return {
                    "valid": False,
                    "error": "Rule must have opening and closing braces"
                }

            if "condition:" not in rule:
                return {
                    "valid": False,
                    "error": "Rule must have a condition section"
                }

            # Try to import yara if available for full validation
            try:
                import yara
                yara.compile(source=rule)
                return {"valid": True}
            except ImportError:
                # yara-python not installed, use basic validation
                return {"valid": True, "warning": "Full validation not available (yara-python not installed)"}
            except Exception as e:
                return {"valid": False, "error": str(e)}

        except Exception as e:
            return {"valid": False, "error": str(e)}
