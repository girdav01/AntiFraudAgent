"""
Local LLM Integration Module

Provides integration with local LLM models via LangChain and llama-cpp-python.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import structlog
from langchain.llms import LlamaCpp
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from pathlib import Path

logger = structlog.get_logger(__name__)


class LocalLLM:
    """
    Local LLM wrapper using llama-cpp-python.

    Supports:
    - Local model inference
    - Fraud detection analysis
    - Entity extraction
    - Report generation
    """

    def __init__(
        self,
        model_path: str,
        n_ctx: int = 4096,
        n_gpu_layers: int = 0,
        temperature: float = 0.7,
        max_tokens: int = 512,
        verbose: bool = False
    ):
        """
        Initialize local LLM.

        Args:
            model_path: Path to GGUF model file
            n_ctx: Context window size
            n_gpu_layers: Number of layers to offload to GPU
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            verbose: Enable verbose output
        """
        self.model_path = model_path
        self.n_ctx = n_ctx
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Verify model exists
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        # Initialize callback
        callback_manager = CallbackManager([StreamingStdOutCallbackHandler()]) if verbose else None

        # Initialize LLM
        try:
            self.llm = LlamaCpp(
                model_path=model_path,
                n_ctx=n_ctx,
                n_gpu_layers=n_gpu_layers,
                temperature=temperature,
                max_tokens=max_tokens,
                callback_manager=callback_manager,
                verbose=verbose,
                n_batch=512,
                f16_kv=True
            )

            logger.info("local_llm_initialized", model=model_path, n_ctx=n_ctx, gpu_layers=n_gpu_layers)

        except Exception as e:
            logger.error("local_llm_init_failed", error=str(e))
            raise

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate text from prompt.

        Args:
            prompt: Input prompt
            **kwargs: Additional generation parameters

        Returns:
            Generated text
        """
        try:
            response = self.llm(prompt, **kwargs)
            logger.debug("llm_generation_complete", prompt_length=len(prompt), response_length=len(response))
            return response

        except Exception as e:
            logger.error("llm_generation_failed", error=str(e))
            raise

    def analyze_fraud(self, content: str) -> Dict[str, Any]:
        """
        Analyze content for fraud indicators.

        Args:
            content: Content to analyze

        Returns:
            Fraud analysis results
        """
        prompt = f"""You are a cybersecurity expert analyzing content for fraud and social engineering indicators.

Analyze the following content and identify:
1. Fraud type (phishing, scam, social engineering, etc.)
2. Confidence score (0-100)
3. Key fraud indicators found
4. Recommended actions

Content:
{content[:2000]}  # Limit content length

Provide a structured analysis in the following format:
FRAUD_TYPE: <type>
CONFIDENCE: <score>
INDICATORS: <comma-separated list>
ACTIONS: <recommended actions>
EXPLANATION: <detailed explanation>"""

        try:
            response = self.generate(prompt)

            # Parse response
            analysis = {
                "fraud_type": self._extract_field(response, "FRAUD_TYPE"),
                "confidence": self._extract_field(response, "CONFIDENCE"),
                "indicators": self._extract_field(response, "INDICATORS", is_list=True),
                "actions": self._extract_field(response, "ACTIONS"),
                "explanation": self._extract_field(response, "EXPLANATION"),
                "raw_response": response,
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("fraud_analysis_complete", fraud_type=analysis["fraud_type"], confidence=analysis["confidence"])
            return analysis

        except Exception as e:
            logger.error("fraud_analysis_failed", error=str(e))
            return {
                "fraud_type": "unknown",
                "confidence": 0,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def extract_entities(self, content: str) -> Dict[str, List[str]]:
        """
        Extract security entities from content.

        Args:
            content: Content to analyze

        Returns:
            Extracted entities
        """
        prompt = f"""Extract cybersecurity entities from the following content.

Identify:
1. Malware names
2. Threat actor groups
3. Attack techniques/TTPs
4. CVE identifiers
5. IOCs (URLs, IPs, domains, hashes, emails)

Content:
{content[:2000]}

Provide results in the following format:
MALWARE: <comma-separated list>
ACTORS: <comma-separated list>
TTPS: <comma-separated list>
CVES: <comma-separated list>
IOCS: <comma-separated list>"""

        try:
            response = self.generate(prompt)

            entities = {
                "malware": self._extract_field(response, "MALWARE", is_list=True),
                "actors": self._extract_field(response, "ACTORS", is_list=True),
                "ttps": self._extract_field(response, "TTPS", is_list=True),
                "cves": self._extract_field(response, "CVES", is_list=True),
                "iocs": self._extract_field(response, "IOCS", is_list=True),
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.info("entities_extracted", total=sum(len(v) for v in entities.values() if isinstance(v, list)))
            return entities

        except Exception as e:
            logger.error("entity_extraction_failed", error=str(e))
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def generate_report(self, findings: Dict[str, Any]) -> str:
        """
        Generate a comprehensive report from findings.

        Args:
            findings: Analysis findings dictionary

        Returns:
            Generated report text
        """
        prompt = f"""Generate a comprehensive cybersecurity threat intelligence report based on the following findings.

Findings:
{str(findings)[:3000]}

Create a professional report with:
1. Executive Summary
2. Key Findings
3. Threat Analysis
4. IOCs Identified
5. Recommendations
6. Conclusion

Format the report in markdown."""

        try:
            report = self.generate(prompt, max_tokens=1024)
            logger.info("report_generated", length=len(report))
            return report

        except Exception as e:
            logger.error("report_generation_failed", error=str(e))
            return f"# Error Generating Report\n\nError: {str(e)}"

    def summarize_cti(self, cti_data: List[Dict[str, Any]]) -> str:
        """
        Summarize CTI data into actionable intelligence.

        Args:
            cti_data: List of CTI findings

        Returns:
            Summary text
        """
        # Prepare data summary
        data_summary = "\n".join([
            f"- {item.get('type', 'unknown')}: {item.get('indicator', 'N/A')} (Source: {item.get('source', 'N/A')})"
            for item in cti_data[:50]  # Limit to 50 items
        ])

        prompt = f"""Summarize the following threat intelligence data into actionable insights.

CTI Data:
{data_summary}

Provide:
1. Key threats identified
2. Common patterns
3. Priority recommendations
4. Risk assessment

Keep the summary concise and actionable."""

        try:
            summary = self.generate(prompt, max_tokens=512)
            logger.info("cti_summarized", items=len(cti_data))
            return summary

        except Exception as e:
            logger.error("cti_summarization_failed", error=str(e))
            return f"Summarization error: {str(e)}"

    def _extract_field(self, text: str, field_name: str, is_list: bool = False) -> Union[str, List[str]]:
        """
        Extract field value from LLM response.

        Args:
            text: Response text
            field_name: Field name to extract
            is_list: Whether field contains comma-separated list

        Returns:
            Extracted field value
        """
        import re

        pattern = rf"{field_name}:\s*(.+?)(?:\n[A-Z_]+:|$)"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)

        if not match:
            return [] if is_list else ""

        value = match.group(1).strip()

        if is_list:
            # Split by comma and clean
            items = [item.strip() for item in value.split(",")]
            return [item for item in items if item and item.lower() not in ["none", "n/a", ""]]

        return value

    def create_chain(self, template: str) -> LLMChain:
        """
        Create a LangChain LLMChain with custom template.

        Args:
            template: Prompt template string

        Returns:
            LLMChain instance
        """
        prompt = PromptTemplate(
            template=template,
            input_variables=[var for var in re.findall(r'\{(\w+)\}', template)]
        )

        chain = LLMChain(llm=self.llm, prompt=prompt)
        logger.debug("llm_chain_created")
        return chain
