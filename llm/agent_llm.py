"""
Agent LLM Module

Provides LLM integration for autonomous agents with multiple backend support.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import structlog
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage, AIMessage
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.memory import ConversationBufferMemory
import os

from .local_llm import LocalLLM

logger = structlog.get_logger(__name__)


class AgentLLM:
    """
    Unified LLM interface for autonomous agents.

    Supports:
    - Local models (via llama-cpp)
    - OpenAI API
    - OpenAI-compatible APIs (Ollama, LM Studio, etc.)
    """

    def __init__(
        self,
        backend: str = "local",
        model_path: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model_name: str = "gpt-3.5-turbo",
        temperature: float = 0.7,
        **kwargs
    ):
        """
        Initialize agent LLM.

        Args:
            backend: LLM backend ("local", "openai", "custom")
            model_path: Path to local model (for local backend)
            api_key: API key (for openai/custom backend)
            api_base: Custom API base URL
            model_name: Model name
            temperature: Temperature setting
            **kwargs: Additional backend-specific parameters
        """
        self.backend = backend
        self.temperature = temperature
        self.llm = None

        if backend == "local":
            if not model_path:
                raise ValueError("model_path required for local backend")
            self.llm = LocalLLM(
                model_path=model_path,
                temperature=temperature,
                **kwargs
            )
            logger.info("agent_llm_initialized", backend="local", model=model_path)

        elif backend in ["openai", "custom"]:
            if not api_key and backend == "openai":
                api_key = os.getenv("OPENAI_API_KEY")

            self.llm = ChatOpenAI(
                model_name=model_name,
                temperature=temperature,
                openai_api_key=api_key,
                openai_api_base=api_base,
                **kwargs
            )
            logger.info("agent_llm_initialized", backend=backend, model=model_name)

        else:
            raise ValueError(f"Unsupported backend: {backend}")

    def analyze_content(
        self,
        content: str,
        content_type: str = "web",
        system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze content for fraud and security threats.

        Args:
            content: Content to analyze
            content_type: Type of content (web, document, email, etc.)
            system_prompt: Optional custom system prompt

        Returns:
            Analysis results
        """
        if not system_prompt:
            system_prompt = f"""You are a cybersecurity expert specializing in fraud detection and threat analysis.
Analyze the following {content_type} content for:
- Fraud indicators (phishing, scams, social engineering)
- Malicious patterns
- Security threats
- IOCs (Indicators of Compromise)

Provide a structured analysis with confidence scores and actionable recommendations."""

        try:
            if self.backend == "local":
                # Use local LLM's fraud analysis
                return self.llm.analyze_fraud(content)
            else:
                # Use chat-based analysis
                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=f"Content to analyze:\n\n{content[:4000]}")
                ]

                response = self.llm(messages)

                return {
                    "analysis": response.content,
                    "content_type": content_type,
                    "timestamp": datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error("content_analysis_failed", error=str(e))
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def extract_entities(self, content: str) -> Dict[str, List[str]]:
        """
        Extract security entities from content.

        Args:
            content: Content to analyze

        Returns:
            Extracted entities dictionary
        """
        try:
            if self.backend == "local":
                return self.llm.extract_entities(content)
            else:
                system_prompt = """Extract cybersecurity entities from the content:
- Malware names
- Threat actors
- TTPs (Tactics, Techniques, Procedures)
- CVEs
- IOCs (URLs, IPs, domains, hashes)

Return results in structured format."""

                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=content[:4000])
                ]

                response = self.llm(messages)

                # Parse response (simplified)
                return {
                    "raw_extraction": response.content,
                    "timestamp": datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error("entity_extraction_failed", error=str(e))
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def generate_report(self, findings: Dict[str, Any], report_type: str = "daily") -> str:
        """
        Generate a comprehensive report from findings.

        Args:
            findings: Analysis findings
            report_type: Type of report (daily, incident, summary)

        Returns:
            Generated report text
        """
        try:
            if self.backend == "local":
                return self.llm.generate_report(findings)
            else:
                system_prompt = f"""Generate a professional cybersecurity {report_type} report.
Include:
1. Executive Summary
2. Key Findings
3. Threat Analysis
4. Recommendations
5. IOCs and Technical Details

Format in markdown."""

                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=f"Findings:\n{str(findings)[:5000]}")
                ]

                response = self.llm(messages)
                return response.content

        except Exception as e:
            logger.error("report_generation_failed", error=str(e))
            return f"# Report Generation Error\n\n{str(e)}"

    def create_agent_with_tools(
        self,
        tools: List[Tool],
        agent_type: AgentType = AgentType.ZERO_SHOT_REACT_DESCRIPTION
    ):
        """
        Create a LangChain agent with tools.

        Args:
            tools: List of tools for the agent
            agent_type: Type of agent to create

        Returns:
            Initialized agent
        """
        if self.backend == "local":
            # Local models work better with simpler agent types
            agent_type = AgentType.ZERO_SHOT_REACT_DESCRIPTION

        memory = ConversationBufferMemory(memory_key="chat_history")

        agent = initialize_agent(
            tools=tools,
            llm=self.llm if self.backend != "local" else None,  # LocalLLM needs special handling
            agent=agent_type,
            memory=memory,
            verbose=True
        )

        logger.info("agent_created_with_tools", num_tools=len(tools), agent_type=agent_type.value)
        return agent

    def summarize_threats(self, threats: List[Dict[str, Any]]) -> str:
        """
        Summarize threat data into actionable intelligence.

        Args:
            threats: List of threat findings

        Returns:
            Summary text
        """
        try:
            if self.backend == "local":
                return self.llm.summarize_cti(threats)
            else:
                system_prompt = """Summarize threat intelligence data into actionable insights.
Focus on:
- Priority threats
- Common patterns
- Immediate actions needed
- Risk assessment

Be concise and actionable."""

                threat_summary = "\n".join([
                    f"- {t.get('type', 'unknown')}: {t.get('indicator', 'N/A')}"
                    for t in threats[:50]
                ])

                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=f"Threats:\n{threat_summary}")
                ]

                response = self.llm(messages)
                return response.content

        except Exception as e:
            logger.error("threat_summarization_failed", error=str(e))
            return f"Summarization error: {str(e)}"

    def classify_content(
        self,
        content: str,
        categories: List[str]
    ) -> Dict[str, Any]:
        """
        Classify content into predefined categories.

        Args:
            content: Content to classify
            categories: List of possible categories

        Returns:
            Classification results
        """
        categories_str = ", ".join(categories)

        system_prompt = f"""Classify the following content into one of these categories: {categories_str}

Provide:
1. Primary category
2. Confidence score (0-100)
3. Brief reasoning"""

        try:
            if self.backend == "local":
                prompt = f"{system_prompt}\n\nContent: {content[:2000]}"
                response = self.llm.generate(prompt)
            else:
                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=content[:4000])
                ]
                response = self.llm(messages)
                response = response.content

            return {
                "classification": response,
                "categories": categories,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error("classification_failed", error=str(e))
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def detect_social_engineering(self, content: str) -> Dict[str, Any]:
        """
        Specialized detection for social engineering tactics.

        Args:
            content: Content to analyze

        Returns:
            Social engineering analysis
        """
        system_prompt = """You are an expert in detecting social engineering tactics.

Analyze the content for:
1. Urgency/pressure tactics
2. Authority impersonation
3. Trust exploitation
4. Fear appeals
5. Curiosity baiting
6. Greed appeals

Rate each tactic (0-10) and provide overall risk score."""

        try:
            if self.backend == "local":
                prompt = f"{system_prompt}\n\nContent: {content[:2000]}"
                response = self.llm.generate(prompt)
            else:
                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=content[:4000])
                ]
                response = self.llm(messages)
                response = response.content

            return {
                "analysis": response,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error("social_engineering_detection_failed", error=str(e))
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
