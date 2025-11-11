#!/usr/bin/env python3
"""
AntiFraud Agent - Main Entry Point

Run the autonomous fraud detection agent with daily scheduling.
"""

import asyncio
import sys
import logging
from pathlib import Path
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

from config.config_manager import ConfigManager
from agents.fraud_agent import FraudDetectionAgent
from agents.scheduler import AgentScheduler
from llm.agent_llm import AgentLLM
from cti.manager import CTIManager
from config.notifier import EmailNotifier


async def send_notification(results: dict, status: str):
    """Callback for sending email notifications."""
    try:
        config = config_manager.load_config()

        if not config.get("email_enabled", False):
            logger.info("email_notifications_disabled")
            return

        notifier = EmailNotifier(
            smtp_host=config["smtp_host"],
            smtp_port=config["smtp_port"],
            username=config["smtp_username"],
            password=config["smtp_password"],
            from_address=config["from_address"],
            use_tls=config.get("use_tls", True),
            use_ssl=config.get("use_ssl", False)
        )

        recipients = config.get("recipient_addresses", [])

        if recipients:
            success = notifier.send_daily_report(recipients, results, status)
            if success:
                logger.info("notification_sent", recipients=len(recipients))
            else:
                logger.error("notification_failed")

    except Exception as e:
        logger.error("notification_error", error=str(e))


def initialize_components(config: dict):
    """Initialize all components."""
    logger.info("initializing_components")

    # Initialize LLM
    llm = AgentLLM(
        backend=config.get("llm_backend", "local"),
        model_path=config.get("model_path"),
        api_key=config.get("api_key"),
        model_name=config.get("model_name", "gpt-3.5-turbo"),
        temperature=config.get("temperature", 0.7)
    )

    # Initialize CTI Manager
    cti_manager = CTIManager(
        urlhaus_enabled=config.get("urlhaus_enabled", True),
        virustotal_api_key=config.get("virustotal_api_key"),
        trend_api_key=config.get("trend_api_key"),
        trend_base_url=config.get("trend_base_url", "https://api.xdr.trendmicro.com")
    )

    # Initialize Agent
    agent = FraudDetectionAgent(config, llm, cti_manager)

    logger.info("components_initialized")

    return agent


def main():
    """Main entry point."""
    try:
        logger.info("antifraud_agent_starting")

        # Load configuration
        global config_manager
        config_manager = ConfigManager()
        config = config_manager.load_config()

        # Initialize components
        agent = initialize_components(config)

        # Initialize scheduler
        schedule_config = {
            "daily_enabled": config.get("daily_enabled", True),
            "daily_time": config.get("daily_time", "07:00"),
            "timezone": config.get("timezone", "America/Montreal"),
            "interval_enabled": config.get("interval_enabled", False),
            "interval_hours": config.get("interval_hours", 6)
        }

        scheduler = AgentScheduler(
            agent=agent,
            schedule_config=schedule_config,
            notification_callback=send_notification
        )

        # Start scheduler
        scheduler.start()

        logger.info(
            "antifraud_agent_started",
            next_run=scheduler.get_next_run_time().isoformat() if scheduler.get_next_run_time() else None
        )

        # Keep running
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            logger.info("shutdown_requested")
            scheduler.stop()

    except Exception as e:
        logger.error("startup_error", error=str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
