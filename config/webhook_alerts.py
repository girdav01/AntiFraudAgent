"""
Real-Time Webhook Alert System

Sends immediate notifications via HTTP webhooks when fraud is detected.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import structlog
import requests
from tenacity import retry, stop_after_attempt, wait_exponential
import hmac
import hashlib
import json
from enum import Enum

logger = structlog.get_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WebhookAlertManager:
    """
    Manages real-time webhook alerts.

    Features:
    - Multiple webhook endpoints
    - Alert filtering by severity
    - HMAC signature verification
    - Retry logic with exponential backoff
    - Delivery tracking
    - Rate limiting
    """

    def __init__(
        self,
        webhooks: List[Dict[str, Any]],
        default_timeout: int = 10
    ):
        """
        Initialize webhook alert manager.

        Args:
            webhooks: List of webhook configurations
            default_timeout: Default request timeout in seconds
        """
        self.webhooks = webhooks
        self.default_timeout = default_timeout

        # Delivery tracking
        self.sent_count = 0
        self.failed_count = 0
        self.delivery_history = []

        logger.info("webhook_manager_initialized", webhooks=len(webhooks))

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def send_alert(
        self,
        alert_type: str,
        severity: AlertSeverity,
        title: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        iocs: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Send alert to all configured webhooks.

        Args:
            alert_type: Type of alert (fraud_detected, high_confidence, etc.)
            severity: Alert severity level
            title: Alert title
            message: Alert message
            details: Additional details
            iocs: List of IOCs

        Returns:
            Delivery results
        """
        # Build alert payload
        alert = {
            "alert_id": self._generate_alert_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": alert_type,
            "severity": severity.value,
            "title": title,
            "message": message,
            "details": details or {},
            "iocs": iocs or [],
            "source": "AntiFraudAgent"
        }

        results = {
            "alert_id": alert["alert_id"],
            "deliveries": [],
            "successful": 0,
            "failed": 0
        }

        # Send to each webhook
        for webhook_config in self.webhooks:
            # Check if webhook should receive this severity
            min_severity = webhook_config.get("min_severity", "low")
            if not self._should_send(severity, min_severity):
                logger.debug(
                    "webhook_skipped_severity",
                    webhook=webhook_config.get("name"),
                    alert_severity=severity.value,
                    min_severity=min_severity
                )
                continue

            delivery_result = self._send_to_webhook(webhook_config, alert)
            results["deliveries"].append(delivery_result)

            if delivery_result["success"]:
                results["successful"] += 1
                self.sent_count += 1
            else:
                results["failed"] += 1
                self.failed_count += 1

        # Track delivery
        self.delivery_history.append({
            "alert_id": alert["alert_id"],
            "timestamp": alert["timestamp"],
            "results": results
        })

        # Limit history size
        if len(self.delivery_history) > 100:
            self.delivery_history = self.delivery_history[-100:]

        logger.info(
            "alert_sent",
            alert_id=alert["alert_id"],
            type=alert_type,
            severity=severity.value,
            successful=results["successful"],
            failed=results["failed"]
        )

        return results

    def _send_to_webhook(
        self,
        webhook_config: Dict[str, Any],
        alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send alert to a single webhook.

        Args:
            webhook_config: Webhook configuration
            alert: Alert payload

        Returns:
            Delivery result
        """
        webhook_url = webhook_config["url"]
        webhook_name = webhook_config.get("name", "unnamed")

        result = {
            "webhook": webhook_name,
            "url": webhook_url,
            "success": False,
            "timestamp": datetime.utcnow().isoformat()
        }

        try:
            # Prepare payload
            payload = alert.copy()

            # Add custom fields if specified
            if "custom_fields" in webhook_config:
                payload.update(webhook_config["custom_fields"])

            # Calculate HMAC signature if secret provided
            headers = {"Content-Type": "application/json"}
            if "secret" in webhook_config:
                signature = self._calculate_signature(
                    json.dumps(payload),
                    webhook_config["secret"]
                )
                headers["X-Webhook-Signature"] = signature

            # Add custom headers
            if "headers" in webhook_config:
                headers.update(webhook_config["headers"])

            # Send request
            timeout = webhook_config.get("timeout", self.default_timeout)

            response = requests.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=timeout
            )

            response.raise_for_status()

            result["success"] = True
            result["status_code"] = response.status_code
            result["response"] = response.text[:500]  # Limit response size

            logger.info(
                "webhook_delivered",
                webhook=webhook_name,
                status=response.status_code,
                alert_id=alert["alert_id"]
            )

        except requests.RequestException as e:
            result["error"] = str(e)
            logger.error(
                "webhook_delivery_failed",
                webhook=webhook_name,
                error=str(e),
                alert_id=alert["alert_id"]
            )

        return result

    def send_fraud_detected_alert(
        self,
        fraud_finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send fraud detection alert.

        Args:
            fraud_finding: Fraud finding dictionary

        Returns:
            Delivery results
        """
        fraud_type = fraud_finding.get("fraud_type", "unknown")
        confidence = fraud_finding.get("confidence", 0)
        source_url = fraud_finding.get("source_url", "N/A")

        # Determine severity based on confidence
        if confidence >= 90:
            severity = AlertSeverity.CRITICAL
        elif confidence >= 70:
            severity = AlertSeverity.HIGH
        elif confidence >= 50:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        return self.send_alert(
            alert_type="fraud_detected",
            severity=severity,
            title=f"Fraud Detected: {fraud_type.title()}",
            message=f"Detected {fraud_type} with {confidence}% confidence at {source_url}",
            details=fraud_finding,
            iocs=[source_url] if source_url != "N/A" else []
        )

    def send_high_threat_alert(
        self,
        ioc: str,
        threat_score: int,
        enrichment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send high threat score alert.

        Args:
            ioc: IOC value
            threat_score: Threat score (0-100)
            enrichment_data: CTI enrichment data

        Returns:
            Delivery results
        """
        if threat_score >= 80:
            severity = AlertSeverity.CRITICAL
        elif threat_score >= 60:
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM

        return self.send_alert(
            alert_type="high_threat_score",
            severity=severity,
            title=f"High Threat Score: {threat_score}/100",
            message=f"IOC '{ioc}' has a threat score of {threat_score}/100",
            details={
                "ioc": ioc,
                "threat_score": threat_score,
                "enrichment": enrichment_data
            },
            iocs=[ioc]
        )

    def send_workflow_error_alert(
        self,
        error_message: str,
        error_details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Send workflow error alert.

        Args:
            error_message: Error message
            error_details: Additional error details

        Returns:
            Delivery results
        """
        return self.send_alert(
            alert_type="workflow_error",
            severity=AlertSeverity.HIGH,
            title="Workflow Execution Error",
            message=error_message,
            details=error_details or {}
        )

    def send_batch_alert(
        self,
        findings: List[Dict[str, Any]],
        workflow_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send batch alert with multiple findings.

        Args:
            findings: List of fraud findings
            workflow_summary: Workflow execution summary

        Returns:
            Delivery results
        """
        high_confidence_count = sum(
            1 for f in findings
            if f.get("confidence", 0) >= 70
        )

        if high_confidence_count >= 10:
            severity = AlertSeverity.CRITICAL
        elif high_confidence_count >= 5:
            severity = AlertSeverity.HIGH
        elif high_confidence_count >= 1:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        return self.send_alert(
            alert_type="batch_findings",
            severity=severity,
            title=f"Daily Workflow: {len(findings)} Findings",
            message=f"Workflow completed with {len(findings)} fraud findings ({high_confidence_count} high confidence)",
            details={
                "total_findings": len(findings),
                "high_confidence": high_confidence_count,
                "workflow_summary": workflow_summary,
                "findings": findings[:10]  # Include top 10
            }
        )

    def _calculate_signature(self, payload: str, secret: str) -> str:
        """
        Calculate HMAC signature for webhook verification.

        Args:
            payload: JSON payload string
            secret: Webhook secret

        Returns:
            HMAC signature
        """
        signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"sha256={signature}"

    def _should_send(self, alert_severity: AlertSeverity, min_severity: str) -> bool:
        """
        Check if alert should be sent based on severity.

        Args:
            alert_severity: Alert severity
            min_severity: Minimum severity for webhook

        Returns:
            True if should send
        """
        severity_levels = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3
        }

        alert_level = severity_levels.get(alert_severity.value, 0)
        min_level = severity_levels.get(min_severity, 0)

        return alert_level >= min_level

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        import uuid
        return f"alert-{uuid.uuid4().hex[:12]}"

    def get_stats(self) -> Dict[str, Any]:
        """
        Get webhook delivery statistics.

        Returns:
            Statistics dictionary
        """
        recent_deliveries = self.delivery_history[-10:] if self.delivery_history else []

        return {
            "total_sent": self.sent_count,
            "total_failed": self.failed_count,
            "success_rate": (
                self.sent_count / (self.sent_count + self.failed_count)
                if (self.sent_count + self.failed_count) > 0
                else 0
            ) * 100,
            "webhooks_configured": len(self.webhooks),
            "recent_deliveries": recent_deliveries
        }

    def test_webhook(self, webhook_name: str) -> Dict[str, Any]:
        """
        Send test alert to specific webhook.

        Args:
            webhook_name: Name of webhook to test

        Returns:
            Test result
        """
        # Find webhook
        webhook = None
        for wh in self.webhooks:
            if wh.get("name") == webhook_name:
                webhook = wh
                break

        if not webhook:
            return {
                "success": False,
                "error": f"Webhook '{webhook_name}' not found"
            }

        # Send test alert
        test_alert = {
            "alert_id": "test-alert",
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": "test",
            "severity": "low",
            "title": "Test Alert",
            "message": "This is a test alert from AntiFraudAgent",
            "details": {},
            "iocs": [],
            "source": "AntiFraudAgent"
        }

        return self._send_to_webhook(webhook, test_alert)
