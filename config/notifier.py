"""
Email Notification Module

Handles secure email notifications for agent workflow results.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import structlog
from pathlib import Path

logger = structlog.get_logger(__name__)


class EmailNotifier:
    """
    Secure email notifier for sending reports and alerts.

    Features:
    - Secure SMTP with TLS/SSL
    - HTML and plain text emails
    - Attachment support
    - Delivery tracking
    - Error logging
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_address: str,
        use_tls: bool = True,
        use_ssl: bool = False
    ):
        """
        Initialize email notifier.

        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            username: SMTP username
            password: SMTP password
            from_address: Sender email address
            use_tls: Use STARTTLS
            use_ssl: Use SSL/TLS
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_address = from_address
        self.use_tls = use_tls
        self.use_ssl = use_ssl

        # Delivery tracking
        self.sent_count = 0
        self.failed_count = 0
        self.last_send_time = None
        self.last_error = None

        logger.info("email_notifier_initialized", smtp_host=smtp_host, smtp_port=smtp_port)

    def send_daily_report(
        self,
        to_addresses: List[str],
        workflow_results: Dict[str, Any],
        status: str = "success"
    ) -> bool:
        """
        Send daily workflow report via email.

        Args:
            to_addresses: List of recipient email addresses
            workflow_results: Workflow results dictionary
            status: Workflow status ("success", "failed", "manual")

        Returns:
            True if sent successfully, False otherwise
        """
        # Generate email subject
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        subject = f"AntiFraud Agent Daily Report - {date_str} [{status.upper()}]"

        # Generate email body
        html_body = self._generate_html_report(workflow_results, status)
        text_body = self._generate_text_report(workflow_results, status)

        return self.send_email(
            to_addresses=to_addresses,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )

    def send_alert(
        self,
        to_addresses: List[str],
        alert_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send alert email.

        Args:
            to_addresses: List of recipient addresses
            alert_type: Type of alert
            message: Alert message
            details: Optional additional details

        Returns:
            True if sent successfully
        """
        subject = f"AntiFraud Agent Alert: {alert_type}"

        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .alert {{ background-color: #f44336; color: white; padding: 15px; margin-bottom: 20px; }}
                .details {{ background-color: #f5f5f5; padding: 10px; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <h2>{alert_type}</h2>
            </div>
            <p>{message}</p>
            {self._format_details_html(details) if details else ''}
            <p><small>Sent at {datetime.utcnow().isoformat()} UTC</small></p>
        </body>
        </html>
        """

        text_body = f"""
ALERT: {alert_type}

{message}

{self._format_details_text(details) if details else ''}

Sent at {datetime.utcnow().isoformat()} UTC
        """

        return self.send_email(
            to_addresses=to_addresses,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )

    def send_email(
        self,
        to_addresses: List[str],
        subject: str,
        html_body: Optional[str] = None,
        text_body: Optional[str] = None,
        attachments: Optional[List[str]] = None
    ) -> bool:
        """
        Send email with optional HTML, text, and attachments.

        Args:
            to_addresses: List of recipient addresses
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body
            attachments: List of file paths to attach

        Returns:
            True if sent successfully
        """
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["From"] = self.from_address
            msg["To"] = ", ".join(to_addresses)
            msg["Subject"] = subject
            msg["Date"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")

            # Add text body
            if text_body:
                msg.attach(MIMEText(text_body, "plain"))

            # Add HTML body
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            # Add attachments
            if attachments:
                for file_path in attachments:
                    try:
                        with open(file_path, "rb") as f:
                            part = MIMEApplication(f.read())
                            file_name = Path(file_path).name
                            part.add_header("Content-Disposition", "attachment", filename=file_name)
                            msg.attach(part)
                    except Exception as e:
                        logger.warning("attachment_failed", file=file_path, error=str(e))

            # Send email
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port) as server:
                    server.login(self.username, self.password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls()
                    server.login(self.username, self.password)
                    server.send_message(msg)

            # Update tracking
            self.sent_count += 1
            self.last_send_time = datetime.utcnow()
            self.last_error = None

            logger.info(
                "email_sent",
                recipients=len(to_addresses),
                subject=subject,
                has_html=html_body is not None,
                has_attachments=attachments is not None
            )

            return True

        except Exception as e:
            self.failed_count += 1
            self.last_error = str(e)

            logger.error(
                "email_send_failed",
                recipients=to_addresses,
                subject=subject,
                error=str(e)
            )

            return False

    def _generate_html_report(self, workflow_results: Dict[str, Any], status: str) -> str:
        """Generate HTML report from workflow results."""
        # Extract key metrics
        start_time = workflow_results.get("start_time", "N/A")
        end_time = workflow_results.get("end_time", "N/A")
        duration = workflow_results.get("duration_seconds", 0)
        steps_completed = workflow_results.get("steps_completed", [])
        findings_count = workflow_results.get("fraud_findings_count", 0)
        iocs_enriched = workflow_results.get("iocs_enriched", 0)
        urls_crawled = workflow_results.get("urls_crawled", 0)

        status_color = "#4CAF50" if status == "success" else "#f44336"

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .header {{ background-color: {status_color}; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; }}
                .metric {{ background-color: #f5f5f5; padding: 10px; margin: 5px 0; border-left: 4px solid {status_color}; }}
                .metric-label {{ font-weight: bold; }}
                .findings {{ background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>AntiFraud Agent Daily Report</h1>
                <p>Status: {status.upper()}</p>
            </div>

            <div class="section">
                <h2>Execution Summary</h2>
                <div class="metric">
                    <span class="metric-label">Start Time:</span> {start_time}
                </div>
                <div class="metric">
                    <span class="metric-label">End Time:</span> {end_time}
                </div>
                <div class="metric">
                    <span class="metric-label">Duration:</span> {duration:.2f} seconds
                </div>
                <div class="metric">
                    <span class="metric-label">Steps Completed:</span> {len(steps_completed)}/{len(steps_completed)}
                </div>
            </div>

            <div class="section">
                <h2>Key Metrics</h2>
                <div class="metric">
                    <span class="metric-label">URLs Crawled:</span> {urls_crawled}
                </div>
                <div class="metric">
                    <span class="metric-label">IOCs Enriched:</span> {iocs_enriched}
                </div>
                <div class="metric">
                    <span class="metric-label">Fraud Findings:</span> {findings_count}
                </div>
            </div>

            {self._format_findings_html(workflow_results.get("findings", [])) if findings_count > 0 else ''}

            <div class="section">
                <h2>Workflow Steps</h2>
                <ul>
                    {''.join([f'<li>{step}</li>' for step in steps_completed])}
                </ul>
            </div>

            <div class="section">
                <p><small>Generated by AntiFraud Agent at {datetime.utcnow().isoformat()} UTC</small></p>
            </div>
        </body>
        </html>
        """

        return html

    def _generate_text_report(self, workflow_results: Dict[str, Any], status: str) -> str:
        """Generate plain text report from workflow results."""
        start_time = workflow_results.get("start_time", "N/A")
        end_time = workflow_results.get("end_time", "N/A")
        duration = workflow_results.get("duration_seconds", 0)
        steps_completed = workflow_results.get("steps_completed", [])
        findings_count = workflow_results.get("fraud_findings_count", 0)
        iocs_enriched = workflow_results.get("iocs_enriched", 0)
        urls_crawled = workflow_results.get("urls_crawled", 0)

        report = f"""
AntiFraud Agent Daily Report
Status: {status.upper()}
{'=' * 50}

Execution Summary:
- Start Time: {start_time}
- End Time: {end_time}
- Duration: {duration:.2f} seconds
- Steps Completed: {len(steps_completed)}

Key Metrics:
- URLs Crawled: {urls_crawled}
- IOCs Enriched: {iocs_enriched}
- Fraud Findings: {findings_count}

Workflow Steps:
{chr(10).join([f'- {step}' for step in steps_completed])}

{'=' * 50}
Generated by AntiFraud Agent at {datetime.utcnow().isoformat()} UTC
        """

        return report

    def _format_findings_html(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings as HTML."""
        if not findings:
            return ""

        html = '<div class="section findings"><h2>Fraud Findings</h2><table><tr><th>Type</th><th>Source URL</th><th>Confidence</th></tr>'

        for finding in findings[:10]:  # Limit to 10
            fraud_type = finding.get("fraud_type", "Unknown")
            source_url = finding.get("source_url", "N/A")
            confidence = finding.get("confidence", 0)

            html += f"<tr><td>{fraud_type}</td><td>{source_url}</td><td>{confidence}%</td></tr>"

        html += "</table></div>"

        return html

    def _format_details_html(self, details: Dict[str, Any]) -> str:
        """Format details dictionary as HTML."""
        html = '<div class="details"><h3>Details</h3><ul>'

        for key, value in details.items():
            html += f"<li><strong>{key}:</strong> {value}</li>"

        html += "</ul></div>"

        return html

    def _format_details_text(self, details: Dict[str, Any]) -> str:
        """Format details dictionary as plain text."""
        text = "\nDetails:\n"

        for key, value in details.items():
            text += f"- {key}: {value}\n"

        return text

    def get_stats(self) -> Dict[str, Any]:
        """
        Get email notification statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "sent_count": self.sent_count,
            "failed_count": self.failed_count,
            "last_send_time": self.last_send_time.isoformat() if self.last_send_time else None,
            "last_error": self.last_error
        }
