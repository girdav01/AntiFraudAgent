"""
Agent Scheduler Module

Handles scheduled execution of fraud detection agent workflows.
"""

import logging
from typing import Dict, Optional, Callable, Any
from datetime import datetime, time
import asyncio
import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import pytz

from .fraud_agent import FraudDetectionAgent

logger = structlog.get_logger(__name__)


class AgentScheduler:
    """
    Scheduler for autonomous agent execution.

    Features:
    - Daily scheduled runs
    - Configurable timezone
    - Email notifications on completion
    - Error handling and recovery
    """

    def __init__(
        self,
        agent: FraudDetectionAgent,
        schedule_config: Dict[str, Any],
        notification_callback: Optional[Callable] = None
    ):
        """
        Initialize agent scheduler.

        Args:
            agent: FraudDetectionAgent instance
            schedule_config: Schedule configuration dictionary
            notification_callback: Optional callback for notifications
        """
        self.agent = agent
        self.schedule_config = schedule_config
        self.notification_callback = notification_callback

        # Initialize scheduler
        self.scheduler = AsyncIOScheduler()

        # Timezone
        tz_name = schedule_config.get("timezone", "America/Montreal")
        self.timezone = pytz.timezone(tz_name)

        # State tracking
        self.last_run = None
        self.last_run_status = None
        self.run_count = 0

        logger.info("scheduler_initialized", timezone=tz_name)

    def start(self):
        """Start the scheduler."""
        # Add daily job
        if self.schedule_config.get("daily_enabled", True):
            daily_time_str = self.schedule_config.get("daily_time", "07:00")
            hour, minute = map(int, daily_time_str.split(":"))

            self.scheduler.add_job(
                self._run_daily_workflow,
                trigger=CronTrigger(
                    hour=hour,
                    minute=minute,
                    timezone=self.timezone
                ),
                id="daily_workflow",
                name="Daily Fraud Detection Workflow",
                max_instances=1,  # Prevent concurrent runs
                replace_existing=True
            )

            logger.info("daily_job_scheduled", time=daily_time_str, timezone=self.timezone.zone)

        # Add interval job (if configured)
        if self.schedule_config.get("interval_enabled", False):
            interval_hours = self.schedule_config.get("interval_hours", 6)

            self.scheduler.add_job(
                self._run_daily_workflow,
                trigger=IntervalTrigger(hours=interval_hours),
                id="interval_workflow",
                name="Interval Fraud Detection Workflow",
                max_instances=1,
                replace_existing=True
            )

            logger.info("interval_job_scheduled", hours=interval_hours)

        # Start scheduler
        self.scheduler.start()
        logger.info("scheduler_started")

    def stop(self):
        """Stop the scheduler."""
        self.scheduler.shutdown(wait=True)
        logger.info("scheduler_stopped")

    async def _run_daily_workflow(self):
        """Execute daily workflow with error handling."""
        logger.info("scheduled_workflow_starting", run_count=self.run_count + 1)
        start_time = datetime.utcnow()

        try:
            # Run workflow
            results = await self.agent.run_daily_workflow()

            # Update state
            self.last_run = start_time
            self.last_run_status = "success"
            self.run_count += 1

            # Send notification
            if self.notification_callback:
                try:
                    await self.notification_callback(results, "success")
                except Exception as e:
                    logger.error("notification_failed", error=str(e))

            logger.info(
                "scheduled_workflow_completed",
                duration_seconds=results.get("duration_seconds"),
                status="success"
            )

        except Exception as e:
            logger.error("scheduled_workflow_failed", error=str(e))

            self.last_run = start_time
            self.last_run_status = "failed"

            # Send error notification
            if self.notification_callback:
                try:
                    error_results = {
                        "error": str(e),
                        "start_time": start_time.isoformat(),
                        "end_time": datetime.utcnow().isoformat()
                    }
                    await self.notification_callback(error_results, "failed")
                except Exception as ne:
                    logger.error("error_notification_failed", error=str(ne))

    async def run_now(self) -> Dict[str, Any]:
        """
        Trigger immediate workflow execution.

        Returns:
            Workflow results
        """
        logger.info("manual_workflow_triggered")

        try:
            results = await self.agent.run_daily_workflow()

            # Send notification
            if self.notification_callback:
                try:
                    await self.notification_callback(results, "manual")
                except Exception as e:
                    logger.error("notification_failed", error=str(e))

            return results

        except Exception as e:
            logger.error("manual_workflow_failed", error=str(e))
            raise

    def get_next_run_time(self) -> Optional[datetime]:
        """
        Get the next scheduled run time.

        Returns:
            Next run datetime or None
        """
        job = self.scheduler.get_job("daily_workflow")
        if job:
            return job.next_run_time
        return None

    def get_status(self) -> Dict[str, Any]:
        """
        Get scheduler status.

        Returns:
            Status dictionary
        """
        return {
            "running": self.scheduler.running,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "last_run_status": self.last_run_status,
            "run_count": self.run_count,
            "next_run": self.get_next_run_time().isoformat() if self.get_next_run_time() else None,
            "timezone": self.timezone.zone,
            "jobs": [
                {
                    "id": job.id,
                    "name": job.name,
                    "next_run": job.next_run_time.isoformat() if job.next_run_time else None
                }
                for job in self.scheduler.get_jobs()
            ]
        }

    def pause(self):
        """Pause all scheduled jobs."""
        self.scheduler.pause()
        logger.info("scheduler_paused")

    def resume(self):
        """Resume all scheduled jobs."""
        self.scheduler.resume()
        logger.info("scheduler_resumed")

    def reschedule_daily(self, new_time: str):
        """
        Reschedule daily job to new time.

        Args:
            new_time: New time in HH:MM format
        """
        hour, minute = map(int, new_time.split(":"))

        self.scheduler.reschedule_job(
            "daily_workflow",
            trigger=CronTrigger(
                hour=hour,
                minute=minute,
                timezone=self.timezone
            )
        )

        logger.info("daily_job_rescheduled", new_time=new_time)
