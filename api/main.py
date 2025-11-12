"""
REST API for AntiFraud Agent

FastAPI-based REST API for programmatic access to fraud detection capabilities.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import structlog
from pathlib import Path
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from agents.fraud_agent import FraudDetectionAgent
from agents.scheduler import AgentScheduler
from llm.agent_llm import AgentLLM
from cti.manager import CTIManager
from ml.fraud_classifier import FraudClassifier
from exporters.yara_generator import YARAGenerator
from config.config_manager import ConfigManager
from config.webhook_alerts import WebhookAlertManager, AlertSeverity

logger = structlog.get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AntiFraud Agent API",
    description="REST API for autonomous fraud detection and CTI enrichment",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
config = None
agent = None
scheduler = None
ml_classifier = None
webhook_manager = None


# Pydantic models
class URLAnalysisRequest(BaseModel):
    url: HttpUrl
    include_enrichment: bool = True


class DocumentAnalysisRequest(BaseModel):
    document_path: str


class IOCEnrichmentRequest(BaseModel):
    iocs: List[str]
    sources: Optional[List[str]] = None


class MLTrainingRequest(BaseModel):
    training_data: List[Dict[str, Any]]
    labels: List[str]
    model_type: str = "random_forest"


class YARARuleRequest(BaseModel):
    findings: List[Dict[str, Any]]
    min_confidence: int = 70


class WebhookAlertRequest(BaseModel):
    alert_type: str
    severity: str
    title: str
    message: str
    details: Optional[Dict[str, Any]] = None


class WorkflowRunRequest(BaseModel):
    send_notification: bool = True


# API key authentication (basic)
API_KEY = None


def verify_api_key(x_api_key: str = Header(None)):
    """Verify API key."""
    global API_KEY
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@app.on_event("startup")
async def startup_event():
    """Initialize components on startup."""
    global config, agent, scheduler, ml_classifier, webhook_manager, API_KEY

    logger.info("api_starting")

    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()

        API_KEY = config.get("api_key")

        # Initialize LLM
        llm = AgentLLM(
            backend=config.get("llm_backend", "local"),
            model_path=config.get("model_path"),
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

        # Initialize ML Classifier
        ml_model_path = Path("models/fraud_classifier.pkl")
        if ml_model_path.exists():
            ml_classifier = FraudClassifier(model_path=str(ml_model_path))
            logger.info("ml_classifier_loaded")

        # Initialize Webhook Manager
        webhooks = config.get("webhooks", [])
        if webhooks:
            webhook_manager = WebhookAlertManager(webhooks)
            logger.info("webhook_manager_initialized")

        logger.info("api_started")

    except Exception as e:
        logger.error("api_startup_failed", error=str(e))
        raise


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint."""
    return {
        "service": "AntiFraud Agent API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "components": {
            "agent": agent is not None,
            "ml_classifier": ml_classifier is not None,
            "webhook_manager": webhook_manager is not None
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/analyze/url", tags=["Analysis"])
async def analyze_url(
    request: URLAnalysisRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Analyze a URL for fraud indicators.

    Returns analysis results including fraud detection, IOC extraction, and CTI enrichment.
    """
    try:
        logger.info("api_url_analysis_requested", url=str(request.url))

        result = await agent.analyze_url(str(request.url))

        # Remove enrichment if not requested
        if not request.include_enrichment:
            result.pop("enriched_iocs", None)

        return result

    except Exception as e:
        logger.error("url_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/document", tags=["Analysis"])
async def analyze_document(
    request: DocumentAnalysisRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Analyze a document for fraud indicators.

    Returns parsed content, IOC extraction, and fraud analysis.
    """
    try:
        logger.info("api_document_analysis_requested", document=request.document_path)

        result = await agent.analyze_document(request.document_path)

        return result

    except Exception as e:
        logger.error("document_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/enrich/iocs", tags=["CTI"])
async def enrich_iocs(
    request: IOCEnrichmentRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Enrich IOCs with CTI data from multiple sources.

    Returns enrichment data from URLHaus, VirusTotal, and Trend Vision One.
    """
    try:
        logger.info("api_ioc_enrichment_requested", iocs=len(request.iocs))

        enriched = agent.cti_manager.enrich_iocs_multi_source(
            request.iocs,
            sources=request.sources
        )

        return {
            "iocs": enriched,
            "total": len(request.iocs),
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error("ioc_enrichment_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ml/predict", tags=["Machine Learning"])
async def ml_predict(
    content: Dict[str, Any],
    api_key: str = Depends(verify_api_key)
):
    """
    Predict fraud type using ML classifier.

    Returns fraud type prediction with confidence scores.
    """
    if not ml_classifier:
        raise HTTPException(status_code=503, detail="ML classifier not available")

    try:
        logger.info("api_ml_prediction_requested")

        prediction = ml_classifier.predict(content)

        return prediction

    except Exception as e:
        logger.error("ml_prediction_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ml/train", tags=["Machine Learning"])
async def ml_train(
    request: MLTrainingRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Train ML classifier on new data.

    Training runs in the background. Returns training job ID.
    """
    try:
        logger.info("api_ml_training_requested", samples=len(request.training_data))

        # Create new classifier
        classifier = FraudClassifier(model_type=request.model_type)

        # Train in background
        def train_model():
            results = classifier.train(request.training_data, request.labels)
            classifier.save_model("models/fraud_classifier.pkl")
            logger.info("ml_training_completed", accuracy=results["accuracy"])

        background_tasks.add_task(train_model)

        return {
            "message": "Training started",
            "samples": len(request.training_data),
            "model_type": request.model_type
        }

    except Exception as e:
        logger.error("ml_training_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/yara/generate", tags=["YARA"])
async def generate_yara_rules(
    request: YARARuleRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Generate YARA rules from fraud findings.

    Returns generated YARA rule strings.
    """
    try:
        logger.info("api_yara_generation_requested", findings=len(request.findings))

        yara_gen = YARAGenerator()
        rules = yara_gen.generate_rules_from_findings(
            request.findings,
            min_confidence=request.min_confidence
        )

        return {
            "rules": rules,
            "count": len(rules),
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error("yara_generation_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/workflow/run", tags=["Workflow"])
async def run_workflow(
    request: WorkflowRunRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Trigger immediate workflow execution.

    Workflow runs in the background. Returns job ID.
    """
    try:
        logger.info("api_workflow_run_requested")

        # Run in background
        async def execute_workflow():
            results = await agent.run_daily_workflow()
            logger.info("workflow_completed", duration=results.get("duration_seconds"))

            if request.send_notification and webhook_manager:
                webhook_manager.send_batch_alert(
                    results.get("findings", []),
                    results
                )

        background_tasks.add_task(lambda: asyncio.create_task(execute_workflow()))

        return {
            "message": "Workflow started",
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error("workflow_run_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/workflow/status", tags=["Workflow"])
async def get_workflow_status(api_key: str = Depends(verify_api_key)):
    """
    Get workflow scheduler status.

    Returns scheduler state and next run time.
    """
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")

    try:
        status = scheduler.get_status()
        return status

    except Exception as e:
        logger.error("workflow_status_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webhooks/send", tags=["Webhooks"])
async def send_webhook_alert(
    request: WebhookAlertRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Send webhook alert.

    Triggers immediate webhook notification to configured endpoints.
    """
    if not webhook_manager:
        raise HTTPException(status_code=503, detail="Webhook manager not configured")

    try:
        logger.info("api_webhook_send_requested", type=request.alert_type)

        severity = AlertSeverity(request.severity)

        results = webhook_manager.send_alert(
            alert_type=request.alert_type,
            severity=severity,
            title=request.title,
            message=request.message,
            details=request.details
        )

        return results

    except Exception as e:
        logger.error("webhook_send_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/webhooks/stats", tags=["Webhooks"])
async def get_webhook_stats(api_key: str = Depends(verify_api_key)):
    """
    Get webhook delivery statistics.

    Returns success rate and recent deliveries.
    """
    if not webhook_manager:
        raise HTTPException(status_code=503, detail="Webhook manager not configured")

    try:
        stats = webhook_manager.get_stats()
        return stats

    except Exception as e:
        logger.error("webhook_stats_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", tags=["Statistics"])
async def get_statistics(api_key: str = Depends(verify_api_key)):
    """
    Get overall system statistics.

    Returns aggregated stats from all components.
    """
    try:
        stats = {
            "agent": {
                "findings": len(agent.findings) if agent else 0,
                "iocs": len(agent.iocs) if agent else 0
            },
            "scheduler": scheduler.get_status() if scheduler else None,
            "webhooks": webhook_manager.get_stats() if webhook_manager else None,
            "timestamp": datetime.utcnow().isoformat()
        }

        return stats

    except Exception as e:
        logger.error("stats_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
