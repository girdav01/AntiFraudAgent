# 🛡️ AntiFraud CTI Agent

**Autonomous Agent-Driven Fraud & CTI Detection System**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)

A secure, modular, MIT-licensed Python application for autonomous agent-driven fraud detection and Cyber Threat Intelligence (CTI) enrichment in web pages and documents. Features integration with local LLMs, modern document/vision parsing, daily reporting, and full interoperability with URLHaus, VirusTotal, and Trend Micro Vision One Sandbox API.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Docker Deployment](#-docker-deployment)
- [Security](#-security)
- [Extension](#-extension)
- [API Reference](#-api-reference)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🤖 Agent Autonomy & Multi-Step Workflow

- **Autonomous Multi-Step Agent**: LangChain + local LLM for daily web crawl, CTI enrichment, fraud/SE detection, and reporting
- **Automatic CTI Discovery**: Configurable discovery from top CTI feeds (URLHaus, VirusTotal, Trend Vision One)
- **Entity Extraction**: TTPs, CVEs, IOCs, malware hashes, actors, and fraud patterns
- **Configurable Sources**: YAML or Streamlit UI for endpoints and schedule

### 🌐 Advanced Parsing & Analysis

- **Web Crawling**: Crawl4AI for sophisticated web content extraction
- **Document Parsing**: Docling for PDF, DOCX, and other formats
- **Vision Analysis**: Granite-Vision for image and screenshot fraud detection
- **LLM-Powered Analysis**: Local or cloud LLM for fraud pattern detection

### 🔍 CTI Integration

- **URLHaus**: Malicious URL detection and IOC enrichment
- **VirusTotal**: File/URL scanning, entity enrichment, related submissions
- **Trend Micro Vision One**: Sandbox submission, verdict/report retrieval
- **Real-Time Updates**: On-demand lookups with error/rate-limit handling

### 📊 Reporting & Notifications

- **Scheduled Daily Emails**: 07:00 AM America/Montreal (configurable)
- **Secure SMTP**: Dynamic configuration, secrets storage (never hardcoded)
- **Full Logging**: Outbound email attempts, CTI API queries, errors, delivery status

### 🔄 STIX 2.1 Export & Integration

- **STIX 2.1 Normalization**: All entities/fraud findings normalized to STIX 2.1
- **Export Targets**: Trend Vision One STIX API and OpenCTI (REST/GraphQL)
- **Granular Config**: Endpoint configuration with error logging and automatic retries

### 🖥️ Streamlit UI & Secure Config

- **Minimal Dashboard**: Agent status, manual run, reports, config, error logs
- **MCP Integration**: Tool selection, endpoint tuning, reporting schedule
- **Authenticated Access**: Sensitive config encrypted at rest

### 🔒 Security Best Practices

- **Secure Coding**: Input validation, output encoding/sanitization, secret management
- **Sandboxed Runtime**: Docker with rootless user, no-new-privileges, read-only filesystem
- **Modular Error Handling**: Recoverable/retriable steps on API/crawl/LLM failures
- **Resource Limits**: Memory and CPU constraints in Docker

---

## 🏗️ Architecture

```
AntiFraudAgent/
│
├── agents/               # Autonomous agent orchestration
│   ├── fraud_agent.py    # Main fraud detection agent
│   └── scheduler.py      # Daily workflow scheduler
│
├── parsers/              # Content parsing modules
│   ├── web_crawler.py    # Crawl4AI web crawling
│   ├── document_parser.py # Docling document parsing
│   └── vision_parser.py  # Granite-Vision image analysis
│
├── llm/                  # LLM integration
│   ├── local_llm.py      # Local model support (llama-cpp)
│   └── agent_llm.py      # Unified LLM interface
│
├── cti/                  # CTI integrations
│   ├── urlhaus.py        # URLHaus API client
│   ├── virustotal.py     # VirusTotal API client
│   ├── trend_vision_one.py # Trend Micro Vision One client
│   └── manager.py        # Unified CTI manager
│
├── exporters/            # STIX 2.1 export
│   └── stix_exporter.py  # STIX bundle creation & export
│
├── config/               # Configuration & notifications
│   ├── config_manager.py # Secure config management
│   └── notifier.py       # Email notification system
│
├── ui/                   # Streamlit web interface
│   └── app.py            # Web dashboard
│
├── mcp/                  # Model Context Protocol tools
│   └── tools.py          # MCP tools integration
│
├── tests/                # Unit and integration tests
│
├── config/               # Configuration files
│   └── config.yaml.example
│
├── Dockerfile            # Hardened Docker image
├── docker-compose.yml    # Docker Compose configuration
├── requirements.txt      # Python dependencies
├── pyproject.toml        # Project metadata
├── .env.example          # Environment variables template
└── README.md             # This file
```

### Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Daily Scheduled Workflow                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  1. Fetch Recent Threats from CTI Sources             │
    │     (URLHaus, VirusTotal, Trend Vision One)           │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  2. Crawl Suspicious URLs                             │
    │     (Crawl4AI: JavaScript rendering, link extraction) │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  3. Parse Documents & Images                          │
    │     (Docling: PDFs/DOCX, Granite-Vision: Screenshots) │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  4. Analyze with LLM                                  │
    │     (Fraud detection, entity extraction, SE analysis) │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  5. Extract & Enrich IOCs                             │
    │     (Multi-source enrichment: URLHaus, VT, Trend)     │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  6. Generate STIX 2.1 Bundles                         │
    │     (Indicators, malware, attack patterns)            │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  7. Export to STIX Platforms                          │
    │     (Trend Vision One, OpenCTI)                       │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  8. Generate Daily Report                             │
    │     (LLM-generated markdown report)                   │
    └───────────────────────────────────────────────────────┘
                                │
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │  9. Send Email Notification                           │
    │     (Secure SMTP with HTML/text format)               │
    └───────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose (for containerized deployment)
- 4GB+ RAM recommended
- Optional: CUDA-capable GPU for local LLM acceleration

### Local Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/girdav01/AntiFraudAgent.git
   cd AntiFraudAgent
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   cp .env.example .env
   cp config/config.yaml.example config/config.yaml
   # Edit .env and config.yaml with your API keys and settings
   ```

5. **Download local LLM model** (optional, for local backend):
   ```bash
   mkdir -p models
   # Download a GGUF model file (e.g., Llama 2)
   wget https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf -O models/llama-2-7b.gguf
   ```

---

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# CTI API Keys
VIRUSTOTAL_API_KEY=your_key_here
TREND_API_KEY=your_key_here

# Email
SMTP_USERNAME=your_email@example.com
SMTP_PASSWORD=your_password
FROM_ADDRESS=antifraud@example.com

# LLM
LLM_BACKEND=local  # or openai, custom
MODEL_PATH=/models/llama-2-7b.gguf
```

### Configuration File (config/config.yaml)

```yaml
# Agent settings
max_urls_to_crawl: 50
max_iocs_to_enrich: 100

# CTI sources
urlhaus_enabled: true
virustotal_enabled: true
virustotal_api_key: "${VIRUSTOTAL_API_KEY}"

# Scheduling
daily_enabled: true
daily_time: "07:00"
timezone: "America/Montreal"

# Email notifications
email_enabled: true
smtp_host: "smtp.gmail.com"
smtp_port: 587
recipient_addresses:
  - "admin@example.com"
```

See `config/config.yaml.example` for full configuration options.

---

## 🎯 Usage

### Run Streamlit UI

```bash
streamlit run ui/app.py
```

Access the dashboard at `http://localhost:8501`

### Manual URL Analysis

```python
from agents.fraud_agent import FraudDetectionAgent
from llm.agent_llm import AgentLLM
from cti.manager import CTIManager
import asyncio

# Initialize components
config = {...}  # Load from config.yaml
llm = AgentLLM(backend="local", model_path="/models/llama-2-7b.gguf")
cti_manager = CTIManager(virustotal_api_key="your_key")
agent = FraudDetectionAgent(config, llm, cti_manager)

# Analyze URL
result = asyncio.run(agent.analyze_url("https://suspicious-site.com"))
print(result)
```

### Run Daily Workflow

```python
from agents.fraud_agent import FraudDetectionAgent
from agents.scheduler import AgentScheduler

# Initialize agent
agent = FraudDetectionAgent(config, llm, cti_manager)

# Initialize scheduler
schedule_config = {
    "daily_enabled": True,
    "daily_time": "07:00",
    "timezone": "America/Montreal"
}

scheduler = AgentScheduler(agent, schedule_config)
scheduler.start()

# Keep running
import asyncio
asyncio.get_event_loop().run_forever()
```

### REST API Usage

```bash
# Start the API server
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Or with Docker
docker run -p 8000:8000 antifraud-agent:latest uvicorn api.main:app --host 0.0.0.0
```

Access API documentation at `http://localhost:8000/docs`

**Example API Calls:**

```python
import requests

# Analyze URL
response = requests.post(
    "http://localhost:8000/analyze/url",
    json={"url": "https://suspicious-site.com"},
    headers={"X-API-Key": "your-api-key"}
)
result = response.json()

# Enrich IOCs
response = requests.post(
    "http://localhost:8000/enrich/iocs",
    json={"iocs": ["malicious.com", "192.168.1.1"]},
    headers={"X-API-Key": "your-api-key"}
)

# ML Prediction
response = requests.post(
    "http://localhost:8000/ml/predict",
    json={"text": "Your account has been suspended...", "url": "http://phish.com"},
    headers={"X-API-Key": "your-api-key"}
)
```

### ML-Based Classification

```python
from ml.fraud_classifier import FraudClassifier

# Initialize classifier
classifier = FraudClassifier(model_type="random_forest")

# Train on data
training_data = [...]  # List of content dictionaries
labels = ["phishing", "scam", "legitimate", ...]

results = classifier.train(training_data, labels)
print(f"Accuracy: {results['accuracy']:.2%}")

# Save model
classifier.save_model("models/fraud_classifier.pkl")

# Predict
prediction = classifier.predict({"text": "...", "url": "..."})
print(f"Fraud Type: {prediction['fraud_type']}")
print(f"Confidence: {prediction['confidence']}%")
```

### Webhook Alerts

```python
from config.webhook_alerts import WebhookAlertManager, AlertSeverity

# Configure webhooks
webhooks = [
    {
        "name": "slack",
        "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        "min_severity": "high",
        "secret": "your-secret"
    }
]

webhook_manager = WebhookAlertManager(webhooks)

# Send alert
webhook_manager.send_fraud_detected_alert({
    "fraud_type": "phishing",
    "confidence": 85,
    "source_url": "http://malicious.com"
})
```

### YARA Rule Generation

```python
from exporters.yara_generator import YARAGenerator

yara_gen = YARAGenerator()

# Generate rules from findings
findings = [...]  # Your fraud findings
rules = yara_gen.generate_rules_from_findings(findings, min_confidence=70)

# Save rules
yara_gen.save_rules(rules, "output/fraud_rules.yar")

# Generate custom IOC rule
iocs = ["malicious.com", "192.168.1.1", "bad-hash-here"]
rule = yara_gen.generate_ioc_rule(
    iocs=iocs,
    rule_name="fraud_campaign_2024",
    description="Fraud campaign IOCs from Jan 2024"
)
```

### Jupyter Notebook Analysis

```bash
# Start Jupyter
jupyter notebook notebooks/fraud_analysis.ipynb

# Or use JupyterLab
jupyter lab
```

The notebook includes:
- Interactive fraud findings analysis
- Visualization of threat trends
- IOC analysis and enrichment
- Custom ML model training
- YARA rule generation
- Report export

---

## 🐳 Docker Deployment

### Quick Start with Docker Compose

1. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

2. **Build and run**:
   ```bash
   docker-compose up -d
   ```

3. **Access UI**:
   ```
   http://localhost:8501
   ```

4. **View logs**:
   ```bash
   docker-compose logs -f antifraud-agent
   ```

### Manual Docker Build

```bash
# Build image
docker build -t antifraud-agent:latest .

# Run container
docker run -d \
  --name antifraud-agent \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp:mode=1777,size=1G \
  --security-opt=no-new-privileges:true \
  --memory=4g \
  --cpus=2 \
  -p 8501:8501 \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/data:/data:rw \
  -v $(pwd)/logs:/logs:rw \
  -v $(pwd)/models:/models:ro \
  --env-file .env \
  antifraud-agent:latest
```

---

## 🔒 Security

### Security Features

- **Rootless Container**: Runs as non-root user (UID 1000)
- **Read-Only Filesystem**: Root filesystem is read-only
- **No New Privileges**: Security option prevents privilege escalation
- **Resource Limits**: Memory and CPU constraints prevent DoS
- **Encrypted Secrets**: Sensitive config fields encrypted at rest (Fernet)
- **Input Validation**: All user inputs sanitized
- **HTTPS/TLS**: Secure communication with external APIs
- **Secret Management**: Never hardcode secrets; use environment variables

### Secrets Management

1. **Generate encryption key**:
   ```python
   from cryptography.fernet import Fernet
   print(Fernet.generate_key().decode())
   ```

2. **Store in .env**:
   ```bash
   ENCRYPTION_KEY=your_generated_key_here
   ```

3. **Sensitive fields automatically encrypted** in config.yaml

### Vulnerability Scanning

```bash
# Scan Docker image
docker scan antifraud-agent:latest

# Scan Python dependencies
pip install safety
safety check
```

---

## 🔧 Extension

### Adding New CTI Sources

1. **Create new client** in `cti/`:
   ```python
   # cti/new_source.py
   class NewSourceClient:
       def enrich_iocs(self, iocs):
           # Implementation
           pass
   ```

2. **Register in CTI Manager** (`cti/manager.py`):
   ```python
   if new_source_api_key:
       self.clients["new_source"] = NewSourceClient(new_source_api_key)
   ```

### Custom LLM Backends

Extend `llm/agent_llm.py` to support additional LLM providers:

```python
elif backend == "anthropic":
    from langchain.chat_models import ChatAnthropic
    self.llm = ChatAnthropic(model="claude-2", ...)
```

### MCP Tools

Add new MCP tools in `mcp/tools.py`:

```python
async def new_tool(self, param: str) -> Dict[str, Any]:
    # Tool implementation
    pass
```

---

## 📚 API Reference

### FraudDetectionAgent

**`analyze_url(url: str) -> Dict[str, Any]`**
- Analyze a single URL for fraud indicators
- Returns analysis results with IOCs and enrichment

**`analyze_document(doc_path: str) -> Dict[str, Any]`**
- Analyze a document for fraud patterns
- Returns parsed content, IOCs, and LLM analysis

**`run_daily_workflow() -> Dict[str, Any]`**
- Execute full autonomous workflow
- Returns comprehensive workflow results

### CTIManager

**`enrich_iocs_multi_source(iocs: List[str]) -> Dict[str, Dict[str, Any]]`**
- Enrich IOCs across multiple CTI sources in parallel
- Returns enrichment data mapped by IOC

**`get_threat_score(ioc: str) -> Dict[str, Any]`**
- Calculate aggregate threat score for an IOC
- Returns score, verdict, and source data

### STIXExporter

**`create_bundle_from_iocs(enriched_iocs: Dict) -> Dict`**
- Create STIX 2.1 bundle from enriched IOCs
- Returns serialized STIX bundle

**`export_to_trend_vision_one(bundles: List[Dict]) -> Dict`**
- Export STIX bundles to Trend Vision One
- Returns export results with submission IDs

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
pip install -r requirements.txt
pip install -e ".[dev]"  # Install dev dependencies

# Run tests
pytest tests/

# Format code
black .
ruff check .
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Crawl4AI**: Advanced web crawling
- **Docling**: Document parsing
- **Granite-Vision**: Vision model support (IBM Research)
- **LangChain**: LLM orchestration framework
- **STIX**: Structured Threat Information eXpression
- **URLHaus**: Abuse.ch malware URL sharing
- **VirusTotal**: Google's threat intelligence platform
- **Trend Micro**: Vision One threat intelligence

---

## 📧 Support

For issues, questions, or contributions:

- **GitHub Issues**: https://github.com/girdav01/AntiFraudAgent/issues
- **Documentation**: See this README and inline code documentation

---

## 🛣️ Roadmap

### ✅ Recently Implemented
- [x] **Advanced ML-based fraud classification** - scikit-learn classifiers with TF-IDF vectorization
- [x] **Real-time webhook alerts** - HTTP webhooks with HMAC signatures and severity filtering
- [x] **YARA rule generation** - Automatic YARA rule creation from fraud findings
- [x] **Jupyter notebook for analysis** - Interactive analysis with visualizations
- [x] **REST API** - FastAPI-based API with OpenAPI documentation

### 🔜 Future Enhancements
- [ ] Additional CTI source integrations (MISP, AlienVault OTX)
- [ ] Kubernetes deployment manifests
- [ ] GraphQL API support
- [ ] Real-time streaming data pipeline
- [ ] Advanced threat hunting queries

---

**Built with ❤️ for the cybersecurity community**

**⚠️ Disclaimer**: This tool is for authorized security testing, defensive security, and research purposes only. Users are responsible for compliance with applicable laws and regulations.
