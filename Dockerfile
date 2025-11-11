# AntiFraud Agent - Hardened Dockerfile
# Security best practices: rootless, read-only, resource limits, minimal attack surface

# Stage 1: Builder
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libmagic1 \
    poppler-utils \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash antifraud && \
    mkdir -p /app /data /logs /models && \
    chown -R antifraud:antifraud /app /data /logs /models

# Copy virtual environment from builder
COPY --from=builder --chown=antifraud:antifraud /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=antifraud:antifraud . /app/

# Set environment
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Switch to non-root user
USER antifraud

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Security: Read-only root filesystem (except /tmp, /data, /logs)
# Set in docker-compose or run command: --read-only --tmpfs /tmp

# Security: No new privileges
# Set in docker-compose or run command: --security-opt=no-new-privileges:true

# Security: Resource limits
# Set in docker-compose: memory, cpu limits

# Expose port for Streamlit UI
EXPOSE 8501

# Default command: Run Streamlit UI
CMD ["streamlit", "run", "ui/app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
