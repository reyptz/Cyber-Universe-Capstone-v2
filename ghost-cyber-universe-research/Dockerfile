# Ghost Research Core - Unified Dockerfile
FROM python:3.11-slim

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLP models
RUN python -m spacy download fr_core_news_sm && \
    python -m spacy download en_core_web_sm

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs chroma_db docs

# Expose API port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Run the unified service
CMD ["python", "run.py"]
